using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using MssqlMcpServer.Configuration;

namespace MssqlMcpServer.Security;

/// <summary>
/// Enforces security guardrails, database and table access restrictions, and query safety.
/// </summary>
public class GuardrailsValidator
{
    private readonly GlobalSecurity _security;
    private readonly Regex? _compiledDeniedColumnsRegex;

    private static readonly HashSet<string> HazardousKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
        "EXEC", "EXECUTE", "MERGE", "GRANT", "REVOKE", "DENY", "SHUTDOWN",
        "BACKUP", "RESTORE", "RECONFIGURE", "DBCC", "INTO",
        "OPENROWSET", "OPENDATASOURCE", "OPENQUERY", "KILL", "SP_EXECUTESQL"
    };

    private static readonly Regex HazardousRegex = new(
        @"\b(" + string.Join("|", new[]
        {
            "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
            "EXEC", "EXECUTE", "MERGE", "GRANT", "REVOKE", "DENY", "SHUTDOWN",
            "BACKUP", "RESTORE", "RECONFIGURE", "DBCC", "INTO",
            "OPENROWSET", "OPENDATASOURCE", "OPENQUERY", "KILL", "SP_EXECUTESQL",
            @"XP_[A-Z0-9_]+"
        }) + @")\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private const string IdentifierPartPattern =
        @"(?:\[(?:[^\]\r\n]|\]\])+\]|""(?:[^""\r\n]|"""")+""|[a-zA-Z_#@$][a-zA-Z0-9_#@$]*)";

    private static readonly Regex FourPartNameRegex = new(
        @"(?:\b|(?=[\[""]))" +
        IdentifierPartPattern +
        @"(?:\s*\.\s*" + IdentifierPartPattern + @"?){2,}" +
        @"\s*\.\s*" +
        IdentifierPartPattern +
        @"(?:\b|(?<=[\]""]))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public GuardrailsValidator(GlobalSecurity security)
    {
        _security = security ?? new GlobalSecurity();
        _compiledDeniedColumnsRegex = CompileDeniedColumnsRegex(_security.DeniedColumns);
    }

    private static Regex? CompileDeniedColumnsRegex(IEnumerable<string>? patterns)
    {
        if (patterns == null)
            return null;

        var subPatterns = new List<string>();
        foreach (var pattern in patterns)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                continue;

            string escaped = Regex.Escape(pattern.Trim())
                .Replace("\\*", ".*")
                .Replace("\\?", ".");

            subPatterns.Add("(?:" + escaped + ")");
        }

        if (subPatterns.Count == 0)
            return null;

        string unifiedPattern = "^(?:" + string.Join("|", subPatterns) + ")$";
        return new Regex(unifiedPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Validates whether access to the target database is allowed for the given profile.
    /// </summary>
    public void ValidateDatabase(string database, ProfileConfig profile)
    {
        if (string.IsNullOrWhiteSpace(database))
            throw new ArgumentException("Database name cannot be empty.", nameof(database));

        string cleanDb = database.Trim().Trim('[', ']');

        // 1. Check global denied databases
        if (WildcardMatcher.MatchesAny(cleanDb, _security.DeniedDatabases))
        {
            throw new SecurityException($"Access to database '{cleanDb}' is denied by global security policy.");
        }

        // 2. Check profile allowed databases
        if (profile.AllowedDatabases != null && profile.AllowedDatabases.Count > 0)
        {
            bool allowed = WildcardMatcher.MatchesAny(cleanDb, profile.AllowedDatabases);
            if (!allowed)
            {
                throw new SecurityException($"Database '{cleanDb}' is not in the allowed databases list for profile '{profile.Description}'.");
            }
        }
    }

    /// <summary>
    /// Validates that an identifier (table, stored procedure, etc.) does not contain 4 parts or references to linked servers.
    /// </summary>
    public void ValidateNoFourPartIdentifier(string rawIdentifier, string objectType = "Object")
    {
        if (!_security.ProhibitFourPartNames || string.IsNullOrWhiteSpace(rawIdentifier))
            return;

        string trimmed = rawIdentifier.Trim();

        if (FourPartNameRegex.IsMatch(trimmed) || CountIdentifierDots(trimmed) >= 3)
        {
            throw new SecurityException($"Four-part object identifiers (linked server references) like '{trimmed}' are strictly prohibited by security guardrails.");
        }
    }

    private static int CountIdentifierDots(string identifier)
    {
        int count = 0;
        bool inBracket = false;
        bool inQuote = false;
        for (int i = 0; i < identifier.Length; i++)
        {
            char c = identifier[i];
            if (c == '[' && !inQuote && !inBracket)
            {
                inBracket = true;
            }
            else if (c == ']' && inBracket)
            {
                // Check for escaped closing bracket ]]
                if (i + 1 < identifier.Length && identifier[i + 1] == ']')
                {
                    i++;
                    continue;
                }
                inBracket = false;
            }
            else if (c == '"' && !inBracket)
            {
                // Check for escaped double quote ""
                if (inQuote && i + 1 < identifier.Length && identifier[i + 1] == '"')
                {
                    i++;
                    continue;
                }
                inQuote = !inQuote;
            }
            else if (c == '.' && !inBracket && !inQuote)
            {
                count++;
            }
        }
        return count;
    }

    /// <summary>
    /// Validates whether access to the target table is allowed.
    /// </summary>
    public void ValidateTable(string tableName)
    {
        if (string.IsNullOrWhiteSpace(tableName))
            throw new ArgumentException("Table name cannot be empty.", nameof(tableName));

        ValidateNoFourPartIdentifier(tableName, "Table");

        // Normalize table name: remove brackets and isolate schema / object name
        string cleanTable = tableName.Trim();
        string[] parts = cleanTable.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string objectName = (parts.Length > 0 ? parts[^1] : cleanTable).Trim('[', ']');

        // Check against denied table patterns
        if (WildcardMatcher.MatchesAny(objectName, _security.DeniedTables) ||
            WildcardMatcher.MatchesAny(cleanTable.Replace("[", "").Replace("]", ""), _security.DeniedTables))
        {
            throw new SecurityException($"Access to table '{cleanTable}' is blocked by security guardrails (denied table pattern).");
        }
    }

    /// <summary>
    /// Checks whether a column matches the denied columns policy.
    /// </summary>
    public bool IsColumnDenied(string columnName)
    {
        if (string.IsNullOrWhiteSpace(columnName) || _compiledDeniedColumnsRegex == null)
            return false;

        string cleanCol = columnName.Trim().Trim('[', ']');
        return _compiledDeniedColumnsRegex.IsMatch(cleanCol);
    }

    /// <summary>
    /// Validates whether the profile allows executing stored procedures (live or simulation).
    /// </summary>
    public void ValidateExecutionPermissions(ProfileConfig profile, bool simulate)
    {
        if (simulate)
        {
            if (!profile.AllowSimulation)
            {
                throw new SecurityException("Simulation mode is not permitted on this profile.");
            }
            return;
        }

        if (profile.IsReadOnly)
        {
            throw new SecurityException("Current profile is read-only. Live execution of stored procedures is prohibited.");
        }

        if (!profile.AllowExecuteSp)
        {
            throw new SecurityException("Stored procedure execution is disabled on this profile.");
        }
    }

    /// <summary>
    /// Validates that a SQL query is strictly read-only (SELECT / WITH CTE) and does not contain dangerous operations.
    /// </summary>
    public QuerySafetyResult ValidateReadQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return QuerySafetyResult.Unsafe("Query cannot be empty.");

        // 1. Strip comments and string literals to inspect query structure
        string strippedSql = StripCommentsAndStrings(query, out bool hasUnclosedString, out bool hasMultipleStatements);

        if (hasUnclosedString)
            return QuerySafetyResult.Unsafe("Query has unclosed string literals or delimited identifiers.");

        if (hasMultipleStatements)
            return QuerySafetyResult.Unsafe("Stacked queries and multiple statements separated by ';' are prohibited.");

        string trimmed = strippedSql.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return QuerySafetyResult.Unsafe("Query has no executable statements after stripping comments.");

        // 2. Check starting statement keyword (must start with SELECT or WITH)
        var matchFirstWord = Regex.Match(trimmed, @"^[A-Z]+", RegexOptions.IgnoreCase);
        if (!matchFirstWord.Success)
            return QuerySafetyResult.Unsafe("Unable to determine query root command.");

        string rootCommand = matchFirstWord.Value.ToUpperInvariant();
        if (rootCommand != "SELECT" && rootCommand != "WITH")
        {
            return QuerySafetyResult.Unsafe($"Only 'SELECT' or 'WITH' (CTE) queries are permitted in read_query. Detected root command: '{rootCommand}'.");
        }

        // 3. Check for four-part object identifiers (linked server references)
        if (_security.ProhibitFourPartNames)
        {
            var matches = FourPartNameRegex.Matches(strippedSql);
            foreach (Match match in matches)
            {
                if (match.Success && IsLinkedServerReference(strippedSql, match))
                {
                    return QuerySafetyResult.Unsafe($"Four-part object identifiers (linked server references) like '{match.Value.Trim()}' are strictly prohibited by security guardrails.");
                }
            }
        }

        // 4. Scan for hazardous keywords outside strings and comments
        var hazardousMatch = HazardousRegex.Match(strippedSql);
        if (hazardousMatch.Success)
        {
            string keyword = hazardousMatch.Value.ToUpperInvariant();
            return QuerySafetyResult.Unsafe($"Hazardous or modification keyword '{keyword}' is prohibited in read_query.");
        }

        return QuerySafetyResult.Safe();
    }

    private static bool IsLinkedServerReference(string strippedSql, Match match)
    {
        // 1. If it contains omitted empty parts ('..' or '...'), it is strictly a linked server reference.
        // In T-SQL, column references can never have omitted parts (e.g. db..table.col is invalid).
        if (Regex.IsMatch(match.Value, @"\.\s*\."))
        {
            return true;
        }

        // 2. In T-SQL, 4-part names without omitted parts only refer to linked servers if they appear
        // in table source contexts (after FROM, JOIN, APPLY, INTO). Otherwise, in SELECT, WHERE, ON,
        // GROUP BY, ORDER BY, etc., they represent 4-part column references (db.schema.table.col).
        return IsInTableSourceContext(strippedSql, match.Index);
    }

    private enum ClauseContext
    {
        None,
        Select,
        From,
        Join,
        Apply,
        Into,
        Where,
        On,
        GroupBy,
        OrderBy,
        Having,
        Set,
        Values,
        With
    }

    private static bool IsInTableSourceContext(string sql, int targetIndex)
    {
        var stack = new Stack<ClauseContext>();
        stack.Push(ClauseContext.None);

        int len = Math.Min(targetIndex, sql.Length);
        int i = 0;

        while (i < len)
        {
            char c = sql[i];

            if (c == '(')
            {
                // When entering parentheses, inherit the active clause context
                // (e.g. parenthesized table sources like FROM (tbl) or subqueries like FROM (SELECT...))
                stack.Push(stack.Peek());
                i++;
                continue;
            }

            if (c == ')')
            {
                if (stack.Count > 1)
                {
                    stack.Pop();
                }
                i++;
                continue;
            }

            // Skip bracketed identifiers [ID]
            if (c == '[')
            {
                int close = sql.IndexOf(']', i);
                i = (close >= 0 && close < len) ? close + 1 : len;
                continue;
            }

            // Skip quoted identifiers "ID"
            if (c == '"')
            {
                int close = sql.IndexOf('"', i + 1);
                i = (close >= 0 && close < len) ? close + 1 : len;
                continue;
            }

            // Skip string placeholders 'STR'
            if (c == '\'')
            {
                int close = sql.IndexOf('\'', i + 1);
                i = (close >= 0 && close < len) ? close + 1 : len;
                continue;
            }

            // Keyword token
            if (char.IsLetter(c))
            {
                int start = i;
                while (i < len && (char.IsLetterOrDigit(sql[i]) || sql[i] == '_'))
                {
                    i++;
                }
                string word = sql.Substring(start, i - start);

                // Check clause keywords (case-insensitive)
                if (word.Equals("SELECT", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Select);
                }
                else if (word.Equals("FROM", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.From);
                }
                else if (word.Equals("JOIN", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Join);
                }
                else if (word.Equals("APPLY", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Apply);
                }
                else if (word.Equals("INTO", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Into);
                }
                else if (word.Equals("WHERE", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Where);
                }
                else if (word.Equals("ON", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.On);
                }
                else if (word.Equals("HAVING", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Having);
                }
                else if (word.Equals("GROUP", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.GroupBy);
                }
                else if (word.Equals("ORDER", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.OrderBy);
                }
                else if (word.Equals("SET", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Set);
                }
                else if (word.Equals("VALUES", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.Values);
                }
                else if (word.Equals("WITH", StringComparison.OrdinalIgnoreCase))
                {
                    ReplaceTop(stack, ClauseContext.With);
                }
                continue;
            }

            i++;
        }

        ClauseContext current = stack.Peek();
        return current == ClauseContext.From ||
               current == ClauseContext.Join ||
               current == ClauseContext.Apply ||
               current == ClauseContext.Into;
    }

    private static void ReplaceTop(Stack<ClauseContext> stack, ClauseContext newContext)
    {
        if (stack.Count > 0)
            stack.Pop();
        stack.Push(newContext);
    }

    /// <summary>
    /// Skips a delimited identifier ([name] or "name") that starts at <paramref name="start"/>.
    /// The closing delimiter is escaped by doubling it (]] or "").
    /// Returns the index right after the closing delimiter, or -1 if the identifier is not closed.
    /// </summary>
    private static int SkipDelimitedIdentifier(string sql, int start, char close)
    {
        int len = sql.Length;
        int i = start + 1; // skip the opening delimiter
        while (i < len)
        {
            if (sql[i] == close)
            {
                if (i + 1 < len && sql[i + 1] == close)
                {
                    i += 2; // escaped delimiter, still inside the identifier
                    continue;
                }
                return i + 1;
            }
            i++;
        }
        return -1;
    }

    /// <summary>
    /// Helper to remove comments (-- and /* */), replace string literals ('...') with a safe placeholder,
    /// and preserve delimited identifiers ([...] and "...") so that subsequent guardrails (4-part names,
    /// hazardous keywords) correctly inspect the query structure without being bypassed by characters inside identifiers.
    /// Also detects semicolons separating statements.
    /// </summary>
    private static string StripCommentsAndStrings(string sql, out bool hasUnclosedString, out bool hasMultipleStatements)
    {
        hasUnclosedString = false;
        hasMultipleStatements = false;

        var sb = new StringBuilder(sql.Length);
        int len = sql.Length;
        int i = 0;
        bool foundSemicolon = false;

        while (i < len)
        {
            char c = sql[i];

            // Anything that starts after a ';' is a second statement, even a string or an identifier.
            if (foundSemicolon && (c == '[' || c == '"' || c == '\''))
            {
                hasMultipleStatements = true;
                break;
            }

            // Delimited identifiers: [name] and "name". Their content is never code, so quotes,
            // comment markers or ';' inside them must not be interpreted. They are replaced by a
            // placeholder that keeps the identifier shape, so the four-part check still works.
            if (c == '[' || c == '"')
            {
                int end = SkipDelimitedIdentifier(sql, i, c == '[' ? ']' : '"');
                if (end < 0)
                {
                    hasUnclosedString = true; // unclosed identifier: reject like an unclosed string
                    return string.Empty;
                }
                sb.Append(c == '[' ? "[ID]" : "\"ID\"");
                i = end;
                continue;
            }

            // 1. Single line comment: --
            if (c == '-' && i + 1 < len && sql[i + 1] == '-')
            {
                i += 2;
                while (i < len && sql[i] != '\n' && sql[i] != '\r')
                {
                    i++;
                }
                sb.Append(' ');
                continue;
            }

            // 2. Block comment: /* ... */ (supports nested block comments in T-SQL)
            if (c == '/' && i + 1 < len && sql[i + 1] == '*')
            {
                int commentDepth = 1;
                i += 2;
                while (i < len && commentDepth > 0)
                {
                    if (sql[i] == '/' && i + 1 < len && sql[i + 1] == '*')
                    {
                        commentDepth++;
                        i += 2;
                    }
                    else if (sql[i] == '*' && i + 1 < len && sql[i + 1] == '/')
                    {
                        commentDepth--;
                        i += 2;
                    }
                    else
                    {
                        i++;
                    }
                }

                if (commentDepth > 0)
                {
                    hasUnclosedString = true;
                    return string.Empty;
                }

                sb.Append(' ');
                continue;
            }

            // 3. Statement separator ;
            if (c == ';')
            {
                foundSemicolon = true;
                sb.Append(' ');
                i++;
                continue;
            }

            // 4. Check for multiple statements: non-whitespace token encountered after a semicolon
            if (foundSemicolon && !char.IsWhiteSpace(c))
            {
                hasMultipleStatements = true;
                break;
            }

            // 5. String literal: '...'
            if (c == '\'')
            {
                sb.Append("'STR'");
                i++;
                bool closed = false;
                while (i < len)
                {
                    if (sql[i] == '\'')
                    {
                        // Check for escaped quote ''
                        if (i + 1 < len && sql[i + 1] == '\'')
                        {
                            i += 2;
                            continue;
                        }
                        closed = true;
                        i++;
                        break;
                    }
                    i++;
                }
                if (!closed)
                {
                    hasUnclosedString = true;
                    return string.Empty;
                }
                continue;
            }

            // 6. Regular character
            sb.Append(c);
            i++;
        }

        return sb.ToString();
    }
}
