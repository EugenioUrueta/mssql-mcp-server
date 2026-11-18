using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MssqlMcpServer.Security;

/// <summary>
/// Utility for wildcard pattern matching (* and ?).
/// </summary>
public static class WildcardMatcher
{
    private static readonly ConcurrentDictionary<string, Regex> PatternCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Checks if the input matches the specified wildcard pattern.
    /// </summary>
    public static bool IsMatch(string input, string pattern)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        if (string.IsNullOrEmpty(pattern))
            return false;

        if (pattern == "*")
            return true;

        var regex = PatternCache.GetOrAdd(pattern, p =>
        {
            string regexPattern = "^" + Regex.Escape(p)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") + "$";

            return new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        });

        return regex.IsMatch(input);
    }

    /// <summary>
    /// Checks if the input matches any of the patterns in the collection.
    /// </summary>
    public static bool MatchesAny(string input, IEnumerable<string> patterns)
    {
        if (string.IsNullOrEmpty(input) || patterns == null)
            return false;

        foreach (var pattern in patterns)
        {
            if (IsMatch(input, pattern))
                return true;
        }

        return false;
    }
}
