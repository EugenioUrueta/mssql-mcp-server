using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Tools;

public class SearchObjectsTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    public SearchObjectsTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager;
        _validator = validator;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "search_objects",
        Description = "Searches for database objects (tables, views, stored procedures) matching a pattern or list of patterns in the active or specified database.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                pattern = new
                {
                    type = "string",
                    description = "Search pattern (e.g. '%orders%', 'inv_%', 'Customers'). Supports comma/pipe separation for multiple patterns."
                },
                patterns = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Optional list of multiple search patterns to match (OR logic)."
                },
                object_type = new
                {
                    type = "string",
                    description = "Type of object to filter: 'TABLE', 'VIEW', 'PROCEDURE', or 'ALL' (default 'ALL').",
                    @enum = new[] { "TABLE", "VIEW", "PROCEDURE", "ALL" }
                },
                include_row_count = new
                {
                    type = "boolean",
                    description = "Whether to include approximate row count for tables (via sys.partitions). Default is false."
                },
                profile = new
                {
                    type = "string",
                    description = "Target profile (optional, defaults to active profile)."
                },
                database = new
                {
                    type = "string",
                    description = "Target database (optional, defaults to active database)."
                },
                indent = new
                {
                    type = "boolean",
                    description = "Whether to format JSON with indentation. Default is false."
                }
            }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with 'pattern' or 'patterns' property.");
        }

        var patternList = new List<string>();

        // 1. Check for 'patterns' array
        if (arguments.Value.TryGetProperty("patterns", out var patsProp) && patsProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var elem in patsProp.EnumerateArray())
            {
                string? p = elem.GetString();
                if (!string.IsNullOrWhiteSpace(p))
                {
                    patternList.Add(NormalizePattern(p.Trim()));
                }
            }
        }

        // 2. Check for 'pattern' string (may be comma/pipe separated)
        if (arguments.Value.TryGetProperty("pattern", out var pProp) && !string.IsNullOrWhiteSpace(pProp.GetString()))
        {
            string raw = pProp.GetString()!.Trim();
            var parts = raw.Split(new[] { ',', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                patternList.Add(NormalizePattern(part));
            }
        }

        if (patternList.Count == 0)
        {
            return McpToolCallResult.Error("Either 'pattern' or 'patterns' parameter is required.");
        }

        string objectType = "ALL";
        if (arguments.Value.TryGetProperty("object_type", out var otProp) && !string.IsNullOrWhiteSpace(otProp.GetString()))
        {
            objectType = otProp.GetString()!.Trim().ToUpperInvariant();
        }

        bool includeRowCount = false;
        if (arguments.Value.TryGetProperty("include_row_count", out var rcProp) &&
            (rcProp.ValueKind == JsonValueKind.True || rcProp.ValueKind == JsonValueKind.False))
        {
            includeRowCount = rcProp.GetBoolean();
        }

        bool indent = false;
        if (arguments.Value.TryGetProperty("indent", out var indProp) &&
            (indProp.ValueKind == JsonValueKind.True || indProp.ValueKind == JsonValueKind.False))
        {
            indent = indProp.GetBoolean();
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            // Build dynamic pattern predicate
            var patternPredicates = new List<string>();
            for (int i = 0; i < patternList.Count; i++)
            {
                patternPredicates.Add($"o.name LIKE @Pattern_{i}");
            }
            string patternClause = string.Join(" OR ", patternPredicates);

            string rowCountSelect = includeRowCount ? ", ps.row_count" : "";
            string rowCountJoin = includeRowCount ? @"
LEFT JOIN (
    SELECT object_id, SUM(rows) AS row_count
    FROM sys.partitions
    WHERE index_id IN (0, 1)
    GROUP BY object_id
) ps ON o.object_id = ps.object_id" : "";

            string sql = $@"
SELECT 
    s.name AS schema_name,
    o.name AS object_name,
    CASE o.type
        WHEN 'U' THEN 'TABLE'
        WHEN 'V' THEN 'VIEW'
        WHEN 'P' THEN 'PROCEDURE'
        WHEN 'PC' THEN 'PROCEDURE'
        WHEN 'FN' THEN 'FUNCTION'
        WHEN 'IF' THEN 'FUNCTION'
        WHEN 'TF' THEN 'FUNCTION'
        ELSE o.type_desc
    END AS object_type,
    o.create_date,
    o.modify_date{rowCountSelect}
FROM sys.objects o
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id{rowCountJoin}
WHERE o.is_ms_shipped = 0
  AND (@Type = 'ALL' OR 
       (@Type = 'TABLE' AND o.type = 'U') OR 
       (@Type = 'VIEW' AND o.type = 'V') OR 
       (@Type = 'PROCEDURE' AND o.type IN ('P', 'PC')))
  AND ({patternClause})
ORDER BY s.name, o.name;";

            await using var cmd = new SqlCommand(sql, connection);
            for (int i = 0; i < patternList.Count; i++)
            {
                cmd.Parameters.Add(new SqlParameter($"@Pattern_{i}", SqlDbType.NVarChar, 200) { Value = patternList[i] });
            }
            cmd.Parameters.Add(new SqlParameter("@Type", SqlDbType.NVarChar, 20) { Value = objectType });

            var results = new List<object>();
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                string schemaName = reader.GetString(0);
                string objectNameVal = reader.GetString(1);
                string typeVal = reader.GetString(2);
                DateTime createDate = reader.GetDateTime(3);
                DateTime modifyDate = reader.GetDateTime(4);
                long? rowCount = null;
                if (includeRowCount && typeVal == "TABLE" && !reader.IsDBNull(5))
                {
                    rowCount = reader.GetInt64(5);
                }

                // If it's a table, verify it's not restricted by DeniedTables
                if (typeVal == "TABLE")
                {
                    try
                    {
                        _validator.ValidateTable($"{schemaName}.{objectNameVal}");
                    }
                    catch
                    {
                        // Skip denied tables from search output
                        continue;
                    }
                }

                if (includeRowCount)
                {
                    results.Add(new
                    {
                        schema = schemaName,
                        name = objectNameVal,
                        fullName = $"{schemaName}.{objectNameVal}",
                        type = typeVal,
                        rowCount,
                        created = createDate.ToString("yyyy-MM-dd HH:mm:ss"),
                        modified = modifyDate.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }
                else
                {
                    results.Add(new
                    {
                        schema = schemaName,
                        name = objectNameVal,
                        fullName = $"{schemaName}.{objectNameVal}",
                        type = typeVal,
                        created = createDate.ToString("yyyy-MM-dd HH:mm:ss"),
                        modified = modifyDate.ToString("yyyy-MM-dd HH:mm:ss")
                    });
                }
            }

            var output = new
            {
                database = connection.Database,
                count = results.Count,
                patterns = patternList,
                objects = results
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error searching database objects: {ex.Message}");
        }
    }

    private static string NormalizePattern(string raw)
    {
        string p = raw.Contains('%') ? raw : raw.Replace('*', '%');
        return p.Contains('%') ? p : $"%{p}%";
    }
}
