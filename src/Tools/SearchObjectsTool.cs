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
        Description = "Searches for database objects (tables, views, stored procedures) matching a pattern in the active or specified database.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                pattern = new
                {
                    type = "string",
                    description = "Search pattern (e.g. '%orders%', 'inv_%', 'Customers')."
                },
                object_type = new
                {
                    type = "string",
                    description = "Type of object to filter: 'TABLE', 'VIEW', 'PROCEDURE', or 'ALL' (default 'ALL').",
                    @enum = new[] { "TABLE", "VIEW", "PROCEDURE", "ALL" }
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
                }
            },
            required = new[] { "pattern" }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with a 'pattern' property.");
        }

        if (!arguments.Value.TryGetProperty("pattern", out var pProp) || string.IsNullOrWhiteSpace(pProp.GetString()))
        {
            return McpToolCallResult.Error("The 'pattern' parameter is required.");
        }

        string rawPattern = pProp.GetString()!.Trim();
        // Translate wildcard * to % if no % present
        string sqlPattern = rawPattern.Contains('%') ? rawPattern : rawPattern.Replace('*', '%');
        if (!sqlPattern.Contains('%'))
        {
            sqlPattern = $"%{sqlPattern}%";
        }

        string objectType = "ALL";
        if (arguments.Value.TryGetProperty("object_type", out var otProp) && !string.IsNullOrWhiteSpace(otProp.GetString()))
        {
            objectType = otProp.GetString()!.Trim().ToUpperInvariant();
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            const string sql = @"
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
    o.modify_date
FROM sys.objects o
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
WHERE o.is_ms_shipped = 0
  AND (@Type = 'ALL' OR 
       (@Type = 'TABLE' AND o.type = 'U') OR 
       (@Type = 'VIEW' AND o.type = 'V') OR 
       (@Type = 'PROCEDURE' AND o.type IN ('P', 'PC')))
  AND o.name LIKE @Pattern
ORDER BY s.name, o.name;";

            await using var cmd = new SqlCommand(sql, connection);
            cmd.Parameters.Add(new SqlParameter("@Pattern", SqlDbType.NVarChar, 200) { Value = sqlPattern });
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

            var output = new
            {
                database = connection.Database,
                count = results.Count,
                pattern = sqlPattern,
                objects = results
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error searching database objects: {ex.Message}");
        }
    }
}
