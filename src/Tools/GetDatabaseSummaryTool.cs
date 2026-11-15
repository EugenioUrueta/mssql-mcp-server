using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Tools;

/// <summary>
/// Provides an executive summary of the active or specified database.
/// Groups tables by functional module prefix, computes total and per-module row counts and table counts,
/// and reports last modification dates.
/// </summary>
public class GetDatabaseSummaryTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    public GetDatabaseSummaryTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager ?? throw new ArgumentNullException(nameof(connectionManager));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    public McpToolDefinition Definition => new()
    {
        Name = "get_database_summary",
        Description = "Provides an executive summary of the active or specified database: groups tables by functional module prefix (e.g. main_*, gen_*, car_*, tes_*), computes total and per-module row counts and table counts, and reports last modification dates.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
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
                include_empty_tables = new
                {
                    type = "boolean",
                    description = "Whether to include tables with 0 rows (default true)."
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
        string? profile = null;
        string? database = null;
        bool includeEmptyTables = true;
        bool indent = false;

        if (arguments.HasValue && arguments.Value.ValueKind == JsonValueKind.Object)
        {
            var args = arguments.Value;
            if (args.TryGetProperty("profile", out var pProp) && pProp.ValueKind == JsonValueKind.String)
            {
                profile = pProp.GetString();
            }

            if (args.TryGetProperty("database", out var dProp) && dProp.ValueKind == JsonValueKind.String)
            {
                database = dProp.GetString();
            }

            if (args.TryGetProperty("include_empty_tables", out var eProp) &&
                (eProp.ValueKind == JsonValueKind.True || eProp.ValueKind == JsonValueKind.False))
            {
                includeEmptyTables = eProp.GetBoolean();
            }

            if (args.TryGetProperty("indent", out var iProp) &&
                (iProp.ValueKind == JsonValueKind.True || iProp.ValueKind == JsonValueKind.False))
            {
                indent = iProp.GetBoolean();
            }
        }

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            const string sql = @"
SELECT 
    s.name AS schema_name,
    t.name AS table_name,
    COALESCE(SUM(p.rows), 0) AS row_count,
    t.create_date,
    t.modify_date
FROM sys.tables t
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
LEFT JOIN sys.partitions p ON t.object_id = p.object_id AND p.index_id IN (0, 1)
WHERE t.is_ms_shipped = 0
GROUP BY s.name, t.name, t.create_date, t.modify_date
ORDER BY s.name, t.name;";

            await using var cmd = new SqlCommand(sql, connection);
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

            var moduleDict = new Dictionary<string, (List<object> Tables, long TotalRows)>(StringComparer.OrdinalIgnoreCase);
            int totalTables = 0;
            long totalRows = 0;

            while (await reader.ReadAsync(cancellationToken))
            {
                string schemaName = reader.GetString(0);
                string tableName = reader.GetString(1);
                long rowCount = reader.IsDBNull(2) ? 0L : Convert.ToInt64(reader.GetValue(2));
                DateTime modifyDate = reader.IsDBNull(4) ? DateTime.MinValue : reader.GetDateTime(4);

                // Omit denied tables by validating with guardrails
                try
                {
                    _validator.ValidateTable($"{schemaName}.{tableName}");
                }
                catch
                {
                    // Skip denied tables
                    continue;
                }

                if (!includeEmptyTables && rowCount == 0)
                {
                    continue;
                }

                string module = ExtractModulePrefix(tableName);

                if (!moduleDict.TryGetValue(module, out var moduleData))
                {
                    moduleData = (new List<object>(), 0L);
                    moduleDict[module] = moduleData;
                }

                var tableEntry = new
                {
                    name = tableName,
                    fullName = $"{schemaName}.{tableName}",
                    rowCount,
                    modified = modifyDate.ToString("yyyy-MM-dd HH:mm:ss")
                };

                moduleData.Tables.Add(tableEntry);
                moduleDict[module] = (moduleData.Tables, moduleData.TotalRows + rowCount);

                totalTables++;
                totalRows += rowCount;
            }

            var modulesList = moduleDict
                .OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
                .Select(kvp => new
                {
                    module = kvp.Key,
                    tableCount = kvp.Value.Tables.Count,
                    totalRows = kvp.Value.TotalRows,
                    tables = kvp.Value.Tables
                })
                .ToList();

            var output = new
            {
                database = connection.Database,
                totalTables,
                totalRows,
                modules = modulesList
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(output, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error generating database summary: {ex.Message}");
        }
    }

    public static string ExtractModulePrefix(string? tableName)
    {
        if (string.IsNullOrWhiteSpace(tableName))
        {
            return "general";
        }

        string cleanName = tableName.Trim();
        int underscoreIndex = cleanName.IndexOf('_');
        return underscoreIndex > 0
            ? cleanName.Substring(0, underscoreIndex).ToLowerInvariant()
            : "general";
    }
}
