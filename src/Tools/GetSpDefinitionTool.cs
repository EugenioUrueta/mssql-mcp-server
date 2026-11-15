using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;

namespace MssqlMcpServer.Tools;

public class StoredProcedureInfo
{
    public string Schema { get; set; } = "";
    public string Procedure { get; set; } = "";
    public string FullName { get; set; } = "";
    public string? Created { get; set; }
    public string? Modified { get; set; }
    public int ParameterCount { get; set; }
    public object Parameters { get; set; } = new List<object>();
    public object? Dependencies { get; set; }
    public string? Definition { get; set; }
}

public class GetSpDefinitionTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;

    public GetSpDefinitionTool(InstanceConnectionManager connectionManager)
    {
        _connectionManager = connectionManager;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "get_sp_definition",
        Description = "Retrieves the full T-SQL definition, typed parameters metadata, and referenced object dependencies for one or more stored procedures. Supports single or batch mode, summary_only to reduce tokens, and aliases 'procedure_name', 'sp', 'name'.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                sp_name = new
                {
                    type = "string",
                    description = "Name of the stored procedure (e.g. 'usp_get_customer_orders' or 'dbo.usp_get_customer_orders'). Supports comma-separated list. Aliases: 'procedure_name', 'procedure', 'sp', 'name'."
                },
                sp_names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Optional list of stored procedure names to retrieve definitions for in a single batch. Aliases: 'procedure_names', 'procedures', 'names'."
                },
                procedure_name = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                procedure = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                sp = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                name = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                procedure_names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Alias for sp_names."
                },
                procedures = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Alias for sp_names."
                },
                names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Alias for sp_names."
                },
                summary_only = new
                {
                    type = "boolean",
                    description = "Whether to omit the full T-SQL definition text to avoid token explosion when inspecting procedures (keeps parameters, metadata, and dependencies). Default is false. Alias: 'compact'."
                },
                compact = new
                {
                    type = "boolean",
                    description = "Alias for summary_only."
                },
                include_dependencies = new
                {
                    type = "boolean",
                    description = "Whether to analyze and return referenced database objects (tables, views, other procedures). Default is false."
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
            return McpToolCallResult.Error("Arguments object is required with a 'sp_name' or 'sp_names' property.");
        }

        var spList = new List<string>();

        void AddSp(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            var parts = raw.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part) && !spList.Contains(part, StringComparer.OrdinalIgnoreCase))
                {
                    spList.Add(part);
                }
            }
        }

        void ProcessSpProperty(JsonElement elem)
        {
            if (elem.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in elem.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        AddSp(item.GetString());
                    }
                }
            }
            else if (elem.ValueKind == JsonValueKind.String)
            {
                AddSp(elem.GetString());
            }
        }

        // 1. Check batch aliases
        string[] batchAliases = { "sp_names", "procedure_names", "procedures", "names" };
        foreach (var alias in batchAliases)
        {
            if (arguments.Value.TryGetProperty(alias, out var bProp))
            {
                ProcessSpProperty(bProp);
            }
        }

        // 2. Check single aliases
        string[] singleAliases = { "sp_name", "procedure_name", "procedure", "sp", "name" };
        foreach (var alias in singleAliases)
        {
            if (arguments.Value.TryGetProperty(alias, out var sProp))
            {
                ProcessSpProperty(sProp);
            }
        }

        if (spList.Count == 0)
        {
            return McpToolCallResult.Error("The 'sp_name' or 'sp_names' parameter is required.");
        }

        bool summaryOnly = false;
        if (arguments.Value.TryGetProperty("summary_only", out var soProp) &&
            (soProp.ValueKind == JsonValueKind.True || soProp.ValueKind == JsonValueKind.False))
        {
            summaryOnly = soProp.GetBoolean();
        }
        else if (arguments.Value.TryGetProperty("compact", out var cmpProp) &&
            (cmpProp.ValueKind == JsonValueKind.True || cmpProp.ValueKind == JsonValueKind.False))
        {
            summaryOnly = cmpProp.GetBoolean();
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        bool includeDependencies = false;
        if (arguments.Value.TryGetProperty("include_dependencies", out var incProp) &&
            (incProp.ValueKind == JsonValueKind.True || incProp.ValueKind == JsonValueKind.False))
        {
            includeDependencies = incProp.GetBoolean();
        }

        bool indent = false;
        if (arguments.Value.TryGetProperty("indent", out var indProp) &&
            (indProp.ValueKind == JsonValueKind.True || indProp.ValueKind == JsonValueKind.False))
        {
            indent = indProp.GetBoolean();
        }

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            var proceduresResults = new List<object>();
            StoredProcedureInfo? firstProcObj = null;

            foreach (var rawSp in spList)
            {
                string schemaName = "dbo";
                string spName = rawSp.Replace("[", "").Replace("]", "");
                if (spName.Contains('.'))
                {
                    var parts = spName.Split('.', 2);
                    schemaName = parts[0];
                    spName = parts[1];
                }

                var (procObj, error) = await GetSingleSpDefinitionAsync(
                    connection,
                    schemaName,
                    spName,
                    includeDependencies,
                    cancellationToken);

                if (error != null)
                {
                    if (spList.Count == 1)
                    {
                        return McpToolCallResult.Error(error);
                    }
                    proceduresResults.Add(new { procedure = rawSp, error });
                }
                else if (procObj != null)
                {
                    firstProcObj ??= procObj;
                    proceduresResults.Add(FormatBatchItem(procObj, summaryOnly));
                }
            }

            if (spList.Count == 1 && firstProcObj != null)
            {
                // Single procedure backwards-compatible format
                var singleWithDb = FormatSingleResult(connection.Database, firstProcObj, summaryOnly);
                return McpToolCallResult.Success(JsonSerializer.Serialize(singleWithDb, new JsonSerializerOptions { WriteIndented = indent }));
            }

            var batchResult = new
            {
                database = connection.Database,
                count = proceduresResults.Count,
                procedures = proceduresResults
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(batchResult, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error retrieving stored procedure definition: {ex.Message}");
        }
    }

    public static object FormatSingleResult(string database, StoredProcedureInfo single, bool summaryOnly)
    {
        return summaryOnly
            ? new
            {
                database,
                schema = single.Schema,
                procedure = single.Procedure,
                fullName = single.FullName,
                created = single.Created,
                modified = single.Modified,
                parameterCount = single.ParameterCount,
                parameters = single.Parameters,
                dependencies = single.Dependencies
            }
            : new
            {
                database,
                schema = single.Schema,
                procedure = single.Procedure,
                fullName = single.FullName,
                created = single.Created,
                modified = single.Modified,
                parameterCount = single.ParameterCount,
                parameters = single.Parameters,
                dependencies = single.Dependencies,
                definition = single.Definition
            };
    }

    public static object FormatBatchItem(StoredProcedureInfo single, bool summaryOnly)
    {
        return summaryOnly
            ? new
            {
                schema = single.Schema,
                procedure = single.Procedure,
                fullName = single.FullName,
                created = single.Created,
                modified = single.Modified,
                parameterCount = single.ParameterCount,
                parameters = single.Parameters,
                dependencies = single.Dependencies
            }
            : new
            {
                schema = single.Schema,
                procedure = single.Procedure,
                fullName = single.FullName,
                created = single.Created,
                modified = single.Modified,
                parameterCount = single.ParameterCount,
                parameters = single.Parameters,
                dependencies = single.Dependencies,
                definition = single.Definition
            };
    }

    private static async Task<(StoredProcedureInfo? Result, string? Error)> GetSingleSpDefinitionAsync(
        SqlConnection connection,
        string schemaName,
        string spName,
        bool includeDependencies,
        CancellationToken cancellationToken)
    {
        // 1. Definition query
        const string defSql = @"
SELECT 
    m.definition,
    o.create_date,
    o.modify_date
FROM sys.sql_modules m
INNER JOIN sys.objects o ON m.object_id = o.object_id
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
WHERE s.name = @SchemaName AND o.name = @SpName;";

        await using var cmdDef = new SqlCommand(defSql, connection);
        cmdDef.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
        cmdDef.Parameters.Add(new SqlParameter("@SpName", SqlDbType.NVarChar, 128) { Value = spName });

        string? definition = null;
        DateTime? created = null;
        DateTime? modified = null;

        await using (var reader = await cmdDef.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                definition = reader.GetString(0);
                created = reader.GetDateTime(1);
                modified = reader.GetDateTime(2);
            }
        }

        if (definition == null && created == null)
        {
            return (null, $"Stored procedure '{schemaName}.{spName}' was not found in database '{connection.Database}' or access was restricted.");
        }

        // 2. Parameters metadata query
        const string paramsSql = @"
SELECT 
    p.parameter_id,
    p.name AS param_name,
    tp.name AS data_type,
    p.max_length,
    p.precision,
    p.scale,
    p.is_output,
    p.has_default_value,
    p.default_value
FROM sys.parameters p
INNER JOIN sys.objects o ON p.object_id = o.object_id
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
INNER JOIN sys.types tp ON p.user_type_id = tp.user_type_id
WHERE s.name = @SchemaName AND o.name = @SpName
ORDER BY p.parameter_id;";

        await using var cmdParams = new SqlCommand(paramsSql, connection);
        cmdParams.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
        cmdParams.Parameters.Add(new SqlParameter("@SpName", SqlDbType.NVarChar, 128) { Value = spName });

        var parameters = new List<object>();
        await using (var reader = await cmdParams.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                parameters.Add(new
                {
                    parameterId = reader.GetInt32(0),
                    name = reader.GetString(1),
                    dataType = reader.GetString(2),
                    maxLength = reader.GetInt16(3),
                    precision = reader.GetByte(4),
                    scale = reader.GetByte(5),
                    isOutput = reader.GetBoolean(6),
                    hasDefaultValue = reader.GetBoolean(7),
                    defaultValue = reader.IsDBNull(8) ? null : reader.GetValue(8)
                });
            }
        }

        // 3. Dependencies query (optional)
        object? dependenciesObj = null;
        if (includeDependencies)
        {
            const string depSql = @"
SELECT DISTINCT 
    COALESCE(sed.referenced_schema_name, 'dbo') AS ref_schema,
    sed.referenced_entity_name AS ref_entity,
    COALESCE(o.type_desc, 'UNKNOWN') AS ref_type
FROM sys.sql_expression_dependencies sed
INNER JOIN sys.objects parent ON sed.referencing_id = parent.object_id
INNER JOIN sys.schemas ps ON parent.schema_id = ps.schema_id
LEFT JOIN sys.objects o ON sed.referenced_id = o.object_id
WHERE ps.name = @SchemaName AND parent.name = @SpName
ORDER BY ref_schema, sed.referenced_entity_name;";

            await using var cmdDep = new SqlCommand(depSql, connection);
            cmdDep.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
            cmdDep.Parameters.Add(new SqlParameter("@SpName", SqlDbType.NVarChar, 128) { Value = spName });

            var refTables = new List<string>();
            var refViews = new List<string>();
            var refProcedures = new List<string>();
            var refOthers = new List<string>();

            await using (var reader = await cmdDep.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    string rSchema = reader.GetString(0);
                    string rEntity = reader.GetString(1);
                    string rType = reader.GetString(2);
                    string fullRef = $"{rSchema}.{rEntity}";

                    if (rType.Contains("TABLE"))
                    {
                        refTables.Add(fullRef);
                    }
                    else if (rType.Contains("VIEW"))
                    {
                        refViews.Add(fullRef);
                    }
                    else if (rType.Contains("PROCEDURE"))
                    {
                        refProcedures.Add(fullRef);
                    }
                    else
                    {
                        refOthers.Add(fullRef);
                    }
                }
            }

            dependenciesObj = new
            {
                tables = refTables,
                views = refViews,
                procedures = refProcedures,
                others = refOthers
            };
        }

        var result = new StoredProcedureInfo
        {
            Schema = schemaName,
            Procedure = spName,
            FullName = $"{schemaName}.{spName}",
            Created = created?.ToString("yyyy-MM-dd HH:mm:ss"),
            Modified = modified?.ToString("yyyy-MM-dd HH:mm:ss"),
            ParameterCount = parameters.Count,
            Parameters = parameters,
            Dependencies = dependenciesObj,
            Definition = definition
        };

        return (result, null);
    }
}
