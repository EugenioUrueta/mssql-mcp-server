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
        Description = "Retrieves the full T-SQL definition, typed parameters metadata, and referenced object dependencies for a stored procedure.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                sp_name = new
                {
                    type = "string",
                    description = "Name of the stored procedure (e.g. 'usp_get_customer_orders' or 'dbo.usp_get_customer_orders')."
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
            },
            required = new[] { "sp_name" }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with a 'sp_name' property.");
        }

        if (!arguments.Value.TryGetProperty("sp_name", out var spProp) || string.IsNullOrWhiteSpace(spProp.GetString()))
        {
            return McpToolCallResult.Error("The 'sp_name' parameter is required.");
        }

        string rawSp = spProp.GetString()!.Trim();
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

        // Parse schema and procedure name
        string schemaName = "dbo";
        string spName = rawSp.Replace("[", "").Replace("]", "");
        if (spName.Contains('.'))
        {
            var parts = spName.Split('.', 2);
            schemaName = parts[0];
            spName = parts[1];
        }

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

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

            if (definition == null)
            {
                return McpToolCallResult.Error($"Stored procedure '{schemaName}.{spName}' was not found in database '{connection.Database}' or access was restricted.");
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

            var result = new
            {
                database = connection.Database,
                schema = schemaName,
                procedure = spName,
                fullName = $"{schemaName}.{spName}",
                created = created?.ToString("yyyy-MM-dd HH:mm:ss"),
                modified = modified?.ToString("yyyy-MM-dd HH:mm:ss"),
                parameterCount = parameters.Count,
                parameters,
                dependencies = dependenciesObj,
                definition
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error retrieving stored procedure definition: {ex.Message}");
        }
    }
}
