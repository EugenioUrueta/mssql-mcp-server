using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Tools;

public class ProcedureSignatureInfo
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = "dbo";

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("fullName")]
    public string FullName => $"{Schema}.{Name}";

    [JsonPropertyName("parameterCount")]
    public int ParameterCount { get; set; }

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    [JsonPropertyName("details")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ProcedureParameterDetail>? Details { get; set; }
}

public class ProcedureParameterDetail
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("dataType")]
    public string DataType { get; set; } = "";

    [JsonPropertyName("maxLength")]
    public int MaxLength { get; set; }

    [JsonPropertyName("precision")]
    public int Precision { get; set; }

    [JsonPropertyName("scale")]
    public int Scale { get; set; }

    [JsonPropertyName("isOutput")]
    public bool IsOutput { get; set; }
}

public class GetProcedureSignaturesTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    public GetProcedureSignaturesTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager ?? throw new ArgumentNullException(nameof(connectionManager));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    public McpToolDefinition Definition => new()
    {
        Name = "get_procedure_signatures",
        Description = "Retrieves compact typed signatures (parameters, data types, lengths, outputs) for stored procedures matching a pattern or list of procedure names. Fully compatible across all SQL Server versions (compatibility_level 100+).",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                pattern = new
                {
                    type = "string",
                    description = "Search pattern for procedure names (e.g. 'usp_%', 'sales_%'). Supports comma/pipe separation. Aliases: 'patterns', 'search', 'query'."
                },
                patterns = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Optional list of multiple search patterns to match (OR logic)."
                },
                search = new
                {
                    type = "string",
                    description = "Alias for pattern."
                },
                query = new
                {
                    type = "string",
                    description = "Alias for pattern."
                },
                sp_name = new
                {
                    type = "string",
                    description = "Alias for sp_names."
                },
                sp_names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "List of specific stored procedure names to retrieve signatures for. Aliases: 'sp_name', 'procedure_names', 'procedure_name', 'procedures', 'procedure', 'names', 'name'."
                },
                procedure_name = new
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
                procedure = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Alias for sp_names."
                },
                name = new
                {
                    type = "string",
                    description = "Alias for sp_name."
                },
                include_details = new
                {
                    type = "boolean",
                    description = "Whether to include the detailed typed parameter array ({ name, dataType, maxLength, precision, scale, isOutput }) for each procedure. Default is false."
                },
                format = new
                {
                    type = "string",
                    description = "Output format: 'objects' (structured procedure objects) or 'compact' (array of rows). Default is 'objects'.",
                    @enum = new[] { "objects", "compact" }
                },
                indent = new
                {
                    type = "boolean",
                    description = "Whether to format JSON with indentation. Default is false."
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
            }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with 'pattern' or 'sp_names' parameter.");
        }

        var patternList = new List<string>();

        void AddPatterns(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            var parts = raw.Split(new[] { ',', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                string norm = NormalizePattern(part);
                if (!patternList.Contains(norm, StringComparer.OrdinalIgnoreCase))
                {
                    patternList.Add(norm);
                }
            }
        }

        void ProcessPatternProperty(JsonElement elem)
        {
            if (elem.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in elem.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        AddPatterns(item.GetString());
                    }
                }
            }
            else if (elem.ValueKind == JsonValueKind.String)
            {
                AddPatterns(elem.GetString());
            }
        }

        string[] patternAliases = { "patterns", "pattern", "search", "query" };
        foreach (var alias in patternAliases)
        {
            if (arguments.Value.TryGetProperty(alias, out var pProp))
            {
                ProcessPatternProperty(pProp);
            }
        }

        var spList = new List<string>();

        void AddSpNames(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            var parts = raw.Split(new[] { ',', '|' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part) && !spList.Contains(part, StringComparer.OrdinalIgnoreCase))
                {
                    spList.Add(part.Trim());
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
                        AddSpNames(item.GetString());
                    }
                }
            }
            else if (elem.ValueKind == JsonValueKind.String)
            {
                AddSpNames(elem.GetString());
            }
        }

        string[] spAliases = { "sp_names", "procedure_names", "procedures", "names", "sp_name", "procedure_name", "procedure", "name" };
        foreach (var alias in spAliases)
        {
            if (arguments.Value.TryGetProperty(alias, out var sProp))
            {
                ProcessSpProperty(sProp);
            }
        }

        if (patternList.Count == 0 && spList.Count == 0)
        {
            return McpToolCallResult.Error("At least one parameter ('pattern' or 'sp_names') is required.");
        }

        bool includeDetails = false;
        if (arguments.Value.TryGetProperty("include_details", out var idProp) &&
            (idProp.ValueKind == JsonValueKind.True || idProp.ValueKind == JsonValueKind.False))
        {
            includeDetails = idProp.GetBoolean();
        }
        else if (arguments.Value.TryGetProperty("details", out var dProp) &&
            (dProp.ValueKind == JsonValueKind.True || dProp.ValueKind == JsonValueKind.False))
        {
            includeDetails = dProp.GetBoolean();
        }

        string format = "objects";
        if (arguments.Value.TryGetProperty("format", out var fmtProp) && fmtProp.ValueKind == JsonValueKind.String)
        {
            string val = fmtProp.GetString()?.Trim().ToLowerInvariant() ?? "";
            if (val == "compact")
            {
                format = "compact";
            }
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
            int compLevel = await _connectionManager.GetCompatibilityLevelAsync(profile, database, cancellationToken);

            var filterConditions = new List<string>();
            var sqlParams = new List<SqlParameter>();

            for (int i = 0; i < patternList.Count; i++)
            {
                string paramName = $"@Pattern_{i}";
                filterConditions.Add($"o.name LIKE {paramName}");
                sqlParams.Add(new SqlParameter(paramName, SqlDbType.NVarChar, 200) { Value = patternList[i] });
            }

            for (int j = 0; j < spList.Count; j++)
            {
                string raw = spList[j].Replace("[", "").Replace("]", "").Trim();
                if (raw.Contains('.'))
                {
                    var parts = raw.Split('.', 2);
                    string schemaParam = $"@SpSchema_{j}";
                    string nameParam = $"@SpName_{j}";
                    filterConditions.Add($"(s.name = {schemaParam} AND o.name = {nameParam})");
                    sqlParams.Add(new SqlParameter(schemaParam, SqlDbType.NVarChar, 128) { Value = parts[0] });
                    sqlParams.Add(new SqlParameter(nameParam, SqlDbType.NVarChar, 128) { Value = parts[1] });
                }
                else
                {
                    string nameParam = $"@SpName_{j}";
                    filterConditions.Add($"o.name = {nameParam}");
                    sqlParams.Add(new SqlParameter(nameParam, SqlDbType.NVarChar, 128) { Value = raw });
                }
            }

            string whereClause = string.Join(" OR ", filterConditions);

            string sql = $@"
SELECT 
    s.name AS schema_name,
    o.name AS sp_name,
    (SELECT COUNT(*) FROM sys.parameters p WHERE p.object_id = o.object_id) AS parameter_count,
    COALESCE(STUFF((
        SELECT ', ' + p.name + ' ' + tp.name + 
            CASE 
                WHEN tp.name IN ('varchar', 'nvarchar', 'char', 'nchar') THEN '(' + CASE WHEN p.max_length = -1 THEN 'max' ELSE CAST(p.max_length AS VARCHAR(10)) END + ')'
                WHEN tp.name IN ('decimal', 'numeric') THEN '(' + CAST(p.precision AS VARCHAR(10)) + ',' + CAST(p.scale AS VARCHAR(10)) + ')'
                ELSE ''
            END + 
            CASE WHEN p.is_output = 1 THEN ' OUTPUT' ELSE '' END
        FROM sys.parameters p
        INNER JOIN sys.types tp ON p.user_type_id = tp.user_type_id
        WHERE p.object_id = o.object_id
        ORDER BY p.parameter_id
        FOR XML PATH(''), TYPE
    ).value('.', 'NVARCHAR(MAX)'), 1, 2, ''), '') AS signature,
    o.object_id
FROM sys.objects o
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
WHERE o.type = 'P' AND o.is_ms_shipped = 0
  AND ({whereClause})
ORDER BY s.name, o.name;";

            var procedures = new List<ProcedureSignatureInfo>();
            var objectIds = new List<int>();
            var objIdToProc = new Dictionary<int, ProcedureSignatureInfo>();

            await using var cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddRange(sqlParams.ToArray());

            await using (var reader = await cmd.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    string schemaName = reader.GetString(0);
                    string spName = reader.GetString(1);
                    int paramCount = reader.GetInt32(2);
                    string signature = reader.IsDBNull(3) ? "" : reader.GetString(3);
                    int objectId = reader.GetInt32(4);

                    var procInfo = new ProcedureSignatureInfo
                    {
                        Schema = schemaName,
                        Name = spName,
                        ParameterCount = paramCount,
                        Signature = signature
                    };

                    procedures.Add(procInfo);
                    objectIds.Add(objectId);
                    objIdToProc[objectId] = procInfo;
                }
            }

            if (includeDetails && objectIds.Count > 0)
            {
                string idList = string.Join(",", objectIds);
                string detailsSql = $@"
SELECT 
    p.object_id,
    p.name AS param_name,
    tp.name AS data_type,
    p.max_length,
    p.precision,
    p.scale,
    p.is_output
FROM sys.parameters p
INNER JOIN sys.types tp ON p.user_type_id = tp.user_type_id
WHERE p.object_id IN ({idList})
ORDER BY p.object_id, p.parameter_id;";

                await using var detailsCmd = new SqlCommand(detailsSql, connection);
                await using (var detailsReader = await detailsCmd.ExecuteReaderAsync(cancellationToken))
                {
                    while (await detailsReader.ReadAsync(cancellationToken))
                    {
                        int objId = detailsReader.GetInt32(0);
                        string paramName = detailsReader.GetString(1);
                        string dataType = detailsReader.GetString(2);
                        short maxLength = detailsReader.GetInt16(3);
                        byte precision = detailsReader.GetByte(4);
                        byte scale = detailsReader.GetByte(5);
                        bool isOutput = detailsReader.GetBoolean(6);

                        if (objIdToProc.TryGetValue(objId, out var targetProc))
                        {
                            targetProc.Details ??= new List<ProcedureParameterDetail>();
                            targetProc.Details.Add(new ProcedureParameterDetail
                            {
                                Name = paramName,
                                DataType = dataType,
                                MaxLength = maxLength,
                                Precision = precision,
                                Scale = scale,
                                IsOutput = isOutput
                            });
                        }
                    }
                }

                // Ensure all procedures have a non-null list for Details when includeDetails is true
                foreach (var p in procedures)
                {
                    p.Details ??= new List<ProcedureParameterDetail>();
                }
            }

            object formatted = FormatResult(connection.Database, compLevel, procedures, format, includeDetails);
            string json = JsonSerializer.Serialize(formatted, new JsonSerializerOptions { WriteIndented = indent });
            return McpToolCallResult.Success(json);
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error retrieving procedure signatures: {ex.Message}");
        }
    }

    public static object FormatResult(
        string database,
        int compatibilityLevel,
        List<ProcedureSignatureInfo> procedures,
        string format = "objects",
        bool includeDetails = false)
    {
        if (string.Equals(format, "compact", StringComparison.OrdinalIgnoreCase))
        {
            var columns = includeDetails
                ? new List<string> { "schema", "name", "parameterCount", "signature", "details" }
                : new List<string> { "schema", "name", "parameterCount", "signature" };

            var rows = new List<object?[]>();
            foreach (var p in procedures)
            {
                if (includeDetails)
                {
                    rows.Add(new object?[] { p.Schema, p.Name, p.ParameterCount, p.Signature, p.Details ?? new List<ProcedureParameterDetail>() });
                }
                else
                {
                    rows.Add(new object?[] { p.Schema, p.Name, p.ParameterCount, p.Signature });
                }
            }

            return new
            {
                database,
                compatibilityLevel,
                count = procedures.Count,
                columns,
                procedures = rows
            };
        }
        else
        {
            var procObjects = new List<object>();
            foreach (var p in procedures)
            {
                if (includeDetails)
                {
                    procObjects.Add(new
                    {
                        schema = p.Schema,
                        name = p.Name,
                        fullName = p.FullName,
                        parameterCount = p.ParameterCount,
                        signature = p.Signature,
                        details = (object)(p.Details ?? new List<ProcedureParameterDetail>())
                    });
                }
                else
                {
                    procObjects.Add(new
                    {
                        schema = p.Schema,
                        name = p.Name,
                        fullName = p.FullName,
                        parameterCount = p.ParameterCount,
                        signature = p.Signature
                    });
                }
            }

            return new
            {
                database,
                compatibilityLevel,
                count = procedures.Count,
                procedures = procObjects
            };
        }
    }

    private static string NormalizePattern(string raw)
    {
        string p = raw.Contains('%') ? raw : raw.Replace('*', '%');
        return p.Contains('%') ? p : $"%{p}%";
    }
}
