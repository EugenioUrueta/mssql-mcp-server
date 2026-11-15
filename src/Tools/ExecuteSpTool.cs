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

public class ExecuteSpTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    public ExecuteSpTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager;
        _validator = validator;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "execute_sp",
        Description = "Executes a stored procedure with typed parameters. Supports simulation mode (runs within a transaction that is rolled back). Enforces profile read-only and execution flags.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                sp_name = new
                {
                    type = "string",
                    description = "Name of the stored procedure to execute (e.g. 'usp_get_customer_orders' or 'dbo.usp_process_invoice')."
                },
                parameters = new
                {
                    type = "object",
                    description = "Key-value dictionary of parameter names and their values (e.g. { '@TenantId': 1, '@OrderId': 42 })."
                },
                simulate = new
                {
                    type = "boolean",
                    description = "If true, executes within a transaction and rolls it back, allowing safe dry-run execution."
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
        bool simulate = arguments.Value.TryGetProperty("simulate", out var simProp) && simProp.GetBoolean();
        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        // Parse profile config and check permissions
        try
        {
            var (_, profileConfig) = _connectionManager.GetProfile(profile);
            _validator.ValidateExecutionPermissions(profileConfig, simulate);
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Execution permission rejected: {ex.Message}");
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
            SqlTransaction? transaction = null;

            if (simulate)
            {
                transaction = (SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
            }

            try
            {
                // Query parameter metadata from sys.parameters
                const string paramMetaSql = @"
SELECT 
    p.name,
    tp.name AS type_name,
    p.is_output,
    p.max_length,
    p.precision,
    p.scale
FROM sys.parameters p
INNER JOIN sys.objects o ON p.object_id = o.object_id
INNER JOIN sys.schemas s ON o.schema_id = s.schema_id
INNER JOIN sys.types tp ON p.user_type_id = tp.user_type_id
WHERE s.name = @SchemaName AND o.name = @SpName;";

                var paramMetaDict = new Dictionary<string, (string TypeName, bool IsOutput, int MaxLength, byte Precision, byte Scale)>(StringComparer.OrdinalIgnoreCase);

                await using (var cmdMeta = new SqlCommand(paramMetaSql, connection, transaction))
                {
                    cmdMeta.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
                    cmdMeta.Parameters.Add(new SqlParameter("@SpName", SqlDbType.NVarChar, 128) { Value = spName });

                    await using var reader = await cmdMeta.ExecuteReaderAsync(cancellationToken);
                    while (await reader.ReadAsync(cancellationToken))
                    {
                        string pName = reader.GetString(0);
                        string typeName = reader.GetString(1);
                        bool isOutput = reader.GetBoolean(2);
                        short maxLen = reader.GetInt16(3);
                        byte prec = reader.GetByte(4);
                        byte scale = reader.GetByte(5);
                        paramMetaDict[pName] = (typeName, isOutput, maxLen, prec, scale);
                    }
                }

                await using var cmd = new SqlCommand($"{schemaName}.{spName}", connection, transaction)
                {
                    CommandType = CommandType.StoredProcedure
                };

                // Add Return Value parameter
                var retParam = new SqlParameter("@RETURN_VALUE", SqlDbType.Int)
                {
                    Direction = ParameterDirection.ReturnValue
                };
                cmd.Parameters.Add(retParam);

                // Add configured parameters
                var userParams = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
                if (arguments.Value.TryGetProperty("parameters", out var pElem) && pElem.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in pElem.EnumerateObject())
                    {
                        string key = prop.Name.StartsWith('@') ? prop.Name : "@" + prop.Name;
                        userParams[key] = prop.Value;
                    }
                }

                // If parameter metadata exists, build typed parameters
                if (paramMetaDict.Count > 0)
                {
                    foreach (var (pName, meta) in paramMetaDict)
                    {
                        var sqlParam = new SqlParameter(pName, MapSqlType(meta.TypeName));
                        if (meta.IsOutput)
                        {
                            sqlParam.Direction = ParameterDirection.InputOutput;
                            if (meta.MaxLength > 0) sqlParam.Size = meta.MaxLength;
                        }

                        if (userParams.TryGetValue(pName, out var userVal))
                        {
                            sqlParam.Value = ConvertJsonElementToSqlValue(userVal);
                        }
                        else
                        {
                            sqlParam.Value = DBNull.Value;
                        }

                        cmd.Parameters.Add(sqlParam);
                    }
                }
                else
                {
                    // Fallback to directly supplied parameters if metadata was unavailable
                    foreach (var (k, v) in userParams)
                    {
                        cmd.Parameters.Add(new SqlParameter(k, ConvertJsonElementToSqlValue(v)));
                    }
                }

                var resultSets = new List<object>();
                await using (var reader = await cmd.ExecuteReaderAsync(cancellationToken))
                {
                    int setIndex = 1;
                    do
                    {
                        var rows = new List<Dictionary<string, object?>>();
                        var colNames = new List<string>();

                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            colNames.Add(reader.GetName(i));
                        }

                        while (await reader.ReadAsync(cancellationToken))
                        {
                            var row = new Dictionary<string, object?>();
                            for (int i = 0; i < reader.FieldCount; i++)
                            {
                                string colName = colNames[i];
                                if (_validator.IsColumnDenied(colName))
                                {
                                    row[colName] = "***RESTRICTED***";
                                }
                                else
                                {
                                    row[colName] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                                }
                            }
                            rows.Add(row);
                        }

                        resultSets.Add(new
                        {
                            resultSet = setIndex++,
                            rowCount = rows.Count,
                            columns = colNames,
                            data = rows
                        });
                    } while (await reader.NextResultAsync(cancellationToken));
                }

                // Capture output parameters
                var outputParams = new Dictionary<string, object?>();
                foreach (SqlParameter p in cmd.Parameters)
                {
                    if (p.Direction is ParameterDirection.Output or ParameterDirection.InputOutput)
                    {
                        outputParams[p.ParameterName] = p.Value == DBNull.Value ? null : p.Value;
                    }
                }

                int returnValue = retParam.Value is int ret ? ret : 0;

                if (simulate && transaction != null)
                {
                    await transaction.RollbackAsync(cancellationToken);
                }

                var result = new
                {
                    procedure = $"{schemaName}.{spName}",
                    database = connection.Database,
                    simulation = simulate,
                    status = simulate ? "Simulation rolled back successfully" : "Executed successfully",
                    returnValue,
                    outputParameters = outputParams,
                    resultSets
                };

                return McpToolCallResult.Success(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch
            {
                if (simulate && transaction != null)
                {
                    try { await transaction.RollbackAsync(cancellationToken); } catch { }
                }
                throw;
            }
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error executing stored procedure: {ex.Message}");
        }
    }

    private static object ConvertJsonElementToSqlValue(JsonElement elem)
    {
        return elem.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => DBNull.Value,
            JsonValueKind.String => elem.GetString() ?? (object)DBNull.Value,
            JsonValueKind.Number => elem.TryGetInt64(out long l) ? l : elem.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => elem.GetRawText()
        };
    }

    private static SqlDbType MapSqlType(string typeName)
    {
        return typeName.ToLowerInvariant() switch
        {
            "bigint" => SqlDbType.BigInt,
            "binary" => SqlDbType.Binary,
            "bit" => SqlDbType.Bit,
            "char" => SqlDbType.Char,
            "date" => SqlDbType.Date,
            "datetime" => SqlDbType.DateTime,
            "datetime2" => SqlDbType.DateTime2,
            "decimal" => SqlDbType.Decimal,
            "float" => SqlDbType.Float,
            "image" => SqlDbType.Image,
            "int" => SqlDbType.Int,
            "money" => SqlDbType.Money,
            "nchar" => SqlDbType.NChar,
            "ntext" => SqlDbType.NText,
            "numeric" => SqlDbType.Decimal,
            "nvarchar" => SqlDbType.NVarChar,
            "real" => SqlDbType.Real,
            "smalldatetime" => SqlDbType.SmallDateTime,
            "smallint" => SqlDbType.SmallInt,
            "smallmoney" => SqlDbType.SmallMoney,
            "text" => SqlDbType.Text,
            "time" => SqlDbType.Time,
            "tinyint" => SqlDbType.TinyInt,
            "uniqueidentifier" => SqlDbType.UniqueIdentifier,
            "varbinary" => SqlDbType.VarBinary,
            "varchar" => SqlDbType.VarChar,
            "xml" => SqlDbType.Xml,
            _ => SqlDbType.NVarChar
        };
    }
}
