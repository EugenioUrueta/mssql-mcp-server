using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Tools;

public class ReadQueryTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;
    private readonly GlobalSecurity _security;

    public ReadQueryTool(
        InstanceConnectionManager connectionManager,
        GuardrailsValidator validator,
        GlobalSecurity security)
    {
        _connectionManager = connectionManager;
        _validator = validator;
        _security = security;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "read_query",
        Description = "Executes a safe read-only SQL query (SELECT or WITH CTE). Strictly rejects any modification or DDL statements (INSERT, UPDATE, DELETE, DROP, ALTER, EXEC, etc.). Enforces row limits and timeouts.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                query = new
                {
                    type = "string",
                    description = "The read-only SQL query to execute (SELECT / WITH CTE). Alias: 'sql'."
                },
                sql = new
                {
                    type = "string",
                    description = "Alias for query."
                },
                max_rows = new
                {
                    type = "integer",
                    description = "Maximum number of rows to return (capped by server policy, default 500)."
                },
                timeout_seconds = new
                {
                    type = "integer",
                    description = "Execution timeout in seconds (default 30, maximum 300)."
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
                format = new
                {
                    type = "string",
                    description = "Output format: 'objects' (array of JSON objects per row, default) or 'compact' (array of row value arrays matching the columns array).",
                    @enum = new[] { "objects", "compact" }
                },
                indent = new
                {
                    type = "boolean",
                    description = "Whether to format JSON with indentation. Default is false to minimize token consumption."
                }
            },
            required = new[] { "query" }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with a 'query' or 'sql' property.");
        }

        string? rawQuery = null;
        if (arguments.Value.TryGetProperty("query", out var qProp) && !string.IsNullOrWhiteSpace(qProp.GetString()))
        {
            rawQuery = qProp.GetString()!.Trim();
        }
        else if (arguments.Value.TryGetProperty("sql", out var sqlProp) && !string.IsNullOrWhiteSpace(sqlProp.GetString()))
        {
            rawQuery = sqlProp.GetString()!.Trim();
        }

        if (string.IsNullOrWhiteSpace(rawQuery))
        {
            return McpToolCallResult.Error("The 'query' (or 'sql') parameter is required.");
        }

        // Validate query safety through guardrails
        var safety = _validator.ValidateReadQuery(rawQuery);
        if (!safety.IsSafe)
        {
            return McpToolCallResult.Error($"Query rejected by guardrails: {safety.ErrorMessage}");
        }

        // Determine max rows
        int maxRows = _security.MaxRowsLimit;
        if (arguments.Value.TryGetProperty("max_rows", out var mrProp) && mrProp.TryGetInt32(out int customMaxRows))
        {
            if (customMaxRows > 0)
            {
                maxRows = Math.Min(customMaxRows, _security.MaxRowsLimit);
            }
        }

        // Determine timeout
        int timeout = _security.DefaultTimeoutSeconds;
        if (arguments.Value.TryGetProperty("timeout_seconds", out var toProp) && toProp.TryGetInt32(out int customTimeout))
        {
            if (customTimeout > 0)
            {
                timeout = Math.Min(customTimeout, 300);
            }
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        string format = "objects";
        if (arguments.Value.TryGetProperty("format", out var fmtProp) && !string.IsNullOrWhiteSpace(fmtProp.GetString()))
        {
            string requestedFormat = fmtProp.GetString()!.Trim().ToLowerInvariant();
            if (requestedFormat == "compact")
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

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);
            await using var cmd = new SqlCommand(rawQuery, connection)
            {
                CommandTimeout = timeout
            };

            var objectRows = new List<Dictionary<string, object?>>();
            var compactRows = new List<List<object?>>();
            var columnNames = new List<string>();
            bool truncated = false;

            await using (var reader = await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess, cancellationToken))
            {
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    columnNames.Add(reader.GetName(i));
                }

                int rowCount = 0;
                while (await reader.ReadAsync(cancellationToken))
                {
                    if (rowCount >= maxRows)
                    {
                        truncated = true;
                        break;
                    }

                    if (format == "compact")
                    {
                        var rowList = new List<object?>(reader.FieldCount);
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            string colName = columnNames[i];
                            if (_validator.IsColumnDenied(colName))
                            {
                                rowList.Add("***RESTRICTED***");
                            }
                            else
                            {
                                rowList.Add(reader.IsDBNull(i) ? null : reader.GetValue(i));
                            }
                        }
                        compactRows.Add(rowList);
                    }
                    else
                    {
                        var rowDict = new Dictionary<string, object?>(reader.FieldCount);
                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            string colName = columnNames[i];
                            if (_validator.IsColumnDenied(colName))
                            {
                                rowDict[colName] = "***RESTRICTED***";
                            }
                            else
                            {
                                rowDict[colName] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                            }
                        }
                        objectRows.Add(rowDict);
                    }

                    rowCount++;
                }
            }

            int finalRowCount = format == "compact" ? compactRows.Count : objectRows.Count;
            object dataPayload = format == "compact" ? compactRows : objectRows;

            var result = new
            {
                database = connection.Database,
                format,
                rowCount = finalRowCount,
                maxRowsEnforced = maxRows,
                isTruncated = truncated,
                columns = columnNames,
                data = dataPayload
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error executing read query: {ex.Message}");
        }
    }
}
