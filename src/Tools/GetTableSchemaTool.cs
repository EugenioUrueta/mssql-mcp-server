using System;
using System.Collections.Concurrent;
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

public class GetTableSchemaTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;
    private readonly ConcurrentDictionary<string, (object Result, DateTime Expiry)> _schemaCache = new(StringComparer.OrdinalIgnoreCase);

    public GetTableSchemaTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager;
        _validator = validator;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "get_table_schema",
        Description = "Retrieves comprehensive schema information for one or more tables: columns, data types, nullability, identity, default values, primary keys, foreign keys, and indexes. Supports single table or batch mode, and compact format.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                table_name = new
                {
                    type = "string",
                    description = "Name of the table (e.g. 'Orders' or 'dbo.Orders'). Supports comma-separated list."
                },
                table_names = new
                {
                    type = "array",
                    items = new { type = "string" },
                    description = "Optional list of table names to retrieve schemas for in a single batch."
                },
                compact = new
                {
                    type = "boolean",
                    description = "Whether to return a compact summary schema (omitting verbose column attributes and raw index details). Default is false."
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
                },
                no_cache = new
                {
                    type = "boolean",
                    description = "Whether to bypass the in-memory schema cache (TTL 5 min). Default is false."
                }
            }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with 'table_name' or 'table_names' property.");
        }

        var tableList = new List<string>();

        // 1. Check for 'table_names' array
        if (arguments.Value.TryGetProperty("table_names", out var tNamesProp) && tNamesProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var elem in tNamesProp.EnumerateArray())
            {
                string? t = elem.GetString();
                if (!string.IsNullOrWhiteSpace(t))
                {
                    tableList.Add(t.Trim());
                }
            }
        }

        // 2. Check for 'table_name' string
        if (arguments.Value.TryGetProperty("table_name", out var tProp) && !string.IsNullOrWhiteSpace(tProp.GetString()))
        {
            string raw = tProp.GetString()!.Trim();
            var parts = raw.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (!tableList.Contains(part, StringComparer.OrdinalIgnoreCase))
                {
                    tableList.Add(part);
                }
            }
        }

        if (tableList.Count == 0)
        {
            return McpToolCallResult.Error("Either 'table_name' or 'table_names' parameter is required.");
        }

        // Validate all tables against security guardrails
        foreach (var rawTable in tableList)
        {
            try
            {
                _validator.ValidateTable(rawTable);
            }
            catch (Exception ex)
            {
                return McpToolCallResult.Error($"Security guardrail blocked: {ex.Message}");
            }
        }

        bool compact = false;
        if (arguments.Value.TryGetProperty("compact", out var cmpProp) &&
            (cmpProp.ValueKind == JsonValueKind.True || cmpProp.ValueKind == JsonValueKind.False))
        {
            compact = cmpProp.GetBoolean();
        }

        bool indent = false;
        if (arguments.Value.TryGetProperty("indent", out var indProp) &&
            (indProp.ValueKind == JsonValueKind.True || indProp.ValueKind == JsonValueKind.False))
        {
            indent = indProp.GetBoolean();
        }

        bool noCache = false;
        if (arguments.Value.TryGetProperty("no_cache", out var ncProp) &&
            (ncProp.ValueKind == JsonValueKind.True || ncProp.ValueKind == JsonValueKind.False))
        {
            noCache = ncProp.GetBoolean();
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            var tableResults = new List<object>();
            foreach (var rawTable in tableList)
            {
                string schemaName = "dbo";
                string tableName = rawTable.Replace("[", "").Replace("]", "");
                if (tableName.Contains('.'))
                {
                    var parts = tableName.Split('.', 2);
                    schemaName = parts[0];
                    tableName = parts[1];
                }

                var (schemaObj, error) = await GetSingleTableSchemaAsync(connection, schemaName, tableName, compact, noCache, cancellationToken);
                if (error != null)
                {
                    if (tableList.Count == 1)
                    {
                        return McpToolCallResult.Error(error);
                    }
                    // In batch mode, include the error in the list
                    tableResults.Add(new { table = rawTable, error });
                }
                else if (schemaObj != null)
                {
                    tableResults.Add(schemaObj);
                }
            }

            if (tableList.Count == 1 && tableResults.Count == 1 && !arguments.Value.TryGetProperty("table_names", out _))
            {
                // Single table backwards-compatible format
                var single = tableResults[0];
                var singleWithDb = new
                {
                    database = connection.Database,
                    schema = ((dynamic)single).schema,
                    table = ((dynamic)single).table,
                    fullName = ((dynamic)single).fullName,
                    primaryKey = ((dynamic)single).primaryKey,
                    columns = ((dynamic)single).columns,
                    foreignKeys = ((dynamic)single).foreignKeys,
                    indexes = compact ? null : ((dynamic)single).indexes
                };

                return McpToolCallResult.Success(JsonSerializer.Serialize(singleWithDb, new JsonSerializerOptions { WriteIndented = indent }));
            }

            var batchResult = new
            {
                database = connection.Database,
                tableCount = tableResults.Count,
                compact,
                tables = tableResults
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(batchResult, new JsonSerializerOptions { WriteIndented = indent }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error retrieving table schema: {ex.Message}");
        }
    }

    private async Task<(object? TableResult, string? Error)> GetSingleTableSchemaAsync(
        SqlConnection connection,
        string schemaName,
        string tableName,
        bool compact,
        bool noCache,
        CancellationToken cancellationToken)
    {
        string cacheKey = $"{connection.Database}:{schemaName}.{tableName}:{(compact ? "compact" : "full")}";
        if (!noCache && _schemaCache.TryGetValue(cacheKey, out var cached) && DateTime.UtcNow < cached.Expiry)
        {
            return (cached.Result, null);
        }

        // 1. Primary Key query
        const string pkSql = @"
SELECT 
    i.name AS pk_name,
    c.name AS column_name,
    ic.key_ordinal
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
INNER JOIN sys.tables t ON i.object_id = t.object_id
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE s.name = @SchemaName AND t.name = @TableName AND i.is_primary_key = 1
ORDER BY ic.key_ordinal;";

        await using var cmdPk = new SqlCommand(pkSql, connection);
        cmdPk.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
        cmdPk.Parameters.Add(new SqlParameter("@TableName", SqlDbType.NVarChar, 128) { Value = tableName });

        string? pkName = null;
        var pkColumns = new List<string>();
        await using (var reader = await cmdPk.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                pkName ??= reader.GetString(0);
                pkColumns.Add(reader.GetString(1));
            }
        }

        // 2. Foreign Keys query
        const string fkSql = @"
SELECT 
    fk.name AS fk_name,
    cp.name AS column_name,
    OBJECT_SCHEMA_NAME(fk.referenced_object_id) AS ref_schema,
    OBJECT_NAME(fk.referenced_object_id) AS ref_table,
    cr.name AS ref_column
FROM sys.foreign_keys fk
INNER JOIN sys.foreign_key_columns fkc ON fk.object_id = fkc.constraint_object_id
INNER JOIN sys.columns cp ON fkc.parent_object_id = cp.object_id AND fkc.parent_column_id = cp.column_id
INNER JOIN sys.columns cr ON fkc.referenced_object_id = cr.object_id AND fkc.referenced_column_id = cr.column_id
INNER JOIN sys.tables t ON fk.parent_object_id = t.object_id
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE s.name = @SchemaName AND t.name = @TableName;";

        await using var cmdFk = new SqlCommand(fkSql, connection);
        cmdFk.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
        cmdFk.Parameters.Add(new SqlParameter("@TableName", SqlDbType.NVarChar, 128) { Value = tableName });

        var foreignKeys = new List<object>();
        var fkColumnNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var reader = await cmdFk.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                string col = reader.GetString(1);
                fkColumnNames.Add(col);
                if (compact)
                {
                    foreignKeys.Add(new
                    {
                        name = reader.GetString(0),
                        column = col,
                        references = $"{reader.GetString(2)}.{reader.GetString(3)}.{reader.GetString(4)}"
                    });
                }
                else
                {
                    foreignKeys.Add(new
                    {
                        name = reader.GetString(0),
                        column = col,
                        referencedTable = $"{reader.GetString(2)}.{reader.GetString(3)}",
                        referencedColumn = reader.GetString(4)
                    });
                }
            }
        }

        // 3. Columns query
        const string columnsSql = @"
SELECT 
    c.column_id,
    c.name AS column_name,
    tp.name AS data_type,
    c.max_length,
    c.precision,
    c.scale,
    c.is_nullable,
    c.is_identity,
    OBJECT_DEFINITION(c.default_object_id) AS default_value
FROM sys.columns c
INNER JOIN sys.tables t ON c.object_id = t.object_id
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
INNER JOIN sys.types tp ON c.user_type_id = tp.user_type_id
WHERE s.name = @SchemaName AND t.name = @TableName
ORDER BY c.column_id;";

        await using var cmdCols = new SqlCommand(columnsSql, connection);
        cmdCols.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
        cmdCols.Parameters.Add(new SqlParameter("@TableName", SqlDbType.NVarChar, 128) { Value = tableName });

        var columns = new List<object>();
        await using (var reader = await cmdCols.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                string colName = reader.GetString(1);
                bool isRestricted = _validator.IsColumnDenied(colName);
                bool isPk = pkColumns.Contains(colName, StringComparer.OrdinalIgnoreCase);
                bool isFk = fkColumnNames.Contains(colName);

                if (compact)
                {
                    columns.Add(new
                    {
                        name = colName,
                        type = reader.GetString(2),
                        nullable = reader.GetBoolean(6),
                        isPrimaryKey = isPk,
                        isForeignKey = isFk,
                        isIdentity = reader.GetBoolean(7),
                        isRestricted
                    });
                }
                else
                {
                    columns.Add(new
                    {
                        columnId = reader.GetInt32(0),
                        name = colName,
                        dataType = reader.GetString(2),
                        maxLength = reader.GetInt16(3),
                        precision = reader.GetByte(4),
                        scale = reader.GetByte(5),
                        isNullable = reader.GetBoolean(6),
                        isIdentity = reader.GetBoolean(7),
                        defaultValue = reader.IsDBNull(8) ? null : reader.GetString(8),
                        isRestricted
                    });
                }
            }
        }

        if (columns.Count == 0)
        {
            return (null, $"Table '{schemaName}.{tableName}' was not found in database '{connection.Database}'.");
        }

        // 4. Indexes query
        var indexes = new List<object>();
        if (!compact)
        {
            const string idxSql = @"
SELECT 
    i.name AS index_name,
    i.type_desc,
    i.is_unique,
    i.is_primary_key,
    STRING_AGG(c.name, ', ') WITHIN GROUP (ORDER BY ic.key_ordinal) AS columns
FROM sys.indexes i
INNER JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
INNER JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
INNER JOIN sys.tables t ON i.object_id = t.object_id
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE s.name = @SchemaName AND t.name = @TableName AND i.is_primary_key = 0 AND i.type > 0
GROUP BY i.name, i.type_desc, i.is_unique, i.is_primary_key;";

            await using var cmdIdx = new SqlCommand(idxSql, connection);
            cmdIdx.Parameters.Add(new SqlParameter("@SchemaName", SqlDbType.NVarChar, 128) { Value = schemaName });
            cmdIdx.Parameters.Add(new SqlParameter("@TableName", SqlDbType.NVarChar, 128) { Value = tableName });

            await using (var reader = await cmdIdx.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    indexes.Add(new
                    {
                        name = reader.GetString(0),
                        type = reader.GetString(1),
                        isUnique = reader.GetBoolean(2),
                        columns = reader.GetString(4)
                    });
                }
            }
        }

        object result = compact
            ? new
            {
                schema = schemaName,
                table = tableName,
                fullName = $"{schemaName}.{tableName}",
                primaryKey = pkName != null ? new { name = pkName, columns = pkColumns } : null,
                columns,
                foreignKeys
            }
            : new
            {
                schema = schemaName,
                table = tableName,
                fullName = $"{schemaName}.{tableName}",
                primaryKey = pkName != null ? new { name = pkName, columns = pkColumns } : null,
                columns,
                foreignKeys,
                indexes
            };

        _schemaCache[cacheKey] = (result, DateTime.UtcNow.AddMinutes(5));

        return (result, null);
    }
}
