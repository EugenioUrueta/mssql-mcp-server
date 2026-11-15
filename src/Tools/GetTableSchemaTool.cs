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

public class GetTableSchemaTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    public GetTableSchemaTool(InstanceConnectionManager connectionManager, GuardrailsValidator validator)
    {
        _connectionManager = connectionManager;
        _validator = validator;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "get_table_schema",
        Description = "Retrieves comprehensive schema information for a table: columns, data types, nullability, identity, default values, primary keys, foreign keys, and indexes.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                table_name = new
                {
                    type = "string",
                    description = "Name of the table (e.g. 'Orders' or 'dbo.Orders')."
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
            required = new[] { "table_name" }
        }
    };

    public async Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        if (!arguments.HasValue || arguments.Value.ValueKind != JsonValueKind.Object)
        {
            return McpToolCallResult.Error("Arguments object is required with a 'table_name' property.");
        }

        if (!arguments.Value.TryGetProperty("table_name", out var tProp) || string.IsNullOrWhiteSpace(tProp.GetString()))
        {
            return McpToolCallResult.Error("The 'table_name' parameter is required.");
        }

        string rawTable = tProp.GetString()!.Trim();

        // Validate table name against security guardrails
        try
        {
            _validator.ValidateTable(rawTable);
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Security guardrail blocked: {ex.Message}");
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        // Parse schema and table name
        string schemaName = "dbo";
        string tableName = rawTable.Replace("[", "").Replace("]", "");
        if (tableName.Contains('.'))
        {
            var parts = tableName.Split('.', 2);
            schemaName = parts[0];
            tableName = parts[1];
        }

        try
        {
            await using var connection = await _connectionManager.OpenConnectionAsync(profile, database, cancellationToken);

            // 1. Columns query
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

            if (columns.Count == 0)
            {
                return McpToolCallResult.Error($"Table '{schemaName}.{tableName}' was not found in database '{connection.Database}'.");
            }

            // 2. Primary Key query
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

            // 3. Foreign Keys query
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
            await using (var reader = await cmdFk.ExecuteReaderAsync(cancellationToken))
            {
                while (await reader.ReadAsync(cancellationToken))
                {
                    foreignKeys.Add(new
                    {
                        name = reader.GetString(0),
                        column = reader.GetString(1),
                        referencedTable = $"{reader.GetString(2)}.{reader.GetString(3)}",
                        referencedColumn = reader.GetString(4)
                    });
                }
            }

            // 4. Indexes query
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

            var indexes = new List<object>();
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

            var result = new
            {
                database = connection.Database,
                schema = schemaName,
                table = tableName,
                fullName = $"{schemaName}.{tableName}",
                primaryKey = pkName != null ? new { name = pkName, columns = pkColumns } : null,
                columns,
                foreignKeys,
                indexes
            };

            return McpToolCallResult.Success(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error retrieving table schema: {ex.Message}");
        }
    }
}
