using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace MssqlMcpServer.Tools;

public class PrimaryKeyInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("columns")]
    public List<string> Columns { get; set; } = new();
}

public class ColumnSchemaInfo
{
    [JsonPropertyName("columnId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? ColumnId { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Type { get; set; }

    [JsonPropertyName("dataType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DataType { get; set; }

    [JsonPropertyName("maxLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public short? MaxLength { get; set; }

    [JsonPropertyName("precision")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte? Precision { get; set; }

    [JsonPropertyName("scale")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public byte? Scale { get; set; }

    [JsonPropertyName("nullable")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Nullable { get; set; }

    [JsonPropertyName("isNullable")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? IsNullable { get; set; }

    [JsonPropertyName("isPrimaryKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? IsPrimaryKey { get; set; }

    [JsonPropertyName("isForeignKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? IsForeignKey { get; set; }

    [JsonPropertyName("isIdentity")]
    public bool IsIdentity { get; set; }

    [JsonPropertyName("defaultValue")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DefaultValue { get; set; }

    [JsonPropertyName("isRestricted")]
    public bool IsRestricted { get; set; }
}

public class ForeignKeyInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("column")]
    public string Column { get; set; } = "";

    [JsonPropertyName("references")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? References { get; set; }

    [JsonPropertyName("referencedTable")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReferencedTable { get; set; }

    [JsonPropertyName("referencedColumn")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ReferencedColumn { get; set; }
}

public class IncomingForeignKeyInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("childTable")]
    public string ChildTable { get; set; } = "";

    [JsonPropertyName("childColumn")]
    public string ChildColumn { get; set; } = "";

    [JsonPropertyName("referencedColumn")]
    public string ReferencedColumn { get; set; } = "";
}

public class IndexInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    [JsonPropertyName("isUnique")]
    public bool IsUnique { get; set; }

    [JsonPropertyName("columns")]
    public string Columns { get; set; } = "";
}

public class TableSchemaInfo
{
    [JsonPropertyName("database")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Database { get; set; }

    [JsonPropertyName("schema")]
    public string Schema { get; set; } = "";

    [JsonPropertyName("table")]
    public string Table { get; set; } = "";

    [JsonPropertyName("fullName")]
    public string FullName { get; set; } = "";

    [JsonPropertyName("primaryKey")]
    public PrimaryKeyInfo? PrimaryKey { get; set; }

    [JsonPropertyName("columns")]
    public List<ColumnSchemaInfo> Columns { get; set; } = new();

    [JsonPropertyName("foreignKeys")]
    public List<ForeignKeyInfo> ForeignKeys { get; set; } = new();

    [JsonPropertyName("referencedBy")]
    public List<IncomingForeignKeyInfo> ReferencedBy { get; set; } = new();

    [JsonPropertyName("incomingForeignKeys")]
    public List<IncomingForeignKeyInfo> IncomingForeignKeys { get; set; } = new();

    [JsonPropertyName("indexes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<IndexInfo>? Indexes { get; set; }

    [JsonPropertyName("sampleRows")]
    public List<Dictionary<string, object?>>? SampleRows { get; set; }

    public TableSchemaInfo CloneWithDatabase(string database) => new()
    {
        Database = database,
        Schema = Schema,
        Table = Table,
        FullName = FullName,
        PrimaryKey = PrimaryKey,
        Columns = Columns,
        ForeignKeys = ForeignKeys,
        ReferencedBy = ReferencedBy,
        IncomingForeignKeys = IncomingForeignKeys,
        Indexes = Indexes,
        SampleRows = SampleRows
    };
}
