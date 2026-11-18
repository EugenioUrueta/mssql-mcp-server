using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Tools;

/// <summary>
/// Result of an execution plan analysis.
/// </summary>
public class QueryAnalysisResult
{
    [JsonPropertyName("database")]
    public string? Database { get; set; }

    [JsonPropertyName("estimatedTotalSubtreeCost")]
    public double EstimatedTotalSubtreeCost { get; set; }

    [JsonPropertyName("expensiveOperations")]
    public List<QueryExpensiveOperation> ExpensiveOperations { get; set; } = new();

    [JsonPropertyName("missingIndexes")]
    public List<QueryMissingIndex> MissingIndexes { get; set; } = new();

    [JsonPropertyName("warnings")]
    public List<QueryPlanWarning> Warnings { get; set; } = new();

    [JsonPropertyName("xmlPlan")]
    public string? XmlPlan { get; set; }
}

/// <summary>
/// Represents an expensive physical or logical operator detected in the execution plan.
/// </summary>
public class QueryExpensiveOperation
{
    [JsonPropertyName("nodeId")]
    public int NodeId { get; set; }

    [JsonPropertyName("physicalOperation")]
    public string PhysicalOperation { get; set; } = string.Empty;

    [JsonPropertyName("logicalOperation")]
    public string LogicalOperation { get; set; } = string.Empty;

    [JsonPropertyName("estimatedSubtreeCost")]
    public double EstimatedSubtreeCost { get; set; }

    [JsonPropertyName("estimatedCost")]
    public double EstimatedCost { get; set; }

    [JsonPropertyName("estimatedRows")]
    public double EstimatedRows { get; set; }

    [JsonPropertyName("table")]
    public string? Table { get; set; }

    [JsonPropertyName("index")]
    public string? Index { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

/// <summary>
/// Represents a missing index recommendation extracted from the execution plan XML.
/// </summary>
public class QueryMissingIndex
{
    [JsonPropertyName("impact")]
    public double Impact { get; set; }

    [JsonPropertyName("database")]
    public string? Database { get; set; }

    [JsonPropertyName("schema")]
    public string? Schema { get; set; }

    [JsonPropertyName("table")]
    public string? Table { get; set; }

    [JsonPropertyName("equalityColumns")]
    public List<string> EqualityColumns { get; set; } = new();

    [JsonPropertyName("inequalityColumns")]
    public List<string> InequalityColumns { get; set; } = new();

    [JsonPropertyName("includeColumns")]
    public List<string> IncludeColumns { get; set; } = new();

    [JsonPropertyName("suggestedIndexScript")]
    public string? SuggestedIndexScript { get; set; }
}

/// <summary>
/// Represents a warning identified in the query plan (e.g., implicit conversions, missing stats).
/// </summary>
public class QueryPlanWarning
{
    [JsonPropertyName("warningType")]
    public string WarningType { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    [JsonPropertyName("nodeId")]
    public int? NodeId { get; set; }
}

/// <summary>
/// MCP tool handler that analyzes SQL query execution plans without executing the query
/// using 'SET SHOWPLAN_XML ON' and synthesizes key metrics, expensive operations, missing indexes, and warnings.
/// </summary>
public class AnalyzeQueryTool : IMcpToolHandler
{
    private readonly InstanceConnectionManager _connectionManager;
    private readonly GuardrailsValidator _validator;

    private static readonly HashSet<string> ExpensiveOpExactNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Table Scan",
        "Clustered Index Scan",
        "Index Scan",
        "Hash Match",
        "Sort"
    };

    public AnalyzeQueryTool(
        InstanceConnectionManager connectionManager,
        GuardrailsValidator validator)
    {
        _connectionManager = connectionManager ?? throw new ArgumentNullException(nameof(connectionManager));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    public McpToolDefinition Definition => new()
    {
        Name = "analyze_query",
        Description = "Analyzes a SQL query execution plan without executing the query (using SET SHOWPLAN_XML ON). Returns estimated subtree cost, expensive operations (scans, sorts, hash matches), missing index recommendations with impact, and query plan warnings.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                query = new
                {
                    type = "string",
                    description = "The read-only SQL query to analyze (SELECT / WITH CTE). Alias: 'sql'."
                },
                sql = new
                {
                    type = "string",
                    description = "Alias for query."
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
                include_xml = new
                {
                    type = "boolean",
                    description = "Whether to include the raw ShowPlanXML string in the response. Default is false."
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

        // Validate query safety through guardrails (reject mutations, DDL, four-part linked server names)
        var safety = _validator.ValidateReadQuery(rawQuery);
        if (!safety.IsSafe)
        {
            return McpToolCallResult.Error($"Query rejected by guardrails: {safety.ErrorMessage}");
        }

        string? profile = arguments.Value.TryGetProperty("profile", out var prProp) ? prProp.GetString() : null;
        string? database = arguments.Value.TryGetProperty("database", out var dbProp) ? dbProp.GetString() : null;

        bool includeXml = false;
        if (arguments.Value.TryGetProperty("include_xml", out var xmlProp) &&
            (xmlProp.ValueKind == JsonValueKind.True || xmlProp.ValueKind == JsonValueKind.False))
        {
            includeXml = xmlProp.GetBoolean();
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

            string rawXml = string.Empty;

            // Enable SHOWPLAN_XML
            await using (var cmdOn = new SqlCommand("SET SHOWPLAN_XML ON;", connection))
            {
                await cmdOn.ExecuteNonQueryAsync(cancellationToken);
            }

            try
            {
                await using var planCmd = new SqlCommand(rawQuery, connection)
                {
                    CommandTimeout = 60
                };

                await using var reader = await planCmd.ExecuteReaderAsync(cancellationToken);
                var sb = new StringBuilder();

                while (await reader.ReadAsync(cancellationToken))
                {
                    if (!reader.IsDBNull(0))
                    {
                        var val = reader.GetValue(0);
                        if (val is System.Data.SqlTypes.SqlXml sqlXml)
                        {
                            sb.Append(sqlXml.Value);
                        }
                        else
                        {
                            sb.Append(val.ToString());
                        }
                    }
                }

                while (await reader.NextResultAsync(cancellationToken))
                {
                    while (await reader.ReadAsync(cancellationToken))
                    {
                        if (!reader.IsDBNull(0))
                        {
                            var val = reader.GetValue(0);
                            if (val is System.Data.SqlTypes.SqlXml sqlXml)
                            {
                                sb.Append(sqlXml.Value);
                            }
                            else
                            {
                                sb.Append(val.ToString());
                            }
                        }
                    }
                }

                rawXml = sb.ToString();
            }
            finally
            {
                try
                {
                    await using var cmdOff = new SqlCommand("SET SHOWPLAN_XML OFF;", connection);
                    await cmdOff.ExecuteNonQueryAsync(cancellationToken);
                }
                catch
                {
                    // Suppress cleanup failure if connection is closed or broken
                }
            }

            if (string.IsNullOrWhiteSpace(rawXml))
            {
                return McpToolCallResult.Error("No execution plan XML was returned by SQL Server.");
            }

            var analysis = ParseShowPlanXml(rawXml, connection.Database, includeXml);

            var json = JsonSerializer.Serialize(analysis, new JsonSerializerOptions
            {
                WriteIndented = indent,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            });

            return McpToolCallResult.Success(json);
        }
        catch (Exception ex)
        {
            return McpToolCallResult.Error($"Error analyzing query execution plan: {ex.Message}");
        }
    }

    /// <summary>
    /// Parses ShowPlanXML content and extracts estimated total cost, expensive operations,
    /// missing index recommendations, and query warnings.
    /// </summary>
    public static QueryAnalysisResult ParseShowPlanXml(string xmlContent, string? database = null, bool includeXml = false)
    {
        var result = new QueryAnalysisResult
        {
            Database = database,
            XmlPlan = includeXml ? xmlContent : null
        };

        if (string.IsNullOrWhiteSpace(xmlContent))
        {
            return result;
        }

        var doc = XDocument.Parse(xmlContent);

        // 1. Estimated Total Subtree Cost
        double totalCost = 0.0;
        var stmts = doc.Descendants().Where(e => e.Name.LocalName is "StmtSimple" or "StmtCond" or "StmtCursor");
        foreach (var stmt in stmts)
        {
            var costAttr = stmt.Attribute("StatementSubTreeCost");
            if (costAttr != null && double.TryParse(costAttr.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double cost))
            {
                totalCost += cost;
            }
        }

        if (totalCost == 0.0)
        {
            var relOps = doc.Descendants().Where(e => e.Name.LocalName == "RelOp");
            foreach (var relOp in relOps)
            {
                var costAttr = relOp.Attribute("EstimatedTotalSubtreeCost");
                if (costAttr != null && double.TryParse(costAttr.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double cost))
                {
                    if (cost > totalCost)
                    {
                        totalCost = cost;
                    }
                }
            }
        }

        result.EstimatedTotalSubtreeCost = totalCost;

        // 2. Expensive Operations
        var allRelOps = doc.Descendants().Where(e => e.Name.LocalName == "RelOp");
        foreach (var relOp in allRelOps)
        {
            string physicalOp = relOp.Attribute("PhysicalOp")?.Value ?? string.Empty;
            string logicalOp = relOp.Attribute("LogicalOp")?.Value ?? string.Empty;

            if (IsExpensiveOperation(physicalOp, logicalOp))
            {
                int.TryParse(relOp.Attribute("NodeId")?.Value, out int nodeId);
                double.TryParse(relOp.Attribute("EstimatedTotalSubtreeCost")?.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double estSubCost);
                double.TryParse(relOp.Attribute("EstimateRows")?.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double estRows);
                double.TryParse(relOp.Attribute("EstimateIO")?.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double estIo);
                double.TryParse(relOp.Attribute("EstimateCPU")?.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double estCpu);

                double estCost = (estIo + estCpu) > 0 ? (estIo + estCpu) : estSubCost;

                var objElem = relOp.Descendants().FirstOrDefault(e => e.Name.LocalName == "Object");
                string? table = objElem?.Attribute("Table")?.Value;
                string? index = objElem?.Attribute("Index")?.Value;

                string targetDesc = !string.IsNullOrEmpty(index) ? $"{table} ({index})" : (table ?? "table");
                string desc = physicalOp switch
                {
                    "Table Scan" => $"Table scan on {targetDesc}: sequentially scans entire table. Candidate for indexing.",
                    "Clustered Index Scan" => $"Clustered index scan on {targetDesc}: full scan of clustered index leaves.",
                    "Index Scan" => $"Index scan on {targetDesc}: full scan of nonclustered index leaves.",
                    "Hash Match" => $"Hash match ({logicalOp}): in-memory hash join/aggregation operation.",
                    "Sort" => "Sort operation: orders rows and may spill to tempdb if memory is constrained.",
                    _ => $"{physicalOp} ({logicalOp}) operation."
                };

                result.ExpensiveOperations.Add(new QueryExpensiveOperation
                {
                    NodeId = nodeId,
                    PhysicalOperation = physicalOp,
                    LogicalOperation = logicalOp,
                    EstimatedSubtreeCost = estSubCost,
                    EstimatedCost = estCost,
                    EstimatedRows = estRows,
                    Table = table,
                    Index = index,
                    Description = desc
                });
            }
        }

        // 3. Missing Indexes
        var missingIndexGroups = doc.Descendants().Where(e => e.Name.LocalName == "MissingIndexGroup");
        foreach (var group in missingIndexGroups)
        {
            double impact = 0.0;
            if (double.TryParse(group.Attribute("Impact")?.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out double imp))
            {
                impact = imp;
            }

            var missingIndexElems = group.Descendants().Where(e => e.Name.LocalName == "MissingIndex");
            foreach (var mi in missingIndexElems)
            {
                string? miDb = mi.Attribute("Database")?.Value;
                string? miSchema = mi.Attribute("Schema")?.Value;
                string? miTable = mi.Attribute("Table")?.Value;

                var equalityCols = new List<string>();
                var inequalityCols = new List<string>();
                var includeCols = new List<string>();

                var colGroups = mi.Descendants().Where(e => e.Name.LocalName == "ColumnGroup");
                foreach (var cg in colGroups)
                {
                    string usage = cg.Attribute("Usage")?.Value?.ToUpperInvariant() ?? string.Empty;
                    var cols = cg.Descendants()
                        .Where(e => e.Name.LocalName == "Column")
                        .Select(c => c.Attribute("Name")?.Value)
                        .Where(n => !string.IsNullOrEmpty(n))
                        .Select(n => n!)
                        .ToList();

                    if (usage == "EQUALITY")
                    {
                        equalityCols.AddRange(cols);
                    }
                    else if (usage == "INEQUALITY")
                    {
                        inequalityCols.AddRange(cols);
                    }
                    else if (usage == "INCLUDE")
                    {
                        includeCols.AddRange(cols);
                    }
                }

                string? script = GenerateSuggestedIndexScript(miTable, miSchema, equalityCols, inequalityCols, includeCols);

                result.MissingIndexes.Add(new QueryMissingIndex
                {
                    Impact = impact,
                    Database = miDb,
                    Schema = miSchema,
                    Table = miTable,
                    EqualityColumns = equalityCols,
                    InequalityColumns = inequalityCols,
                    IncludeColumns = includeCols,
                    SuggestedIndexScript = script
                });
            }
        }

        // 4. Warnings
        var warningElements = doc.Descendants().Where(e => e.Name.LocalName == "Warnings");
        foreach (var wElem in warningElements)
        {
            int? nodeId = null;
            var relOpAncestor = wElem.Ancestors().FirstOrDefault(a => a.Name.LocalName == "RelOp");
            if (relOpAncestor != null && int.TryParse(relOpAncestor.Attribute("NodeId")?.Value, out int nid))
            {
                nodeId = nid;
            }

            foreach (var child in wElem.Elements())
            {
                string childName = child.Name.LocalName;
                string msg;
                if (childName == "PlanAffectingConvert")
                {
                    string issue = child.Attribute("ConvertIssue")?.Value ?? "Implicit conversion";
                    string expr = child.Attribute("Expression")?.Value ?? string.Empty;
                    msg = string.IsNullOrEmpty(expr)
                        ? $"Plan affecting convert: {issue}"
                        : $"Plan affecting convert ({issue}): {expr}";
                }
                else if (childName == "UnmatchedIndexes")
                {
                    msg = "Unmatched indexes detected in query plan.";
                }
                else if (childName == "ColumnsWithNoStatistics")
                {
                    var colNames = child.Descendants()
                        .Where(e => e.Name.LocalName == "ColumnReference")
                        .Select(c => c.Attribute("Column")?.Value)
                        .Where(c => !string.IsNullOrEmpty(c));
                    string cols = string.Join(", ", colNames);
                    msg = string.IsNullOrEmpty(cols)
                        ? "Columns with no statistics found."
                        : $"Columns with no statistics: {cols}";
                }
                else if (childName == "SpillToTempDb")
                {
                    string level = child.Attribute("SpillLevel")?.Value ?? "1";
                    msg = $"Operator spilled to tempdb (Level {level}).";
                }
                else if (childName == "MemoryGrantWarning")
                {
                    string kind = child.Attribute("GrantWarningKind")?.Value ?? "Grant warning";
                    msg = $"Memory grant warning: {kind}.";
                }
                else
                {
                    msg = $"Execution plan warning: {childName}.";
                }

                result.Warnings.Add(new QueryPlanWarning
                {
                    WarningType = childName,
                    Message = msg,
                    NodeId = nodeId
                });
            }

            foreach (var attr in wElem.Attributes())
            {
                if (attr.Value.Equals("true", StringComparison.OrdinalIgnoreCase) || attr.Value == "1")
                {
                    string attrName = attr.Name.LocalName;
                    string msg = attrName switch
                    {
                        "NoJoinPredicate" => "No join predicate detected (potential Cartesian product).",
                        "SpatialGuess" => "Spatial guess used in query plan.",
                        _ => $"Plan warning: {attrName}."
                    };

                    result.Warnings.Add(new QueryPlanWarning
                    {
                        WarningType = attrName,
                        Message = msg,
                        NodeId = nodeId
                    });
                }
            }
        }

        return result;
    }

    private static bool IsExpensiveOperation(string physicalOp, string logicalOp)
    {
        if (ExpensiveOpExactNames.Contains(physicalOp) || ExpensiveOpExactNames.Contains(logicalOp))
        {
            return true;
        }

        if (physicalOp.Contains("Scan", StringComparison.OrdinalIgnoreCase) &&
            !physicalOp.Contains("Seek", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (physicalOp.Contains("Hash", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (physicalOp.Contains("Sort", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string? GenerateSuggestedIndexScript(
        string? table,
        string? schema,
        List<string> eqCols,
        List<string> ineqCols,
        List<string> incCols)
    {
        if (string.IsNullOrWhiteSpace(table))
        {
            return null;
        }

        var keyCols = new List<string>();
        keyCols.AddRange(eqCols);
        keyCols.AddRange(ineqCols);

        if (keyCols.Count == 0)
        {
            return null;
        }

        string cleanTable = table.Replace("[", string.Empty).Replace("]", string.Empty);
        string cleanKeys = string.Join("_", keyCols).Replace("[", string.Empty).Replace("]", string.Empty);
        string indexName = $"IX_{cleanTable}_{cleanKeys}";
        if (indexName.Length > 120)
        {
            indexName = indexName.Substring(0, 120);
        }

        string targetTable = string.IsNullOrWhiteSpace(schema) ? table : $"{schema}.{table}";
        string keysList = string.Join(", ", keyCols);
        string includeClause = incCols.Count > 0 ? $" INCLUDE ({string.Join(", ", incCols)})" : string.Empty;

        return $"CREATE NONCLUSTERED INDEX [{indexName}] ON {targetTable} ({keysList}){includeClause};";
    }
}
