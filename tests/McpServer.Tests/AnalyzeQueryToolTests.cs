using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Security;
using MssqlMcpServer.Tools;
using Xunit;

namespace McpServer.Tests;

public class AnalyzeQueryToolTests
{
    private readonly InstanceSettings _settings;
    private readonly SessionContext _sessionContext;
    private readonly GuardrailsValidator _validator;
    private readonly InstanceConnectionManager _connectionManager;

    public AnalyzeQueryToolTests()
    {
        _settings = new InstanceSettings
        {
            DefaultProfile = "dev",
            Profiles =
            {
                ["dev"] = new ProfileConfig
                {
                    Description = "Local dev",
                    ConnectionString = "Server=localhost;Database=app_db_dev;User Id=sa;Password=secret;",
                    DefaultDatabase = "app_db_dev",
                    AllowedDatabases = new List<string> { "app_*" },
                    IsReadOnly = false,
                    AllowExecuteSp = false,
                    AllowSimulation = false
                }
            },
            Security = new GlobalSecurity
            {
                DeniedDatabases = new List<string> { "master", "tempdb" },
                DeniedTables = new List<string> { "*Password*", "*Token*" },
                DeniedColumns = new List<string> { "*Password*", "*Secret*" },
                MaxRowsLimit = 100,
                DefaultTimeoutSeconds = 15,
                ProhibitFourPartNames = true
            }
        };

        _sessionContext = new SessionContext(_settings);
        _validator = new GuardrailsValidator(_settings.Security);
        _connectionManager = new InstanceConnectionManager(_settings, _sessionContext, _validator);
    }

    [Fact]
    public async Task AnalyzeQueryTool_RejectsEmptyOrMissingArguments()
    {
        var tool = new AnalyzeQueryTool(_connectionManager, _validator);

        // Null argument
        var res1 = await tool.ExecuteAsync(null);
        Assert.True(res1.IsError);
        Assert.Contains("Arguments object is required", res1.Content[0].Text, StringComparison.OrdinalIgnoreCase);

        // Empty JSON object
        using var emptyDoc = JsonDocument.Parse("{}");
        var res2 = await tool.ExecuteAsync(emptyDoc.RootElement);
        Assert.True(res2.IsError);
        Assert.Contains("parameter is required", res2.Content[0].Text, StringComparison.OrdinalIgnoreCase);

        // Whitespace query
        using var wsDoc = JsonDocument.Parse("""{"query": "   "}""");
        var res3 = await tool.ExecuteAsync(wsDoc.RootElement);
        Assert.True(res3.IsError);
        Assert.Contains("parameter is required", res3.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("DROP TABLE dbo.orders")]
    [InlineData("DELETE FROM dbo.orders WHERE order_id = 1")]
    [InlineData("UPDATE dbo.orders SET total = 100 WHERE order_id = 1")]
    [InlineData("INSERT INTO dbo.orders (order_id) VALUES (1)")]
    [InlineData("ALTER TABLE dbo.orders ADD note NVARCHAR(50)")]
    [InlineData("TRUNCATE TABLE dbo.orders")]
    [InlineData("EXEC usp_get_customer_orders")]
    [InlineData("EXECUTE usp_calculate_tax")]
    public async Task AnalyzeQueryTool_RejectsNonReadQueries_ThroughGuardrails(string mutatingQuery)
    {
        var tool = new AnalyzeQueryTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse($$"""{"query": "{{mutatingQuery}}"}""");
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("rejected by guardrails", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT * FROM linked_srv.app_db.dbo.orders")]
    [InlineData("SELECT * FROM [LINKED_SRV].[app_db].[dbo].[orders]")]
    [InlineData("SELECT o.order_id FROM orders o INNER JOIN remote_srv.app_db.dbo.customers c ON o.customer_id = c.customer_id")]
    public async Task AnalyzeQueryTool_RejectsFourPartNamesInTableSources(string linkedQuery)
    {
        var tool = new AnalyzeQueryTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse($$"""{"query": "{{linkedQuery}}"}""");
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("Four-part object identifiers", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseShowPlanXml_ParsesEstimatedSubtreeCost_AndExpensiveOperations()
    {
        string planXml = """
        <ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.5" Build="15.0">
          <BatchSequence>
            <Batch>
              <Statements>
                <StmtSimple StatementSubTreeCost="0.085" StatementText="SELECT * FROM orders">
                  <QueryPlan>
                    <RelOp NodeId="0" PhysicalOp="Clustered Index Scan" LogicalOp="Clustered Index Scan" EstimatedTotalSubtreeCost="0.050" EstimateRows="500" EstimateIO="0.035" EstimateCPU="0.015">
                      <OutputList />
                      <IndexScan>
                        <Object Database="[app_db_dev]" Schema="[dbo]" Table="[orders]" Index="[PK_orders]" />
                      </IndexScan>
                    </RelOp>
                    <RelOp NodeId="1" PhysicalOp="Sort" LogicalOp="Sort" EstimatedTotalSubtreeCost="0.025" EstimateRows="500" EstimateIO="0.015" EstimateCPU="0.010">
                      <OutputList />
                      <Sort />
                    </RelOp>
                    <RelOp NodeId="2" PhysicalOp="Hash Match" LogicalOp="Inner Join" EstimatedTotalSubtreeCost="0.010" EstimateRows="250" EstimateIO="0.005" EstimateCPU="0.005">
                      <OutputList />
                      <Hash />
                    </RelOp>
                  </QueryPlan>
                </StmtSimple>
              </Statements>
            </Batch>
          </BatchSequence>
        </ShowPlanXML>
        """;

        var analysis = AnalyzeQueryTool.ParseShowPlanXml(planXml, "app_db_dev", includeXml: false);

        Assert.Equal("app_db_dev", analysis.Database);
        Assert.Equal(0.085, analysis.EstimatedTotalSubtreeCost, 3);
        Assert.Null(analysis.XmlPlan);

        Assert.Equal(3, analysis.ExpensiveOperations.Count);

        var scanOp = analysis.ExpensiveOperations[0];
        Assert.Equal(0, scanOp.NodeId);
        Assert.Equal("Clustered Index Scan", scanOp.PhysicalOperation);
        Assert.Equal("[orders]", scanOp.Table);
        Assert.Equal("[PK_orders]", scanOp.Index);
        Assert.Equal(500, scanOp.EstimatedRows);
        Assert.Contains("Clustered index scan", scanOp.Description, StringComparison.OrdinalIgnoreCase);

        var sortOp = analysis.ExpensiveOperations[1];
        Assert.Equal(1, sortOp.NodeId);
        Assert.Equal("Sort", sortOp.PhysicalOperation);
        Assert.Contains("Sort operation", sortOp.Description, StringComparison.OrdinalIgnoreCase);

        var hashOp = analysis.ExpensiveOperations[2];
        Assert.Equal(2, hashOp.NodeId);
        Assert.Equal("Hash Match", hashOp.PhysicalOperation);
        Assert.Equal("Inner Join", hashOp.LogicalOperation);
    }

    [Fact]
    public void ParseShowPlanXml_ParsesMissingIndexes_AndGeneratesSuggestedScript()
    {
        string planXml = """
        <ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.5">
          <BatchSequence>
            <Batch>
              <Statements>
                <StmtSimple StatementSubTreeCost="0.12">
                  <QueryPlan>
                    <MissingIndexes>
                      <MissingIndexGroup Impact="85.4">
                        <MissingIndex Database="[app_db_dev]" Schema="[dbo]" Table="[orders]">
                          <ColumnGroup Usage="EQUALITY">
                            <Column Name="[customer_id]" ColumnId="1" />
                            <Column Name="[status]" ColumnId="2" />
                          </ColumnGroup>
                          <ColumnGroup Usage="INEQUALITY">
                            <Column Name="[created_at]" ColumnId="3" />
                          </ColumnGroup>
                          <ColumnGroup Usage="INCLUDE">
                            <Column Name="[total]" ColumnId="4" />
                            <Column Name="[tax]" ColumnId="5" />
                          </ColumnGroup>
                        </MissingIndex>
                      </MissingIndexGroup>
                    </MissingIndexes>
                  </QueryPlan>
                </StmtSimple>
              </Statements>
            </Batch>
          </BatchSequence>
        </ShowPlanXML>
        """;

        var analysis = AnalyzeQueryTool.ParseShowPlanXml(planXml, "app_db_dev", includeXml: true);

        Assert.NotNull(analysis.XmlPlan);
        Assert.Single(analysis.MissingIndexes);

        var mi = analysis.MissingIndexes[0];
        Assert.Equal(85.4, mi.Impact, 1);
        Assert.Equal("[app_db_dev]", mi.Database);
        Assert.Equal("[dbo]", mi.Schema);
        Assert.Equal("[orders]", mi.Table);

        Assert.Equal(2, mi.EqualityColumns.Count);
        Assert.Contains("[customer_id]", mi.EqualityColumns);
        Assert.Contains("[status]", mi.EqualityColumns);

        Assert.Single(mi.InequalityColumns);
        Assert.Contains("[created_at]", mi.InequalityColumns);

        Assert.Equal(2, mi.IncludeColumns.Count);
        Assert.Contains("[total]", mi.IncludeColumns);
        Assert.Contains("[tax]", mi.IncludeColumns);

        Assert.NotNull(mi.SuggestedIndexScript);
        Assert.Contains("CREATE NONCLUSTERED INDEX", mi.SuggestedIndexScript);
        Assert.Contains("ON [dbo].[orders]", mi.SuggestedIndexScript);
        Assert.Contains("[customer_id], [status], [created_at]", mi.SuggestedIndexScript);
        Assert.Contains("INCLUDE ([total], [tax])", mi.SuggestedIndexScript);
    }

    [Fact]
    public void ParseShowPlanXml_ParsesWarnings_Accurately()
    {
        string planXml = """
        <ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan" Version="1.5">
          <BatchSequence>
            <Batch>
              <Statements>
                <StmtSimple StatementSubTreeCost="0.05">
                  <QueryPlan>
                    <RelOp NodeId="4" PhysicalOp="Filter" LogicalOp="Filter" EstimatedTotalSubtreeCost="0.05">
                      <Warnings>
                        <PlanAffectingConvert ConvertIssue="Seek Plan" Expression="CONVERT_IMPLICIT(int, [col], 0)" />
                        <UnmatchedIndexes />
                        <ColumnsWithNoStatistics>
                          <ColumnReference Column="[missing_stat_col]" />
                        </ColumnsWithNoStatistics>
                      </Warnings>
                    </RelOp>
                  </QueryPlan>
                </StmtSimple>
              </Statements>
            </Batch>
          </BatchSequence>
        </ShowPlanXML>
        """;

        var analysis = AnalyzeQueryTool.ParseShowPlanXml(planXml);

        Assert.Equal(3, analysis.Warnings.Count);

        var convertWarn = analysis.Warnings[0];
        Assert.Equal("PlanAffectingConvert", convertWarn.WarningType);
        Assert.Contains("Seek Plan", convertWarn.Message);
        Assert.Equal(4, convertWarn.NodeId);

        var unmatchedWarn = analysis.Warnings[1];
        Assert.Equal("UnmatchedIndexes", unmatchedWarn.WarningType);

        var noStatsWarn = analysis.Warnings[2];
        Assert.Equal("ColumnsWithNoStatistics", noStatsWarn.WarningType);
        Assert.Contains("[missing_stat_col]", noStatsWarn.Message);
    }

    [Fact]
    public void ParseShowPlanXml_HandlesEmptyOrWhitespaceGracefully()
    {
        var analysisEmpty = AnalyzeQueryTool.ParseShowPlanXml("", "app_db_dev");
        Assert.Equal(0.0, analysisEmpty.EstimatedTotalSubtreeCost);
        Assert.Empty(analysisEmpty.ExpensiveOperations);
        Assert.Empty(analysisEmpty.MissingIndexes);
        Assert.Empty(analysisEmpty.Warnings);

        var analysisWs = AnalyzeQueryTool.ParseShowPlanXml("   ", "app_db_dev");
        Assert.Equal(0.0, analysisWs.EstimatedTotalSubtreeCost);
        Assert.Empty(analysisWs.ExpensiveOperations);
    }
}
