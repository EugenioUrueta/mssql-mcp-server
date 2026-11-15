using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Security;
using MssqlMcpServer.Tools;
using Xunit;

namespace McpServer.Tests;

public class ToolExecutionTests
{
    private readonly InstanceSettings _settings;
    private readonly SessionContext _sessionContext;
    private readonly GuardrailsValidator _validator;
    private readonly InstanceConnectionManager _connectionManager;

    public ToolExecutionTests()
    {
        _settings = new InstanceSettings
        {
            DefaultProfile = "dev",
            Profiles =
            {
                ["dev"] = new ProfileConfig
                {
                    Description = "Local dev",
                    ConnectionString = "Server=localhost;Database=DB_Test_Dev;User Id=sa;Password=secret;",
                    DefaultDatabase = "DB_Test_Dev",
                    AllowedDatabases = new List<string> { "DB_*" },
                    IsReadOnly = false,
                    AllowExecuteSp = true,
                    AllowSimulation = true
                },
                ["ro"] = new ProfileConfig
                {
                    Description = "Read Only",
                    ConnectionString = "Server=localhost;Database=DB_Test_Dev;User Id=sa;Password=secret;",
                    DefaultDatabase = "DB_Test_Dev",
                    AllowedDatabases = new List<string> { "DB_*" },
                    IsReadOnly = true,
                    AllowExecuteSp = false,
                    AllowSimulation = true
                }
            },
            Security = new GlobalSecurity
            {
                DeniedDatabases = new List<string> { "master", "tempdb" },
                DeniedTables = new List<string> { "*Password*", "*Token*", "*Session*" },
                DeniedColumns = new List<string> { "*Password*", "*Hash*" },
                MaxRowsLimit = 200,
                DefaultTimeoutSeconds = 15
            }
        };

        _sessionContext = new SessionContext(_settings);
        _validator = new GuardrailsValidator(_settings.Security);
        _connectionManager = new InstanceConnectionManager(_settings, _sessionContext, _validator);
    }

    [Fact]
    public async Task ListProfilesAndDatabasesTool_ReturnsExpectedStructure()
    {
        var tool = new ListProfilesAndDatabasesTool(_settings, _sessionContext);
        var result = await tool.ExecuteAsync(null);

        Assert.False(result.IsError);
        Assert.Single(result.Content);

        using var doc = JsonDocument.Parse(result.Content[0].Text);
        var root = doc.RootElement;

        Assert.Equal("dev", root.GetProperty("activeProfile").GetString());
        Assert.Equal("DB_Test_Dev", root.GetProperty("activeDatabase").GetString());
        Assert.Equal(200, root.GetProperty("maxRowsLimit").GetInt32());

        var profiles = root.GetProperty("configuredProfiles");
        Assert.Equal(2, profiles.GetArrayLength());
    }

    [Fact]
    public async Task ReadQueryTool_RejectsModifyingQueryBeforeDatabaseConnection()
    {
        var tool = new ReadQueryTool(_connectionManager, _validator, _settings.Security);

        string argsJson = """
        {
            "query": "DROP TABLE dbo.Clientes"
        }
        """;

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("rejected by guardrails", result.Content[0].Text, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTableSchemaTool_RejectsDeniedTable()
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        string argsJson = """
        {
            "table_name": "dbo.User_Passwords"
        }
        """;

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("guardrail blocked", result.Content[0].Text, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExecuteSpTool_RejectsExecution_OnReadOnlyProfile()
    {
        var tool = new ExecuteSpTool(_connectionManager, _validator);

        string argsJson = """
        {
            "sp_name": "usp_test_add_item",
            "profile": "ro",
            "simulate": false
        }
        """;

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("read-only", result.Content[0].Text, System.StringComparison.OrdinalIgnoreCase);
    }
}
