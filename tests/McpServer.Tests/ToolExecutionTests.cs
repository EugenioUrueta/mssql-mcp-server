using System;
using System.Collections.Generic;
using System.Reflection;
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
        Assert.Contains("rejected by guardrails", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("DROP TABLE dbo.Clientes", "compact", true)]
    [InlineData("DROP TABLE dbo.Clientes", "compact", false)]
    [InlineData("DELETE FROM dbo.Usuarios WHERE 1=1", "compact", true)]
    [InlineData("DELETE FROM dbo.Usuarios WHERE 1=1", "objects", true)]
    [InlineData("TRUNCATE TABLE dbo.AuditLog", "compact", false)]
    [InlineData("ALTER TABLE dbo.Config ADD MaliciousCol INT", "compact", true)]
    [InlineData("UPDATE dbo.Usuarios SET IsAdmin = 1", "objects", true)]
    [InlineData("INSERT INTO dbo.Usuarios (Name) VALUES ('attacker')", "compact", true)]
    public async Task ReadQueryTool_RejectsMaliciousQueries_WithFormatAndIndentArguments(string query, string format, bool indent)
    {
        var tool = new ReadQueryTool(_connectionManager, _validator, _settings.Security);

        var argsObj = new
        {
            query,
            format,
            indent
        };

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(argsObj));
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("rejected by guardrails", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"format": "compact", "indent": true}""")]
    [InlineData("""{"query": "   ", "format": "compact"}""")]
    public async Task ReadQueryTool_RejectsWhenQueryMissingOrEmpty(string argsJson)
    {
        var tool = new ReadQueryTool(_connectionManager, _validator, _settings.Security);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("query", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadQueryTool_RejectsNullArguments()
    {
        var tool = new ReadQueryTool(_connectionManager, _validator, _settings.Security);
        var result = await tool.ExecuteAsync(null);

        Assert.True(result.IsError);
        Assert.Contains("Arguments object is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
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
        Assert.Contains("guardrail blocked", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"table_names": ["dbo.Clientes", "dbo.User_Passwords"]}""")]
    [InlineData("""{"table_names": ["dbo.User_Passwords", "dbo.Articulos"]}""")]
    [InlineData("""{"table_names": ["dbo.Invoices", "dbo.User_Passwords", "dbo.Orders"]}""")]
    [InlineData("""{"table_names": ["dbo.Auth_Token", "dbo.Invoices"]}""")]
    [InlineData("""{"table_names": ["dbo.UserSession"]}""")]
    public async Task GetTableSchemaTool_RejectsMultipleTables_WhenOneOrMoreDeniedInTableNamesArray(string argsJson)
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("guardrail blocked", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"table_name": "dbo.Clientes, dbo.User_Passwords"}""")]
    [InlineData("""{"table_name": "dbo.User_Passwords, dbo.Clientes, dbo.Articulos"}""")]
    [InlineData("""{"table_name": "dbo.Clientes, [dbo].[Auth_Token]"}""")]
    [InlineData("""{"table_name": "UserSession, Clientes"}""")]
    public async Task GetTableSchemaTool_RejectsMultipleTables_WhenOneOrMoreDeniedInCommaSeparatedTableName(string argsJson)
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("guardrail blocked", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"compact": true, "indent": true}""")]
    [InlineData("""{"table_names": []}""")]
    [InlineData("""{"table_name": "   "}""")]
    [InlineData("""{"table_name": "", "table_names": []}""")]
    public async Task GetTableSchemaTool_RejectsWhenNeitherTableNameNorTableNamesSupplied(string argsJson)
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("Either 'table_name' or 'table_names' parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetTableSchemaTool_RejectsNullArguments()
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);
        var result = await tool.ExecuteAsync(null);

        Assert.True(result.IsError);
        Assert.Contains("Arguments object is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"object_type": "TABLE", "include_row_count": true}""")]
    [InlineData("""{"patterns": []}""")]
    [InlineData("""{"pattern": "   "}""")]
    [InlineData("""{"pattern": "", "patterns": []}""")]
    public async Task SearchObjectsTool_RejectsWhenNeitherPatternNorPatternsSupplied(string argsJson)
    {
        var tool = new SearchObjectsTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("Either 'pattern' or 'patterns' parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SearchObjectsTool_RejectsNullArguments()
    {
        var tool = new SearchObjectsTool(_connectionManager, _validator);
        var result = await tool.ExecuteAsync(null);

        Assert.True(result.IsError);
        Assert.Contains("Arguments object is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("orders", "%orders%")]
    [InlineData("inv_*", "inv_%")]
    [InlineData("*customers*", "%customers%")]
    [InlineData("%orders%", "%orders%")]
    [InlineData("car_%", "car_%")]
    [InlineData("%detail", "%detail")]
    [InlineData("table*name", "table%name")]
    public void SearchObjectsTool_NormalizePattern_CorrectlyHandlesVariousWildcards(string input, string expected)
    {
        var method = typeof(SearchObjectsTool).GetMethod("NormalizePattern", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string? result = method.Invoke(null, new object[] { input }) as string;
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("""{"pattern": "orders, inv_* | car_%"}""")]
    [InlineData("""{"patterns": ["orders", "inv_*", "%car%"]}""")]
    [InlineData("""{"pattern": "orders, items", "patterns": ["inv_*"]}""")]
    public async Task SearchObjectsTool_NormalizesAndValidatesPatterns_ProceedsPastValidation(string argsJson)
    {
        var tool = new SearchObjectsTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        // Pattern validation succeeded: it did NOT fail with "Either 'pattern' or 'patterns' parameter is required."
        // Since there is no active DB server, it fails at the connection step, proving patterns were parsed and accepted.
        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error searching database objects", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
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
        Assert.Contains("read-only", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }
}
