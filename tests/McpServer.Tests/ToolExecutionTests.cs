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

    [Fact]
    public void GetDatabaseSummaryTool_Definition_HasExpectedProperties()
    {
        var tool = new GetDatabaseSummaryTool(_connectionManager, _validator);

        Assert.Equal("get_database_summary", tool.Definition.Name);
        Assert.Contains("executive summary", tool.Definition.Description, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(tool.Definition.InputSchema);
    }

    [Theory]
    [InlineData("main_orders", "main")]
    [InlineData("MAIN_CUSTOMERS", "main")]
    [InlineData("car_recibos_nc", "car")]
    [InlineData("CAR_PAGOS", "car")]
    [InlineData("gen_articulos", "gen")]
    [InlineData("tes_egresos", "tes")]
    [InlineData("base_empresas", "base")]
    [InlineData("Clientes", "general")]
    [InlineData("usuarios", "general")]
    [InlineData("_temp_table", "general")]
    [InlineData("", "general")]
    [InlineData(null, "general")]
    public void GetDatabaseSummaryTool_ExtractModulePrefix_CorrectlyGroupsTables(string? tableName, string expectedModule)
    {
        string result = GetDatabaseSummaryTool.ExtractModulePrefix(tableName!);
        Assert.Equal(expectedModule, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{}")]
    [InlineData("""{"include_empty_tables": false, "indent": true}""")]
    [InlineData("""{"profile": "dev", "database": "DB_Test_Dev"}""")]
    public async Task GetDatabaseSummaryTool_AcceptsValidOrNullArguments_AttemptsConnection(string? argsJson)
    {
        var tool = new GetDatabaseSummaryTool(_connectionManager, _validator);

        JsonElement? args = null;
        JsonDocument? doc = null;
        if (argsJson != null)
        {
            doc = JsonDocument.Parse(argsJson);
            args = doc.RootElement;
        }

        try
        {
            var result = await tool.ExecuteAsync(args);

            // Since there is no live SQL server running at localhost, it should fail at the connection level,
            // returning a handled McpToolCallResult error without throwing an uncaught exception.
            Assert.True(result.IsError);
            Assert.Contains("Error generating database summary", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            doc?.Dispose();
        }
    }

    [Theory]
    [InlineData("P", "PROCEDURE")]
    [InlineData("PC", "PROCEDURE")]
    [InlineData("proc", "PROCEDURE")]
    [InlineData("PROCEDURE", "PROCEDURE")]
    [InlineData("procedures", "PROCEDURE")]
    [InlineData("U", "TABLE")]
    [InlineData("t", "TABLE")]
    [InlineData("TABLE", "TABLE")]
    [InlineData("tables", "TABLE")]
    [InlineData("v", "VIEW")]
    [InlineData("view", "VIEW")]
    [InlineData("views", "VIEW")]
    [InlineData("FN", "FUNCTION")]
    [InlineData("if", "FUNCTION")]
    [InlineData("tf", "FUNCTION")]
    [InlineData("FUNC", "FUNCTION")]
    [InlineData("function", "FUNCTION")]
    [InlineData("functions", "FUNCTION")]
    [InlineData("ALL", "ALL")]
    [InlineData("*", "ALL")]
    public void SearchObjectsTool_NormalizeObjectType_CorrectlyMapsToCanonical(string input, string expected)
    {
        var method = typeof(SearchObjectsTool).GetMethod("NormalizeObjectType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        string? result = method.Invoke(null, new object[] { input }) as string;
        Assert.Equal(expected, result);
    }

    [Fact]
    public void SearchObjectsTool_BuildTypeClause_GeneratesCorrectSqlConditions()
    {
        var method = typeof(SearchObjectsTool).GetMethod("BuildTypeClause", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        // Single type: PROCEDURE
        string? sqlProc = method.Invoke(null, new object[] { new[] { "PROCEDURE" } }) as string;
        Assert.Equal("(o.type IN ('P', 'PC'))", sqlProc);

        // Single type: TABLE
        string? sqlTable = method.Invoke(null, new object[] { new[] { "TABLE" } }) as string;
        Assert.Equal("(o.type = 'U')", sqlTable);

        // Single type: VIEW
        string? sqlView = method.Invoke(null, new object[] { new[] { "VIEW" } }) as string;
        Assert.Equal("(o.type = 'V')", sqlView);

        // Single type: FUNCTION
        string? sqlFunc = method.Invoke(null, new object[] { new[] { "FUNCTION" } }) as string;
        Assert.Equal("(o.type IN ('FN', 'IF', 'TF'))", sqlFunc);

        // Multiple types: PROCEDURE and TABLE
        string? sqlMulti = method.Invoke(null, new object[] { new[] { "PROCEDURE", "TABLE" } }) as string;
        Assert.Contains("o.type IN ('P', 'PC')", sqlMulti);
        Assert.Contains("o.type = 'U'", sqlMulti);
        Assert.Contains(" OR ", sqlMulti);

        // ALL or empty: no type filter
        string? sqlAll = method.Invoke(null, new object[] { new[] { "ALL" } }) as string;
        Assert.Equal("1 = 1", sqlAll);

        string? sqlEmpty = method.Invoke(null, new object[] { Array.Empty<string>() }) as string;
        Assert.Equal("1 = 1", sqlEmpty);
    }

    [Theory]
    [InlineData("""{"pattern": "orders", "object_types": ["P"]}""")]
    [InlineData("""{"pattern": "orders", "types": ["PROCEDURE", "TABLE"]}""")]
    [InlineData("""{"pattern": "orders", "type": "P"}""")]
    [InlineData("""{"pattern": "orders", "object_type": "V"}""")]
    [InlineData("""{"pattern": "orders", "types": "TABLE, PROCEDURE"}""")]
    [InlineData("""{"pattern": "orders", "object_types": ["FN", "TF"]}""")]
    [InlineData("""{"pattern": "orders", "type": "ALL"}""")]
    public async Task SearchObjectsTool_AcceptsObjectTypesAliasesAndArrayFormats(string argsJson)
    {
        var tool = new SearchObjectsTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error searching database objects", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"search": "orders"}""")]
    [InlineData("""{"search": "orders, inv_* | car_%"}""")]
    [InlineData("""{"query": "customers"}""")]
    [InlineData("""{"query": "inv_*, car_*"}""")]
    public async Task SearchObjectsTool_AcceptsSearchAndQueryAliases(string argsJson)
    {
        var tool = new SearchObjectsTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error searching database objects", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetSpDefinitionTool_RejectsWhenParameterMissingOrEmpty()
    {
        var tool = new GetSpDefinitionTool(_connectionManager);

        string[] invalidArgs = { "{}", """{"summary_only": true}""", """{"sp_name": "   "}""", """{"sp_names": []}""" };
        foreach (var argsJson in invalidArgs)
        {
            using var doc = JsonDocument.Parse(argsJson);
            var result = await tool.ExecuteAsync(doc.RootElement);

            Assert.True(result.IsError);
            Assert.Contains("sp_name", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task GetSpDefinitionTool_RejectsNullArguments()
    {
        var tool = new GetSpDefinitionTool(_connectionManager);
        var result = await tool.ExecuteAsync(null);

        Assert.True(result.IsError);
        Assert.Contains("Arguments object is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"procedure_name": "usp_get_customer_orders"}""")]
    [InlineData("""{"procedure": "dbo.usp_calculate_tax"}""")]
    [InlineData("""{"sp": "usp_inventory_audit"}""")]
    [InlineData("""{"name": "dbo.usp_invoices_sync"}""")]
    public async Task GetSpDefinitionTool_AcceptsProcedureNameAliases(string argsJson)
    {
        var tool = new GetSpDefinitionTool(_connectionManager);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error retrieving stored procedure definition", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"sp_names": ["usp_1", "usp_2"], "summary_only": true}""")]
    [InlineData("""{"procedure_names": ["usp_1", "usp_2"], "compact": true}""")]
    [InlineData("""{"procedures": ["usp_1", "usp_2"]}""")]
    [InlineData("""{"names": ["usp_1", "usp_2"], "summary_only": true}""")]
    [InlineData("""{"sp_name": "usp_1, usp_2", "summary_only": true}""")]
    [InlineData("""{"sp_names": ["usp_1"]}""")]
    public async Task GetSpDefinitionTool_AcceptsBatchAndSummaryOnly(string argsJson)
    {
        var tool = new GetSpDefinitionTool(_connectionManager);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error retrieving stored procedure definition", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetSpDefinitionTool_FormatSingleResult_OmitsDefinitionWhenSummaryOnlyIsTrue()
    {
        var sample = new StoredProcedureInfo
        {
            Schema = "dbo",
            Procedure = "usp_test",
            FullName = "dbo.usp_test",
            Created = "2026-01-01 10:00:00",
            Modified = "2026-01-02 10:00:00",
            ParameterCount = 1,
            Parameters = new List<object>(),
            Dependencies = null,
            Definition = "CREATE PROCEDURE dbo.usp_test AS SELECT 1;"
        };

        // summaryOnly = false -> includes definition
        object fullResult = GetSpDefinitionTool.FormatSingleResult("TestDB", sample, false);
        string fullJson = JsonSerializer.Serialize(fullResult);
        using (var doc = JsonDocument.Parse(fullJson))
        {
            Assert.True(doc.RootElement.TryGetProperty("definition", out var defProp));
            Assert.Equal("CREATE PROCEDURE dbo.usp_test AS SELECT 1;", defProp.GetString());
            Assert.Equal("TestDB", doc.RootElement.GetProperty("database").GetString());
            Assert.Equal("dbo.usp_test", doc.RootElement.GetProperty("fullName").GetString());
        }

        // summaryOnly = true -> omits definition
        object summaryResult = GetSpDefinitionTool.FormatSingleResult("TestDB", sample, true);
        string summaryJson = JsonSerializer.Serialize(summaryResult);
        using (var doc = JsonDocument.Parse(summaryJson))
        {
            Assert.False(doc.RootElement.TryGetProperty("definition", out _));
            Assert.Equal("TestDB", doc.RootElement.GetProperty("database").GetString());
            Assert.Equal("dbo.usp_test", doc.RootElement.GetProperty("fullName").GetString());
            Assert.Equal(1, doc.RootElement.GetProperty("parameterCount").GetInt32());
        }
    }

    [Theory]
    [InlineData("""{"table": "dbo.User_Passwords"}""")]
    [InlineData("""{"name": "dbo.User_Passwords"}""")]
    [InlineData("""{"tables": ["dbo.User_Passwords", "dbo.Clientes"]}""")]
    [InlineData("""{"names": ["dbo.User_Passwords"]}""")]
    [InlineData("""{"table": "dbo.Clientes, dbo.User_Passwords"}""")]
    public async Task GetTableSchemaTool_RejectsDeniedTables_WithAliases(string argsJson)
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("guardrail blocked", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("""{"table": "dbo.Orders"}""")]
    [InlineData("""{"name": "dbo.Clientes"}""")]
    [InlineData("""{"tables": ["dbo.Orders", "dbo.Clientes"]}""")]
    [InlineData("""{"names": ["dbo.Invoices"]}""")]
    [InlineData("""{"tables": ["dbo.Orders"]}""")]
    public async Task GetTableSchemaTool_AcceptsTableAliases_ProceedsPastValidation(string argsJson)
    {
        var tool = new GetTableSchemaTool(_connectionManager, _validator);

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.DoesNotContain("parameter is required", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Error retrieving table schema", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }
}
