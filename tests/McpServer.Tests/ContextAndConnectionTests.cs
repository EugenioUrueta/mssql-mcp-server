using System;
using System.Collections.Generic;
using System.Security;
using System.Text.Json;
using System.Threading.Tasks;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Security;
using MssqlMcpServer.Tools;
using Xunit;

namespace McpServer.Tests;

public class ContextAndConnectionTests
{
    private readonly InstanceSettings _settings;
    private readonly GuardrailsValidator _validator;

    public ContextAndConnectionTests()
    {
        _settings = new InstanceSettings
        {
            DefaultProfile = "dev",
            Profiles =
            {
                ["dev"] = new ProfileConfig
                {
                    Description = "Development instance",
                    ConnectionString = "Server=localhost;Database=DB_Test_Dev;User Id=sa;Password=secret;",
                    DefaultDatabase = "DB_Test_Dev",
                    AllowedDatabases = new List<string> { "DB_*", "APP_*" },
                    IsReadOnly = false,
                    AllowExecuteSp = true
                },
                ["prod-ro"] = new ProfileConfig
                {
                    Description = "Production read only",
                    ConnectionString = "Server=prod-server;Database=DB_Test_Prod;User Id=ro_user;Password=secret;",
                    DefaultDatabase = "DB_Test_Prod",
                    AllowedDatabases = new List<string> { "DB_Test_Prod" },
                    IsReadOnly = true,
                    AllowExecuteSp = false
                }
            },
            Security = new GlobalSecurity
            {
                DeniedDatabases = new List<string> { "master", "msdb", "tempdb" }
            }
        };

        _validator = new GuardrailsValidator(_settings.Security);
    }

    [Fact]
    public void SessionContext_InitializesWithDefaultProfileAndDatabase()
    {
        var session = new SessionContext(_settings);
        Assert.Equal("dev", session.ActiveProfileName);
        Assert.Equal("DB_Test_Dev", session.ActiveDatabaseName);
    }

    [Fact]
    public void InstanceConnectionManager_BuildConnectionString_ReplacesInitialCatalogCorrectly()
    {
        var session = new SessionContext(_settings);
        var manager = new InstanceConnectionManager(_settings, session, _validator);

        string cs = manager.BuildConnectionString("dev", "DB_Test_Branch2", out var effProfile, out var effDb, out var cfg);

        Assert.Equal("dev", effProfile);
        Assert.Equal("DB_Test_Branch2", effDb);
        Assert.Contains("Initial Catalog=DB_Test_Branch2", cs);
        Assert.False(cfg.IsReadOnly);
    }

    [Fact]
    public void InstanceConnectionManager_BuildConnectionString_RejectsDeniedDatabase()
    {
        var session = new SessionContext(_settings);
        var manager = new InstanceConnectionManager(_settings, session, _validator);

        Assert.Throws<SecurityException>(() =>
        {
            manager.BuildConnectionString("dev", "master", out _, out _, out _);
        });
    }

    [Fact]
    public void InstanceConnectionManager_BuildConnectionString_RejectsDatabaseNotMatchingAllowedDatabases()
    {
        var session = new SessionContext(_settings);
        var manager = new InstanceConnectionManager(_settings, session, _validator);

        Assert.Throws<SecurityException>(() =>
        {
            manager.BuildConnectionString("dev", "OtherAppDb", out _, out _, out _);
        });
    }

    [Fact]
    public async Task SwitchContextTool_UpdatesSessionSuccessfully()
    {
        var session = new SessionContext(_settings);
        var manager = new InstanceConnectionManager(_settings, session, _validator);
        var tool = new SwitchContextTool(session, manager);

        string argsJson = """
        {
            "profile": "prod-ro",
            "database": "DB_Test_Prod"
        }
        """;

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.False(result.IsError);
        Assert.Equal("prod-ro", session.ActiveProfileName);
        Assert.Equal("DB_Test_Prod", session.ActiveDatabaseName);
    }

    [Fact]
    public async Task SwitchContextTool_ReturnsError_WhenProfileNotFound()
    {
        var session = new SessionContext(_settings);
        var manager = new InstanceConnectionManager(_settings, session, _validator);
        var tool = new SwitchContextTool(session, manager);

        string argsJson = """
        {
            "profile": "non_existent_profile"
        }
        """;

        using var doc = JsonDocument.Parse(argsJson);
        var result = await tool.ExecuteAsync(doc.RootElement);

        Assert.True(result.IsError);
        Assert.Contains("not found", result.Content[0].Text, StringComparison.OrdinalIgnoreCase);
    }
}
