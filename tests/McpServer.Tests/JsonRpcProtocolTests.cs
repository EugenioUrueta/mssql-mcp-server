using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Diagnostics;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Security;
using MssqlMcpServer.Server;
using MssqlMcpServer.Tools;
using Xunit;

namespace McpServer.Tests;

public class JsonRpcProtocolTests
{
    private readonly McpServerHost _host;
    private readonly InstanceSettings _settings;
    private readonly SessionContext _sessionContext;

    public JsonRpcProtocolTests()
    {
        _settings = new InstanceSettings
        {
            DefaultProfile = "test-profile",
            Profiles =
            {
                ["test-profile"] = new ProfileConfig
                {
                    Description = "Unit test profile",
                    DefaultDatabase = "DB_Test",
                    AllowedDatabases = { "DB_*" },
                    ConnectionString = "Server=localhost;Database=DB_Test;Integrated Security=true;"
                }
            }
        };

        var security = new GlobalSecurity();
        var validator = new GuardrailsValidator(security);
        _sessionContext = new SessionContext(_settings);
        var connectionManager = new InstanceConnectionManager(_settings, _sessionContext, validator);
        var auditLogger = new AuditLogger(Path.Combine(Path.GetTempPath(), "audit_test.jsonl"));

        var tools = new IMcpToolHandler[]
        {
            new ListProfilesAndDatabasesTool(_settings, _sessionContext),
            new SwitchContextTool(_sessionContext, connectionManager)
        };

        var registry = new ToolRegistry(tools);
        _host = new McpServerHost(registry, _sessionContext, auditLogger, TextReader.Null, TextWriter.Null, TextWriter.Null);
    }

    [Fact]
    public async Task ProcessMessage_Initialize_ReturnsMcpCapabilitiesAndServerInfo()
    {
        string initRequest = """
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0" }
            }
        }
        """;

        string? responseJson = await _host.ProcessMessageAsync(initRequest);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;

        Assert.Equal("2.0", root.GetProperty("jsonrpc").GetString());
        Assert.Equal(1, root.GetProperty("id").GetInt32());

        var result = root.GetProperty("result");
        Assert.Equal("2024-11-05", result.GetProperty("protocolVersion").GetString());

        var serverInfo = result.GetProperty("serverInfo");
        Assert.Equal("mssql-mcp-server", serverInfo.GetProperty("name").GetString());
        Assert.Equal("1.0.0", serverInfo.GetProperty("version").GetString());
    }

    [Fact]
    public async Task ProcessMessage_Notification_ReturnsNullNoResponse()
    {
        string notif = """
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        """;

        string? responseJson = await _host.ProcessMessageAsync(notif);
        Assert.Null(responseJson);
    }

    [Fact]
    public async Task ProcessMessage_Ping_ReturnsEmptyResult()
    {
        string pingReq = """
        {
            "jsonrpc": "2.0",
            "id": "ping-42",
            "method": "ping"
        }
        """;

        string? responseJson = await _host.ProcessMessageAsync(pingReq);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var root = doc.RootElement;

        Assert.Equal("ping-42", root.GetProperty("id").GetString());
        Assert.True(root.TryGetProperty("result", out _));
    }

    [Fact]
    public async Task ProcessMessage_ToolsList_ReturnsRegisteredTools()
    {
        string toolsListReq = """
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list"
        }
        """;

        string? responseJson = await _host.ProcessMessageAsync(toolsListReq);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var tools = doc.RootElement.GetProperty("result").GetProperty("tools");

        Assert.True(tools.GetArrayLength() >= 2);
    }

    [Fact]
    public async Task ProcessMessage_UnknownMethod_ReturnsMethodNotFound()
    {
        string req = """
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "unknown/method"
        }
        """;

        string? responseJson = await _host.ProcessMessageAsync(req);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var err = doc.RootElement.GetProperty("error");

        Assert.Equal(JsonRpcErrorCodes.MethodNotFound, err.GetProperty("code").GetInt32());
    }

    [Fact]
    public async Task ProcessMessage_InvalidJson_ReturnsParseError()
    {
        string malformed = "NOT_VALID_JSON{{{";

        string? responseJson = await _host.ProcessMessageAsync(malformed);
        Assert.NotNull(responseJson);

        using var doc = JsonDocument.Parse(responseJson);
        var err = doc.RootElement.GetProperty("error");

        Assert.Equal(JsonRpcErrorCodes.ParseError, err.GetProperty("code").GetInt32());
    }
}
