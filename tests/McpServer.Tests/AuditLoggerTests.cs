using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using MssqlMcpServer.Diagnostics;
using Xunit;

namespace McpServer.Tests;

public class AuditLoggerTests : IDisposable
{
    private readonly string _tempFile;

    public AuditLoggerTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"audit_test_{Guid.NewGuid():N}.jsonl");
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempFile))
            {
                File.Delete(_tempFile);
            }
        }
        catch { }
    }

    [Fact]
    public async Task AuditLogger_WritesRecordAndRedactsSensitiveParameters()
    {
        var logger = new AuditLogger(_tempFile);

        string rawParams = """
        {
            "user_id": 101,
            "password": "SuperSecretPassword123!",
            "api_token": "token-xyz-abc",
            "normal_field": "visible_data"
        }
        """;

        using var doc = JsonDocument.Parse(rawParams);

        var entry = new AuditEntry
        {
            Tool = "execute_sp",
            Profile = "test-profile",
            Database = "DB_Test",
            Parameters = doc.RootElement,
            Success = true,
            DurationMs = 45,
            ErrorMessage = null
        };

        await logger.LogAsync(entry);

        Assert.True(File.Exists(_tempFile));
        string[] lines = await File.ReadAllLinesAsync(_tempFile);
        Assert.Single(lines);

        using var resultDoc = JsonDocument.Parse(lines[0]);
        var root = resultDoc.RootElement;

        Assert.Equal("execute_sp", root.GetProperty("tool").GetString());
        Assert.Equal("test-profile", root.GetProperty("profile").GetString());
        Assert.Equal("DB_Test", root.GetProperty("database").GetString());
        Assert.True(root.GetProperty("success").GetBoolean());
        Assert.Equal(45, root.GetProperty("durationMs").GetInt64());

        var paramsObj = root.GetProperty("parameters");
        Assert.Equal("***REDACTED***", paramsObj.GetProperty("password").GetString());
        Assert.Equal("***REDACTED***", paramsObj.GetProperty("api_token").GetString());
        Assert.Equal("visible_data", paramsObj.GetProperty("normal_field").GetString());
        Assert.Equal(101, paramsObj.GetProperty("user_id").GetInt32());
    }
}
