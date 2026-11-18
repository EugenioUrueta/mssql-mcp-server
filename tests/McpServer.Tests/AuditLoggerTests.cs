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
        await logger.FlushAsync();

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

    [Fact]
    public async Task AuditLogger_MultipleConcurrentLogs_FlushesDeterministically()
    {
        await using var logger = new AuditLogger(_tempFile);

        const int entryCount = 25;
        var tasks = new Task[entryCount];

        for (int i = 0; i < entryCount; i++)
        {
            int index = i;
            tasks[i] = Task.Run(async () =>
            {
                using var doc = JsonDocument.Parse($$"""{"iteration": {{index}}, "action": "test_batch"}""");
                var entry = new AuditEntry
                {
                    Tool = "read_query",
                    Profile = "app_profile",
                    Database = "app_db_dev",
                    Parameters = doc.RootElement,
                    Success = true,
                    DurationMs = 10 + index
                };
                await logger.LogAsync(entry);
            });
        }

        await Task.WhenAll(tasks);
        await logger.FlushAsync();

        Assert.True(File.Exists(_tempFile));
        string[] lines = await File.ReadAllLinesAsync(_tempFile);
        Assert.Equal(entryCount, lines.Length);
    }

    [Fact]
    public void AuditLogger_ResolvesCustomPath_WhenProvided()
    {
        string customPath = Path.Combine(Path.GetTempPath(), "custom_mcp_logs", $"custom_audit_{Guid.NewGuid():N}.jsonl");
        try
        {
            using var logger = new AuditLogger(customPath);
            Assert.Equal(customPath, logger.LogFilePath);
        }
        finally
        {
            try
            {
                if (File.Exists(customPath)) File.Delete(customPath);
                string? dir = Path.GetDirectoryName(customPath);
                if (dir != null && Directory.Exists(dir)) Directory.Delete(dir, true);
            }
            catch { }
        }
    }

    [Fact]
    public void AuditLogger_ResolvesEnvironmentVariable_WhenConfigured()
    {
        string envPath = Path.Combine(Path.GetTempPath(), "env_mcp_logs", $"env_audit_{Guid.NewGuid():N}.jsonl");
        string? originalEnv = Environment.GetEnvironmentVariable("MSSQL_AUDIT_LOG_PATH");

        try
        {
            Environment.SetEnvironmentVariable("MSSQL_AUDIT_LOG_PATH", envPath);
            using var logger = new AuditLogger();
            Assert.Equal(envPath, logger.LogFilePath);
        }
        finally
        {
            Environment.SetEnvironmentVariable("MSSQL_AUDIT_LOG_PATH", originalEnv);
            try
            {
                if (File.Exists(envPath)) File.Delete(envPath);
                string? dir = Path.GetDirectoryName(envPath);
                if (dir != null && Directory.Exists(dir)) Directory.Delete(dir, true);
            }
            catch { }
        }
    }

    [Fact]
    public async Task AuditLogger_DisposeAsync_DrainsRemainingEntries()
    {
        string disposePath = Path.Combine(Path.GetTempPath(), $"audit_dispose_{Guid.NewGuid():N}.jsonl");
        try
        {
            var logger = new AuditLogger(disposePath);

            using var doc = JsonDocument.Parse("""{"event": "before_dispose"}""");
            await logger.LogAsync(new AuditEntry
            {
                Tool = "switch_context",
                Profile = "app_profile",
                Database = "app_db_dev",
                Parameters = doc.RootElement,
                Success = true
            });

            await logger.DisposeAsync();

            Assert.True(File.Exists(disposePath));
            string[] lines = await File.ReadAllLinesAsync(disposePath);
            Assert.Single(lines);
            Assert.Contains("before_dispose", lines[0]);
        }
        finally
        {
            try
            {
                if (File.Exists(disposePath)) File.Delete(disposePath);
            }
            catch { }
        }
    }
}
