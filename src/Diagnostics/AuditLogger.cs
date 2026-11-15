using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MssqlMcpServer.Diagnostics;

/// <summary>
/// Thread-safe audit logger writing execution events to logs/audit.jsonl.
/// </summary>
public class AuditLogger
{
    private readonly string _logFilePath;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    public AuditLogger(string? customLogPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customLogPath))
        {
            _logFilePath = customLogPath;
        }
        else
        {
            string baseDir = AppContext.BaseDirectory;
            string logsDir = Path.Combine(baseDir, "logs");
            _logFilePath = Path.Combine(logsDir, "audit.jsonl");
        }

        try
        {
            string? dir = Path.GetDirectoryName(_logFilePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Warning] Could not ensure logs directory: {ex.Message}");
        }
    }

    /// <summary>
    /// Asynchronously logs an audit entry to the JSONL file.
    /// </summary>
    public async Task LogAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        try
        {
            // Mask parameters if needed
            entry.Parameters = SanitizeParameters(entry.Parameters);

            string line = JsonSerializer.Serialize(entry, JsonOptions);

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                await File.AppendAllTextAsync(_logFilePath, line + Environment.NewLine, cancellationToken);
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Error] Failed to write audit log: {ex.Message}");
        }
    }

    private static object? SanitizeParameters(object? parameters)
    {
        if (parameters == null) return null;

        if (parameters is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var dict = new Dictionary<string, object?>();
                foreach (var prop in element.EnumerateObject())
                {
                    if (IsSensitiveKey(prop.Name))
                    {
                        dict[prop.Name] = "***REDACTED***";
                    }
                    else
                    {
                        dict[prop.Name] = prop.Value.Clone();
                    }
                }
                return dict;
            }
            return element;
        }

        if (parameters is IDictionary<string, object?> dictParam)
        {
            var sanitized = new Dictionary<string, object?>();
            foreach (var kvp in dictParam)
            {
                sanitized[kvp.Key] = IsSensitiveKey(kvp.Key) ? "***REDACTED***" : kvp.Value;
            }
            return sanitized;
        }

        return parameters;
    }

    private static bool IsSensitiveKey(string key)
    {
        string lower = key.ToLowerInvariant();
        return lower.Contains("password") ||
               lower.Contains("pwd") ||
               lower.Contains("secret") ||
               lower.Contains("token") ||
               lower.Contains("credential") ||
               lower.Contains("auth");
    }
}
