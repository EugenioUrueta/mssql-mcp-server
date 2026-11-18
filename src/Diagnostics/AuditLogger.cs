using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace MssqlMcpServer.Diagnostics;

/// <summary>
/// High-performance, asynchronous audit logger using System.Threading.Channels.
/// Writes execution events to a resiliently resolved audit.jsonl file.
/// </summary>
public class AuditLogger : IAsyncDisposable, IDisposable
{
    private const string FlushSentinelPrefix = "__MCP_AUDIT_FLUSH__:";

    private readonly string _logFilePath;
    private readonly Channel<string> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _consumerTask;
    private readonly ConcurrentDictionary<string, TaskCompletionSource> _pendingFlushes = new();
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    /// <summary>
    /// Gets the resolved absolute path to the audit log file.
    /// </summary>
    public string LogFilePath => _logFilePath;

    public AuditLogger(string? customLogPath = null)
    {
        _logFilePath = ResolveLogFilePath(customLogPath);

        _channel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        _consumerTask = Task.Run(ProcessLogQueueAsync);
    }

    /// <summary>
    /// Asynchronously enqueues an audit entry to be written to the log file.
    /// </summary>
    public async Task LogAsync(AuditEntry entry, CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            // Mask parameters if needed
            entry.Parameters = SanitizeParameters(entry.Parameters);

            string line = JsonSerializer.Serialize(entry, JsonOptions);

            await _channel.Writer.WriteAsync(line, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Error] Failed to queue audit log: {ex.Message}");
        }
    }

    /// <summary>
    /// Deterministically flushes all queued log entries to disk before returning.
    /// </summary>
    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        if (_disposed || _channel.Reader.Completion.IsCompleted)
        {
            return;
        }

        string flushId = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingFlushes[flushId] = tcs;

        try
        {
            await _channel.Writer.WriteAsync(FlushSentinelPrefix + flushId, cancellationToken).ConfigureAwait(false);
            using (cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken)))
            {
                await tcs.Task.ConfigureAwait(false);
            }
        }
        catch (ChannelClosedException)
        {
            _pendingFlushes.TryRemove(flushId, out _);
        }
        finally
        {
            _pendingFlushes.TryRemove(flushId, out _);
        }
    }

    private async Task ProcessLogQueueAsync()
    {
        try
        {
            while (await _channel.Reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                while (_channel.Reader.TryRead(out var item))
                {
                    await ProcessItemAsync(item).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Drain remaining items upon cancellation
            while (_channel.Reader.TryRead(out var item))
            {
                await ProcessItemAsync(item).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Error] Log consumer queue error: {ex.Message}");
        }
    }

    private async Task ProcessItemAsync(string item)
    {
        if (item.StartsWith(FlushSentinelPrefix, StringComparison.Ordinal))
        {
            var flushId = item.Substring(FlushSentinelPrefix.Length);
            if (_pendingFlushes.TryRemove(flushId, out var tcs))
            {
                tcs.TrySetResult();
            }
            return;
        }

        try
        {
            await File.AppendAllTextAsync(_logFilePath, item + Environment.NewLine, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Error] Failed to write audit log to '{_logFilePath}': {ex.Message}");
        }
    }

    private static string ResolveLogFilePath(string? customLogPath)
    {
        // 1. Check customLogPath parameter
        if (!string.IsNullOrWhiteSpace(customLogPath))
        {
            if (TryEnsureDirectory(customLogPath))
            {
                return customLogPath;
            }
        }

        // 2. Check MSSQL_AUDIT_LOG_PATH environment variable
        string? envPath = Environment.GetEnvironmentVariable("MSSQL_AUDIT_LOG_PATH");
        if (!string.IsNullOrWhiteSpace(envPath))
        {
            if (TryEnsureDirectory(envPath))
            {
                return envPath;
            }
        }

        // 3. Try AppContext.BaseDirectory/logs/audit.jsonl
        string baseDir = AppContext.BaseDirectory;
        string defaultPath = Path.Combine(baseDir, "logs", "audit.jsonl");
        if (TryEnsureDirectory(defaultPath))
        {
            return defaultPath;
        }

        // 4. Fallback to Environment.SpecialFolder.UserProfile (~/.mcp/mssql/logs/audit.jsonl)
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            string fallbackPath = Path.Combine(userProfile, ".mcp", "mssql", "logs", "audit.jsonl");
            if (TryEnsureDirectory(fallbackPath))
            {
                return fallbackPath;
            }
        }

        // 5. Ultimate fallback to system temp directory
        string tempPath = Path.Combine(Path.GetTempPath(), "mssql", "logs", "audit.jsonl");
        TryEnsureDirectory(tempPath);
        return tempPath;
    }

    private static bool TryEnsureDirectory(string filePath)
    {
        try
        {
            string? dir = Path.GetDirectoryName(filePath);
            if (string.IsNullOrEmpty(dir))
            {
                return true;
            }

            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            return Directory.Exists(dir);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Warning] Could not ensure directory for '{filePath}': {ex.Message}");
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        _channel.Writer.TryComplete();
        _cts.Cancel();

        try
        {
            await _consumerTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected on cancellation
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[AuditLogger Error] Consumer task shutdown error: {ex.Message}");
        }
        finally
        {
            foreach (var kvp in _pendingFlushes)
            {
                kvp.Value.TrySetResult();
            }
            _pendingFlushes.Clear();
            _cts.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
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
