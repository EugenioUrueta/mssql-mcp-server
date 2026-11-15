using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MssqlMcpServer.Context;
using MssqlMcpServer.Diagnostics;
using MssqlMcpServer.Protocol;
using MssqlMcpServer.Tools;

namespace MssqlMcpServer.Server;

/// <summary>
/// MCP server host communicating via JSON-RPC 2.0 over standard I/O streams.
/// Standard input/output are reserved strictly for protocol messages; all diagnostics go to stderr.
/// </summary>
public class McpServerHost
{
    private readonly ToolRegistry _toolRegistry;
    private readonly SessionContext _sessionContext;
    private readonly AuditLogger _auditLogger;
    private readonly TextReader _input;
    private readonly TextWriter _output;
    private readonly TextWriter _error;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public McpServerHost(
        ToolRegistry toolRegistry,
        SessionContext sessionContext,
        AuditLogger auditLogger,
        TextReader? input = null,
        TextWriter? output = null,
        TextWriter? error = null)
    {
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _sessionContext = sessionContext ?? throw new ArgumentNullException(nameof(sessionContext));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        _input = input ?? Console.In;
        _output = output ?? Console.Out;
        _error = error ?? Console.Error;
    }

    /// <summary>
    /// Runs the stdio message loop until EOF or cancellation.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        await _error.WriteLineAsync("[mssql-mcp-server] Starting MCP Server listening on stdio (protocolVersion 2024-11-05)...");

        while (!cancellationToken.IsCancellationRequested)
        {
            string? line;
            try
            {
                line = await _input.ReadLineAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                await _error.WriteLineAsync($"[mssql-mcp-server Error] Error reading input: {ex.Message}");
                break;
            }

            if (line == null)
            {
                // End of input stream (EOF)
                await _error.WriteLineAsync("[mssql-mcp-server] Stdio stream closed. Shutting down.");
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            string? responseJson = await ProcessMessageAsync(line, cancellationToken);
            if (!string.IsNullOrEmpty(responseJson))
            {
                await _output.WriteLineAsync(responseJson);
                await _output.FlushAsync(cancellationToken);
            }
        }
    }

    /// <summary>
    /// Processes a single raw JSON-RPC string message and returns the response JSON string (or null if notification).
    /// </summary>
    public async Task<string?> ProcessMessageAsync(string rawMessage, CancellationToken cancellationToken = default)
    {
        JsonRpcRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<JsonRpcRequest>(rawMessage, JsonOptions);
        }
        catch (JsonException ex)
        {
            var errResp = JsonRpcResponse.CreateError(null, JsonRpcErrorCodes.ParseError, $"Parse error: {ex.Message}");
            return JsonSerializer.Serialize(errResp, JsonOptions);
        }

        if (request == null)
        {
            var errResp = JsonRpcResponse.CreateError(null, JsonRpcErrorCodes.InvalidRequest, "Invalid Request.");
            return JsonSerializer.Serialize(errResp, JsonOptions);
        }

        object? rawId = request.Id.HasValue ? ConvertJsonElement(request.Id.Value) : null;

        // If it's a notification without an id
        if (request.IsNotification)
        {
            if (request.Method == "notifications/initialized")
            {
                await _error.WriteLineAsync("[mssql-mcp-server] Client sent notifications/initialized. Handshake complete.");
            }
            return null;
        }

        try
        {
            switch (request.Method)
            {
                case "initialize":
                    var initResult = new McpInitializeResult();
                    return SerializeResponse(JsonRpcResponse.Success(rawId, initResult));

                case "ping":
                    return SerializeResponse(JsonRpcResponse.Success(rawId, new object()));

                case "tools/list":
                    var toolsList = _toolRegistry.GetToolsList();
                    return SerializeResponse(JsonRpcResponse.Success(rawId, toolsList));

                case "tools/call":
                    return await HandleToolCallAsync(rawId, request.Params, cancellationToken);

                default:
                    var notFound = JsonRpcResponse.CreateError(rawId, JsonRpcErrorCodes.MethodNotFound, $"Method '{request.Method}' not found.");
                    return SerializeResponse(notFound);
            }
        }
        catch (Exception ex)
        {
            await _error.WriteLineAsync($"[mssql-mcp-server Error] Unhandled exception processing {request.Method}: {ex}");
            var err = JsonRpcResponse.CreateError(rawId, JsonRpcErrorCodes.InternalError, $"Internal error: {ex.Message}");
            return SerializeResponse(err);
        }
    }

    private async Task<string> HandleToolCallAsync(object? id, JsonElement? @params, CancellationToken cancellationToken)
    {
        if (!@params.HasValue || @params.Value.ValueKind != JsonValueKind.Object)
        {
            var err = JsonRpcResponse.CreateError(id, JsonRpcErrorCodes.InvalidParams, "Invalid 'params' object for tools/call.");
            return SerializeResponse(err);
        }

        if (!@params.Value.TryGetProperty("name", out var nameProp) || string.IsNullOrWhiteSpace(nameProp.GetString()))
        {
            var err = JsonRpcResponse.CreateError(id, JsonRpcErrorCodes.InvalidParams, "Missing required tool 'name' in tools/call.");
            return SerializeResponse(err);
        }

        string toolName = nameProp.GetString()!;
        JsonElement? arguments = null;
        if (@params.Value.TryGetProperty("arguments", out var argsProp) && argsProp.ValueKind == JsonValueKind.Object)
        {
            arguments = argsProp;
        }

        string profile = _sessionContext.ActiveProfileName;
        string database = _sessionContext.ActiveDatabaseName;

        // If arguments override profile/database, capture them for audit
        if (arguments.HasValue)
        {
            if (arguments.Value.TryGetProperty("profile", out var pProp) && !string.IsNullOrWhiteSpace(pProp.GetString()))
                profile = pProp.GetString()!;
            if (arguments.Value.TryGetProperty("database", out var dProp) && !string.IsNullOrWhiteSpace(dProp.GetString()))
                database = dProp.GetString()!;
        }

        var sw = Stopwatch.StartNew();
        McpToolCallResult toolResult;
        string? errorMessage = null;

        try
        {
            toolResult = await _toolRegistry.ExecuteToolAsync(toolName, arguments, cancellationToken);
            if (toolResult.IsError && toolResult.Content.Count > 0)
            {
                errorMessage = toolResult.Content[0].Text;
            }
        }
        catch (Exception ex)
        {
            toolResult = McpToolCallResult.Error($"Unhandled tool execution error: {ex.Message}");
            errorMessage = ex.Message;
        }
        finally
        {
            sw.Stop();
        }

        // Audit the tool invocation
        var auditEntry = new AuditEntry
        {
            Tool = toolName,
            Profile = profile,
            Database = database,
            Parameters = arguments,
            Success = !toolResult.IsError,
            DurationMs = sw.ElapsedMilliseconds,
            ErrorMessage = errorMessage
        };

        // Fire-and-forget / async log
        _ = _auditLogger.LogAsync(auditEntry, CancellationToken.None);

        return SerializeResponse(JsonRpcResponse.Success(id, toolResult));
    }

    private static string SerializeResponse(JsonRpcResponse response)
    {
        return JsonSerializer.Serialize(response, JsonOptions);
    }

    private static object? ConvertJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.TryGetInt64(out long l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => element.GetRawText()
        };
    }
}
