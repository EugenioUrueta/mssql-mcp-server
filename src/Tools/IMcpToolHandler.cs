using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MssqlMcpServer.Protocol;

namespace MssqlMcpServer.Tools;

/// <summary>
/// Interface implemented by all MCP tool handlers.
/// </summary>
public interface IMcpToolHandler
{
    /// <summary>
    /// Metadata definition describing the tool and its JSON input schema.
    /// </summary>
    McpToolDefinition Definition { get; }

    /// <summary>
    /// Executes the tool with the given JSON arguments.
    /// </summary>
    Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default);
}
