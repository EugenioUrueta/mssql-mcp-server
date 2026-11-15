using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MssqlMcpServer.Protocol;

namespace MssqlMcpServer.Tools;

/// <summary>
/// Registry managing all available MCP tools and dispatching requests.
/// </summary>
public class ToolRegistry
{
    private readonly Dictionary<string, IMcpToolHandler> _tools = new(StringComparer.OrdinalIgnoreCase);

    public ToolRegistry(IEnumerable<IMcpToolHandler> tools)
    {
        ArgumentNullException.ThrowIfNull(tools);
        foreach (var tool in tools)
        {
            _tools[tool.Definition.Name] = tool;
        }
    }

    /// <summary>
    /// Gets the list of all registered tool definitions.
    /// </summary>
    public McpToolsListResult GetToolsList()
    {
        return new McpToolsListResult
        {
            Tools = _tools.Values.Select(t => t.Definition).ToList()
        };
    }

    /// <summary>
    /// Checks if a tool with the specified name exists.
    /// </summary>
    public bool ContainsTool(string toolName) => _tools.ContainsKey(toolName);

    /// <summary>
    /// Executes a registered tool by name.
    /// </summary>
    public async Task<McpToolCallResult> ExecuteToolAsync(
        string toolName,
        JsonElement? arguments,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return McpToolCallResult.Error("Tool name cannot be empty.");
        }

        if (!_tools.TryGetValue(toolName, out var handler))
        {
            return McpToolCallResult.Error($"Unknown tool '{toolName}'.");
        }

        return await handler.ExecuteAsync(arguments, cancellationToken);
    }
}
