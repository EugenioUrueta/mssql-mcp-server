using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace MssqlMcpServer.Protocol;

/// <summary>
/// Server information returned during MCP initialize.
/// </summary>
public class McpServerInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "mssql-mcp-server";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0.0";
}

/// <summary>
/// Server capabilities announced to the MCP client.
/// </summary>
public class McpServerCapabilities
{
    [JsonPropertyName("tools")]
    public Dictionary<string, object> Tools { get; set; } = new()
    {
        ["listChanged"] = false
    };
}

/// <summary>
/// Result returned for the 'initialize' method.
/// </summary>
public class McpInitializeResult
{
    [JsonPropertyName("protocolVersion")]
    public string ProtocolVersion { get; set; } = "2024-11-05";

    [JsonPropertyName("capabilities")]
    public McpServerCapabilities Capabilities { get; set; } = new();

    [JsonPropertyName("serverInfo")]
    public McpServerInfo ServerInfo { get; set; } = new();
}

/// <summary>
/// Definition of a tool exposed by the MCP server.
/// </summary>
public class McpToolDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("inputSchema")]
    public object InputSchema { get; set; } = new();
}

/// <summary>
/// Tools list result.
/// </summary>
public class McpToolsListResult
{
    [JsonPropertyName("tools")]
    public List<McpToolDefinition> Tools { get; set; } = new();
}

/// <summary>
/// Content item within an MCP tool execution result.
/// </summary>
public class McpContent
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "text";

    [JsonPropertyName("text")]
    public string Text { get; set; } = string.Empty;

    public static McpContent TextContent(string text) => new() { Type = "text", Text = text };
}

/// <summary>
/// Tool execution outcome returned to MCP client.
/// </summary>
public class McpToolCallResult
{
    [JsonPropertyName("content")]
    public List<McpContent> Content { get; set; } = new();

    [JsonPropertyName("isError")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IsError { get; set; }

    public static McpToolCallResult Success(string text) => new()
    {
        IsError = false,
        Content = new() { McpContent.TextContent(text) }
    };

    public static McpToolCallResult Error(string errorMessage) => new()
    {
        IsError = true,
        Content = new() { McpContent.TextContent(errorMessage) }
    };
}
