using System;
using System.Collections.Generic;

namespace MssqlMcpServer.Configuration;

/// <summary>
/// Root configuration settings for the MSSQL MCP Server.
/// </summary>
public class InstanceSettings
{
    public const string SectionName = "MssqlMcpServer";

    /// <summary>
    /// Default profile to activate on startup.
    /// </summary>
    public string DefaultProfile { get; set; } = string.Empty;

    /// <summary>
    /// Dictionary of configured database profiles keyed by profile name.
    /// </summary>
    public Dictionary<string, ProfileConfig> Profiles { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Global security rules.
    /// </summary>
    public GlobalSecurity Security { get; set; } = new();
}
