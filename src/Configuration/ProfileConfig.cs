using System.Collections.Generic;

namespace MssqlMcpServer.Configuration;

/// <summary>
/// Configuration settings for an individual database profile.
/// </summary>
public class ProfileConfig
{
    /// <summary>
    /// Connection string to the SQL Server instance.
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Default database to connect to when no database is specified.
    /// </summary>
    public string DefaultDatabase { get; set; } = string.Empty;

    /// <summary>
    /// List of allowed databases or wildcard patterns (e.g., "DB_*", "*").
    /// </summary>
    public List<string> AllowedDatabases { get; set; } = new() { "*" };

    /// <summary>
    /// If true, prevents any modifications and disallows stored procedure executions that could alter data.
    /// </summary>
    public bool IsReadOnly { get; set; } = false;

    /// <summary>
    /// Whether stored procedure execution is permitted.
    /// </summary>
    public bool AllowExecuteSp { get; set; } = true;

    /// <summary>
    /// Whether simulated execution (transaction rollback) is allowed.
    /// </summary>
    public bool AllowSimulation { get; set; } = true;

    /// <summary>
    /// Human-readable description of this profile.
    /// </summary>
    public string Description { get; set; } = string.Empty;
}
