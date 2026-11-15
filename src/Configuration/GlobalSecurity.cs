using System.Collections.Generic;

namespace MssqlMcpServer.Configuration;

/// <summary>
/// Global security policies and guardrails enforced across all profiles.
/// </summary>
public class GlobalSecurity
{
    /// <summary>
    /// Databases that are globally prohibited from access (e.g. system databases).
    /// </summary>
    public List<string> DeniedDatabases { get; set; } = new()
    {
        "master",
        "msdb",
        "tempdb",
        "model"
    };

    /// <summary>
    /// Tables or patterns that are prohibited from schema inspection or queries (e.g. credentials, tokens).
    /// </summary>
    public List<string> DeniedTables { get; set; } = new()
    {
        "*Password*",
        "*Token*",
        "*Secret*",
        "*Session*",
        "*Credential*"
    };

    /// <summary>
    /// Columns or patterns that should be masked or restricted.
    /// </summary>
    public List<string> DeniedColumns { get; set; } = new()
    {
        "*Password*",
        "*Token*",
        "*Secret*",
        "*Hash*",
        "*Salt*"
    };

    /// <summary>
    /// Maximum rows allowed to be returned by any query.
    /// </summary>
    public int MaxRowsLimit { get; set; } = 500;

    /// <summary>
    /// Default query execution timeout in seconds.
    /// </summary>
    public int DefaultTimeoutSeconds { get; set; } = 30;
}
