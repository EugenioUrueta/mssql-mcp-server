namespace MssqlMcpServer.Security;

/// <summary>
/// Result of evaluating SQL query safety.
/// </summary>
public record QuerySafetyResult(bool IsSafe, string? ErrorMessage = null)
{
    public static QuerySafetyResult Safe() => new(true);
    public static QuerySafetyResult Unsafe(string reason) => new(false, reason);
}
