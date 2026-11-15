using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MssqlMcpServer.Security;

/// <summary>
/// Utility for wildcard pattern matching (* and ?).
/// </summary>
public static class WildcardMatcher
{
    /// <summary>
    /// Checks if the input matches the specified wildcard pattern.
    /// </summary>
    public static bool IsMatch(string input, string pattern)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        if (string.IsNullOrEmpty(pattern))
            return false;

        if (pattern == "*")
            return true;

        string regexPattern = "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";

        return Regex.IsMatch(input, regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Checks if the input matches any of the patterns in the collection.
    /// </summary>
    public static bool MatchesAny(string input, IEnumerable<string> patterns)
    {
        if (string.IsNullOrEmpty(input) || patterns == null)
            return false;

        foreach (var pattern in patterns)
        {
            if (IsMatch(input, pattern))
                return true;
        }

        return false;
    }
}
