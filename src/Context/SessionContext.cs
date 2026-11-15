using System;
using MssqlMcpServer.Configuration;

namespace MssqlMcpServer.Context;

/// <summary>
/// Maintains active session state: current active profile and database.
/// </summary>
public class SessionContext
{
    private readonly object _lock = new();
    private string _activeProfileName;
    private string _activeDatabaseName;

    public SessionContext(InstanceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!string.IsNullOrWhiteSpace(settings.DefaultProfile) &&
            settings.Profiles.TryGetValue(settings.DefaultProfile, out var defaultProfileConfig))
        {
            _activeProfileName = settings.DefaultProfile;
            _activeDatabaseName = defaultProfileConfig.DefaultDatabase ?? string.Empty;
        }
        else if (settings.Profiles.Count > 0)
        {
            var first = settings.Profiles.Keys.GetEnumerator();
            first.MoveNext();
            _activeProfileName = first.Current;
            _activeDatabaseName = settings.Profiles[_activeProfileName].DefaultDatabase ?? string.Empty;
        }
        else
        {
            _activeProfileName = string.Empty;
            _activeDatabaseName = string.Empty;
        }
    }

    public string ActiveProfileName
    {
        get { lock (_lock) return _activeProfileName; }
    }

    public string ActiveDatabaseName
    {
        get { lock (_lock) return _activeDatabaseName; }
    }

    public void SetContext(string profileName, string? databaseName)
    {
        lock (_lock)
        {
            _activeProfileName = profileName;
            if (!string.IsNullOrWhiteSpace(databaseName))
            {
                _activeDatabaseName = databaseName;
            }
        }
    }

    public void SetDatabase(string databaseName)
    {
        lock (_lock)
        {
            if (!string.IsNullOrWhiteSpace(databaseName))
            {
                _activeDatabaseName = databaseName;
            }
        }
    }
}
