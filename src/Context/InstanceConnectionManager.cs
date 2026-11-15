using System;
using System.Data;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Security;

namespace MssqlMcpServer.Context;

/// <summary>
/// Resolves and creates SQL Server connections adjusted by profile and database catalog.
/// </summary>
public class InstanceConnectionManager
{
    private readonly InstanceSettings _settings;
    private readonly SessionContext _sessionContext;
    private readonly GuardrailsValidator _validator;

    public InstanceConnectionManager(
        InstanceSettings settings,
        SessionContext sessionContext,
        GuardrailsValidator validator)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _sessionContext = sessionContext ?? throw new ArgumentNullException(nameof(sessionContext));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    /// <summary>
    /// Gets the profile configuration by name, or the active profile if name is omitted.
    /// </summary>
    public (string Name, ProfileConfig Config) GetProfile(string? profileName)
    {
        string targetName = string.IsNullOrWhiteSpace(profileName)
            ? _sessionContext.ActiveProfileName
            : profileName.Trim();

        if (string.IsNullOrWhiteSpace(targetName))
        {
            throw new InvalidOperationException("No database profile is currently configured or active.");
        }

        if (!_settings.Profiles.TryGetValue(targetName, out var config))
        {
            throw new ArgumentException($"Profile '{targetName}' was not found in configuration.");
        }

        return (targetName, config);
    }

    /// <summary>
    /// Resolves the effective target database for a profile, validating guardrails.
    /// </summary>
    public string ResolveDatabase(string profileName, ProfileConfig profile, string? requestedDatabase)
    {
        string targetDb;
        if (!string.IsNullOrWhiteSpace(requestedDatabase))
        {
            targetDb = requestedDatabase.Trim();
        }
        else if (string.Equals(profileName, _sessionContext.ActiveProfileName, StringComparison.OrdinalIgnoreCase) &&
                 !string.IsNullOrWhiteSpace(_sessionContext.ActiveDatabaseName))
        {
            targetDb = _sessionContext.ActiveDatabaseName;
        }
        else if (!string.IsNullOrWhiteSpace(profile.DefaultDatabase))
        {
            targetDb = profile.DefaultDatabase;
        }
        else
        {
            // Try extracting from profile's ConnectionString
            var builder = new SqlConnectionStringBuilder(profile.ConnectionString);
            targetDb = builder.InitialCatalog;
        }

        if (string.IsNullOrWhiteSpace(targetDb))
        {
            throw new InvalidOperationException($"No database catalog specified or configured for profile '{profileName}'.");
        }

        // Validate target database against guardrails
        _validator.ValidateDatabase(targetDb, profile);

        return targetDb;
    }

    /// <summary>
    /// Builds a connection string with the dynamically resolved database catalog.
    /// </summary>
    public string BuildConnectionString(string? profileName, string? requestedDatabase, out string effectiveProfile, out string effectiveDatabase, out ProfileConfig profileConfig)
    {
        var (name, config) = GetProfile(profileName);
        effectiveProfile = name;
        profileConfig = config;

        effectiveDatabase = ResolveDatabase(name, config, requestedDatabase);

        var builder = new SqlConnectionStringBuilder(config.ConnectionString)
        {
            InitialCatalog = effectiveDatabase
        };

        return builder.ConnectionString;
    }

    /// <summary>
    /// Opens and returns a new SqlConnection for the specified or active context.
    /// </summary>
    public async Task<SqlConnection> OpenConnectionAsync(
        string? profileName,
        string? requestedDatabase,
        CancellationToken cancellationToken = default)
    {
        string connectionString = BuildConnectionString(profileName, requestedDatabase, out _, out _, out _);
        var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }
}
