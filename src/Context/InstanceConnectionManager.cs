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
    /// Opens and returns a new SqlConnection for the specified or active context with automatic transient retry resilience.
    /// </summary>
    public async Task<SqlConnection> OpenConnectionAsync(
        string? profileName,
        string? requestedDatabase,
        CancellationToken cancellationToken = default)
    {
        string connectionString = BuildConnectionString(profileName, requestedDatabase, out _, out _, out _);

        const int maxAttempts = 2;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var connection = new SqlConnection(connectionString);
            try
            {
                await connection.OpenAsync(cancellationToken);
                return connection;
            }
            catch (SqlException ex) when (attempt < maxAttempts && IsTransient(ex))
            {
                await connection.DisposeAsync();
                SqlConnection.ClearPool(connection);
                await Task.Delay(500, cancellationToken);
            }
            catch
            {
                await connection.DisposeAsync();
                throw;
            }
        }

        var fallbackConnection = new SqlConnection(connectionString);
        await fallbackConnection.OpenAsync(cancellationToken);
        return fallbackConnection;
    }

    private static bool IsTransient(SqlException ex)
    {
        foreach (SqlError error in ex.Errors)
        {
            switch (error.Number)
            {
                case -2:
                case -1:
                case 2:
                case 53:
                case 121:
                case 233:
                case 10053:
                case 10054:
                case 10060:
                case 4060:
                case 40143:
                case 40197:
                case 40501:
                case 40613:
                case 49918:
                case 49919:
                case 49920:
                    return true;
            }
        }
        return false;
    }
}
