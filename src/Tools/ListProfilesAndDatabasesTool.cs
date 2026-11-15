using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;

namespace MssqlMcpServer.Tools;

public class ListProfilesAndDatabasesTool : IMcpToolHandler
{
    private readonly InstanceSettings _settings;
    private readonly SessionContext _sessionContext;

    public ListProfilesAndDatabasesTool(InstanceSettings settings, SessionContext sessionContext)
    {
        _settings = settings;
        _sessionContext = sessionContext;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "list_profiles_and_databases",
        Description = "Returns the active profile, active database, and a list of all configured profiles with their permissions and allowed databases.",
        InputSchema = new
        {
            type = "object",
            properties = new { }
        }
    };

    public Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        var profilesList = new List<object>();

        foreach (var (name, config) in _settings.Profiles)
        {
            profilesList.Add(new
            {
                name,
                description = config.Description,
                isReadOnly = config.IsReadOnly,
                allowExecuteSp = config.AllowExecuteSp,
                allowSimulation = config.AllowSimulation,
                defaultDatabase = config.DefaultDatabase,
                allowedDatabases = config.AllowedDatabases
            });
        }

        var result = new
        {
            activeProfile = _sessionContext.ActiveProfileName,
            activeDatabase = _sessionContext.ActiveDatabaseName,
            configuredProfiles = profilesList,
            deniedDatabases = _settings.Security.DeniedDatabases,
            maxRowsLimit = _settings.Security.MaxRowsLimit
        };

        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        return Task.FromResult(McpToolCallResult.Success(json));
    }
}
