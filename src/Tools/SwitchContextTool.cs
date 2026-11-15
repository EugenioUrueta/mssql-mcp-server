using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MssqlMcpServer.Context;
using MssqlMcpServer.Protocol;

namespace MssqlMcpServer.Tools;

public class SwitchContextTool : IMcpToolHandler
{
    private readonly SessionContext _sessionContext;
    private readonly InstanceConnectionManager _connectionManager;

    public SwitchContextTool(SessionContext sessionContext, InstanceConnectionManager connectionManager)
    {
        _sessionContext = sessionContext;
        _connectionManager = connectionManager;
    }

    public McpToolDefinition Definition => new()
    {
        Name = "switch_context",
        Description = "Switches the active database profile and/or active database catalog for the current session.",
        InputSchema = new
        {
            type = "object",
            properties = new
            {
                profile = new
                {
                    type = "string",
                    description = "Name of the configured profile to activate (optional)."
                },
                database = new
                {
                    type = "string",
                    description = "Name of the database catalog to activate (optional)."
                }
            }
        }
    };

    public Task<McpToolCallResult> ExecuteAsync(JsonElement? arguments, CancellationToken cancellationToken = default)
    {
        string? newProfile = null;
        string? newDatabase = null;

        if (arguments.HasValue && arguments.Value.ValueKind == JsonValueKind.Object)
        {
            if (arguments.Value.TryGetProperty("profile", out var pProp) && pProp.ValueKind == JsonValueKind.String)
            {
                newProfile = pProp.GetString();
            }
            if (arguments.Value.TryGetProperty("database", out var dProp) && dProp.ValueKind == JsonValueKind.String)
            {
                newDatabase = dProp.GetString();
            }
        }

        if (string.IsNullOrWhiteSpace(newProfile) && string.IsNullOrWhiteSpace(newDatabase))
        {
            return Task.FromResult(McpToolCallResult.Error("At least one parameter ('profile' or 'database') must be provided to switch context."));
        }

        try
        {
            string targetProfileName = !string.IsNullOrWhiteSpace(newProfile)
                ? newProfile.Trim()
                : _sessionContext.ActiveProfileName;

            var (profileName, profileConfig) = _connectionManager.GetProfile(targetProfileName);

            string targetDb = _connectionManager.ResolveDatabase(profileName, profileConfig, newDatabase);

            _sessionContext.SetContext(profileName, targetDb);

            var responseObj = new
            {
                message = "Session context updated successfully.",
                activeProfile = _sessionContext.ActiveProfileName,
                activeDatabase = _sessionContext.ActiveDatabaseName,
                isReadOnly = profileConfig.IsReadOnly,
                allowExecuteSp = profileConfig.AllowExecuteSp
            };

            string json = JsonSerializer.Serialize(responseObj, new JsonSerializerOptions { WriteIndented = true });
            return Task.FromResult(McpToolCallResult.Success(json));
        }
        catch (Exception ex)
        {
            return Task.FromResult(McpToolCallResult.Error($"Failed to switch context: {ex.Message}"));
        }
    }
}
