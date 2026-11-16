using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Context;
using MssqlMcpServer.Diagnostics;
using MssqlMcpServer.Security;
using MssqlMcpServer.Server;
using MssqlMcpServer.Tools;

namespace MssqlMcpServer;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            // Build configuration from appsettings.json and environment variables
            string baseDir = AppContext.BaseDirectory;
            var configBuilder = new ConfigurationBuilder()
                .SetBasePath(baseDir)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
                .AddEnvironmentVariables(prefix: "MSSQL_MCP_")
                .AddEnvironmentVariables();

            IConfiguration configuration = configBuilder.Build();

            var settings = new InstanceSettings();
            var section = configuration.GetSection(InstanceSettings.SectionName);
            if (section.Exists())
            {
                section.Bind(settings);
            }

            // Support shorthand environment variables (e.g. MSSQL_CONNECTION_STRING)
            string? envConnStr = configuration["MSSQL_CONNECTION_STRING"] 
                ?? configuration["MSSQL_MCP_CONNECTION_STRING"]
                ?? configuration["CONNECTION_STRING"];
            string? envDb = configuration["MSSQL_DEFAULT_DATABASE"] 
                ?? configuration["MSSQL_MCP_DEFAULT_DATABASE"]
                ?? configuration["DEFAULT_DATABASE"];

            if (!string.IsNullOrWhiteSpace(envConnStr))
            {
                string targetProfile = string.IsNullOrWhiteSpace(settings.DefaultProfile) ? "local-dev" : settings.DefaultProfile;
                if (!settings.Profiles.TryGetValue(targetProfile, out var profileConfig))
                {
                    profileConfig = new ProfileConfig
                    {
                        Description = "Default profile configured via environment variables",
                        AllowedDatabases = new() { "*" },
                        IsReadOnly = false,
                        AllowExecuteSp = false,
                        AllowSimulation = false
                    };
                    settings.Profiles[targetProfile] = profileConfig;
                    settings.DefaultProfile = targetProfile;
                }
                profileConfig.ConnectionString = envConnStr;
                if (!string.IsNullOrWhiteSpace(envDb))
                {
                    profileConfig.DefaultDatabase = envDb;
                }
            }

            // Ensure security settings are populated with defaults if missing
            settings.Security ??= new GlobalSecurity();
            if (settings.Security.DeniedDatabases.Count == 0)
            {
                settings.Security.DeniedDatabases = new() { "master", "msdb", "tempdb", "model" };
            }
            if (settings.Security.DeniedTables.Count == 0)
            {
                settings.Security.DeniedTables = new() { "*Password*", "*Token*", "*Secret*", "*Session*", "*Credential*", "*Clave*", "*Passw*" };
            }
            if (settings.Security.DeniedColumns.Count == 0)
            {
                settings.Security.DeniedColumns = new()
                {
                    "*Password*",
                    "*Token*",
                    "*Secret*",
                    "*Hash*",
                    "*Salt*",
                    "*Clave*",
                    "*Passw*",
                    "*Contrasen*",
                    "*Pin*",
                    "*Conexion*",
                    "*Connection*",
                    "*ConnectionString*",
                    "*CadenaConexion*"
                };
            }

            // Initialize Core Services
            var validator = new GuardrailsValidator(settings.Security);
            var sessionContext = new SessionContext(settings);
            var connectionManager = new InstanceConnectionManager(settings, sessionContext, validator);
            var auditLogger = new AuditLogger();

            // Register Tools
            var tools = new IMcpToolHandler[]
            {
                new ListProfilesAndDatabasesTool(settings, sessionContext),
                new SwitchContextTool(sessionContext, connectionManager),
                new SearchObjectsTool(connectionManager, validator),
                new GetTableSchemaTool(connectionManager, validator),
                new GetDatabaseSummaryTool(connectionManager, validator),
                new GetSpDefinitionTool(connectionManager, validator),
                new GetProcedureSignaturesTool(connectionManager, validator),
                new ExecuteSpTool(connectionManager, validator),
                new ReadQueryTool(connectionManager, validator, settings.Security)
            };

            var toolRegistry = new ToolRegistry(tools);
            var serverHost = new McpServerHost(toolRegistry, sessionContext, auditLogger);

            await serverHost.RunAsync();
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"[mssql-mcp-server Fatal Error] Server crashed: {ex}");
            return 1;
        }
    }
}
