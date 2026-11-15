# MSSQL MCP Server (.NET 10)

Servidor de **Model Context Protocol (MCP)** de alto rendimiento y seguridad empresarial para **Microsoft SQL Server**, construido en **C# sobre .NET 10** bajo la especificación JSON-RPC 2.0 sobre transporte `stdio` (versión del protocolo `2024-11-05`).

Diseñado específicamente para interactuar de forma segura con sistemas ERP empresariales o bases transaccionales, incorporando guardrails estrictos, soporte multi-perfil, simulación transaccional con rollback automático y auditoría estructurada continua.

---

## 1. Características Principales

- **Protocolo MCP Estándar (JSON-RPC 2.0)**: Comunicación bidireccional sobre `stdin`/`stdout`. Todas las bitácoras y mensajes de diagnóstico se dirigen estrictamente a `stderr` para preservar intacto el canal de datos JSON-RPC.
- **Gestión Multi-Inquilino y Multi-Perfil**: Soporte para múltiples instancias y catálogos (`Profiles`) con conmutación dinámica en tiempo de ejecución (`switch_context`).
- **Guardrails de Seguridad Activos (`GuardrailsValidator`)**:
  - **Bases de datos protegidas**: Bloqueo automático de bases de datos del sistema (`master`, `msdb`, `tempdb`, `model`) o catálogos no autorizados.
  - **Tablas y Columnas protegidas**: Bloqueo y enmascaramiento por patrones comodín (`*Password*`, `*Token*`, `*Secret*`, `*Session*`, `*Hash*`).
  - **Perfil de Sólo Lectura**: Perfiles con `IsReadOnly = true` impiden cualquier mutación o ejecución de procedimientos en vivo.
  - **Validador Sintáctico Estricto para `read_query`**: Permite únicamente consultas `SELECT` o `WITH` (CTE), desarmando comentarios, cadenas y rechazando comandos de modificación (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `EXEC`, `MERGE`, etc.) y sentencias múltiples apiladas (`stacked queries`).
- **Simulación Transaccional (`execute_sp`)**: Modo `simulate: true` que envuelve la ejecución del procedimiento almacenado en una transacción `BEGIN TRANSACTION` y la revierte de manera determinista con `ROLLBACK`, permitiendo auditoría y pruebas sin efectos colaterales.
- **Auditoría Continua (`logs/audit.jsonl`)**: Registro asíncrono y protegido contra concurrencia de todas las llamadas a herramientas, con enmascaramiento automático de credenciales y secretos.

---

## 2. Estructura del Proyecto

```
mssql-mcp-server/
├── MssqlMcpServer.sln         # Solución principal de .NET
├── MssqlMcpServer.slnx        # Formato moderno de solución .NET 10
├── README.md                  # Documentación operativa y manual de integración
├── src/
│   ├── Configuration/         # Modelos de configuración y seguridad
│   │   ├── InstanceSettings.cs
│   │   ├── ProfileConfig.cs
│   │   └── GlobalSecurity.cs
│   ├── Context/               # Estado de sesión y resolución dinámica de conexiones
│   │   ├── SessionContext.cs
│   │   └── InstanceConnectionManager.cs
│   ├── Diagnostics/           # Auditoría JSONL y redacción de datos sensibles
│   │   ├── AuditEntry.cs
│   │   └── AuditLogger.cs
│   ├── Protocol/              # DTOs y serializadores JSON-RPC 2.0 y MCP
│   │   ├── JsonRpcModels.cs
│   │   └── McpModels.cs
│   ├── Security/              # Motor de guardrails, regex y comodines
│   │   ├── GuardrailsValidator.cs
│   │   ├── QuerySafetyResult.cs
│   │   └── WildcardMatcher.cs
│   ├── Server/                # Host stdio y bucle de despacho de mensajes
│   │   └── McpServerHost.cs
│   ├── Tools/                 # Implementación de las 7 herramientas MCP
│   │   ├── IMcpToolHandler.cs
│   │   ├── ToolRegistry.cs
│   │   ├── ListProfilesAndDatabasesTool.cs
│   │   ├── SwitchContextTool.cs
│   │   ├── SearchObjectsTool.cs
│   │   ├── GetTableSchemaTool.cs
│   │   ├── GetSpDefinitionTool.cs
│   │   ├── ExecuteSpTool.cs
│   │   └── ReadQueryTool.cs
│   ├── Program.cs             # Punto de entrada
│   ├── appsettings.json       # Configuración local activa
│   ├── appsettings.example.json
│   └── mssql-mcp-server.csproj
└── tests/
    └── McpServer.Tests/       # Suite exhaustiva de pruebas xUnit
        ├── GuardrailsValidatorTests.cs
        ├── JsonRpcProtocolTests.cs
        ├── ContextAndConnectionTests.cs
        ├── AuditLoggerTests.cs
        ├── ToolExecutionTests.cs
        └── McpServer.Tests.csproj
```

---

## 3. Catálogo de Herramientas MCP

| Herramienta | Parámetros | Descripción |
| :--- | :--- | :--- |
| `list_profiles_and_databases` | *(ninguno)* | Devuelve el perfil activo, base de datos activa, perfiles configurados con sus banderas (`isReadOnly`, `allowExecuteSp`, `allowedDatabases`) y restricciones globales. |
| `switch_context` | `profile` *(opc)*, `database` *(opc)* | Cambia el perfil y/o la base de datos activa para la sesión tras validar los permisos contra guardrails. |
| `search_objects` | `pattern` *(opc)*, `patterns` *(opc)*, `object_type` *(opc: TABLE, VIEW, PROCEDURE, ALL)*, `include_row_count` *(opc, bool)*, `profile`, `database`, `indent` *(opc, bool)* | Busca tablas, vistas o procedimientos almacenados mediante comodines o listas de patrones LIKE (`OR`). Soporta conteo estimado de filas. |
| `get_table_schema` | `table_name` *(opc)*, `table_names` *(opc, array)*, `compact` *(opc, bool)*, `profile`, `database`, `indent` *(opc, bool)* | Obtiene el esquema completo o compacto de una o múltiples tablas en lote: columnas, PKs, FKs e índices. |
| `get_sp_definition` | `sp_name` *(req)*, `profile`, `database` | Retorna el código T-SQL original (`sys.sql_modules`) y los metadatos de los parámetros tipados (`sys.parameters`). |
| `execute_sp` | `sp_name` *(req)*, `parameters` *(opc)*, `simulate` *(opc, default: false)*, `profile`, `database` | Invoca procedimientos almacenados fuertemente tipados. Soporta modo simulación (rollback automático en transacción). |
| `read_query` | `query` *(req)*, `format` *(opc: objects, compact)*, `indent` *(opc, bool)*, `max_rows` *(opc)*, `timeout_seconds` *(opc)*, `profile`, `database` | Ejecuta consultas de lectura (`SELECT` / `WITH CTE`) con límite de filas y tiempo de espera. Soporta formato tabular compacto y serialización plana sin indentar para optimización de tokens. |

---

## 4. Compilación y Ejecución de Pruebas

### Requisitos Previos
- **.NET 10 SDK** (versión 10.0.100 o superior).

### Comandos de Construcción y Verificación

```bash
# Navegar a la raíz del proyecto
cd /path/to/mssql-mcp-server

# Restaurar paquetes NuGet y compilar la solución completa
dotnet build MssqlMcpServer.sln

# Ejecutar la suite completa de pruebas unitarias
dotnet test MssqlMcpServer.sln
```

---

## 5. Configuración de Clientes MCP

### 5.1 Configuración con Binario Autónomo (Recomendado)

El proyecto incluye una compilación autónoma de alto rendimiento en `dist/mssql-mcp-server`. Se ejecuta en milisegundos sin requerir compilación previa:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/mssql-mcp-server/dist/mssql-mcp-server"
    }
  }
}
```

### 5.2 Configuración Ejecutando con `dotnet`

```json
{
  "mcpServers": {
    "mssql": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "/path/to/mssql-mcp-server/src/mssql-mcp-server.csproj",
        "--no-build"
      ]
    }
  }
}
```

---

## 6. Configuración de Variables de Entorno en `mcp_config.json`

Puedes inyectar credenciales o configurar perfiles dinámicamente utilizando el bloque `"env"` de tu `mcp_config.json`.

### Opción 6.1: Sintaxis Rápida (1 Instancia / Conexión Directa)

Ideal si quieres pasar la cadena de conexión de forma directa sin editar `appsettings.json`:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/mssql-mcp-server/dist/mssql-mcp-server",
      "env": {
        "MSSQL_CONNECTION_STRING": "Server=localhost,1433;Database=app_db_dev;User Id=usr_mcp;Password=YourPasswordHere!;TrustServerCertificate=True;Encrypt=Optional;",
        "MSSQL_DEFAULT_DATABASE": "app_db_dev"
      }
    }
  }
}
```

* **`MSSQL_CONNECTION_STRING`**: Sobrescribe inmediatamente la cadena de conexión del perfil activo.
* **`MSSQL_DEFAULT_DATABASE`**: Define el catálogo/base de datos predeterminada al arrancar la sesión.

---

### Opción 6.2: Sintaxis Jerárquica .NET (Multi-Perfil y Guardrails Avanzados)

Para configurar múltiples perfiles (desarrollo, staging, réplica de solo lectura) o ajustar políticas de seguridad, utiliza la convención de doble guion bajo (`__`) de .NET:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/mssql-mcp-server/dist/mssql-mcp-server",
      "env": {
        "MssqlMcpServer__DefaultProfile": "local-dev",
        
        "MssqlMcpServer__Profiles__local-dev__ConnectionString": "Server=localhost,1433;Database=app_db_dev;User Id=sa;Password=YourPasswordHere!;TrustServerCertificate=True;",
        "MssqlMcpServer__Profiles__local-dev__DefaultDatabase": "app_db_dev",
        "MssqlMcpServer__Profiles__local-dev__IsReadOnly": "false",
        "MssqlMcpServer__Profiles__local-dev__AllowExecuteSp": "true",
        "MssqlMcpServer__Profiles__local-dev__AllowSimulation": "true",
        
        "MssqlMcpServer__Profiles__staging__ConnectionString": "Server=sql-staging.example.internal,1433;Database=app_db_staging;User Id=usr_qa;Password=YourStagingPassword!;TrustServerCertificate=True;",
        "MssqlMcpServer__Profiles__staging__DefaultDatabase": "app_db_staging",
        "MssqlMcpServer__Profiles__staging__IsReadOnly": "true",
        "MssqlMcpServer__Profiles__staging__AllowExecuteSp": "false",
        
        "MssqlMcpServer__Security__MaxRowsLimit": "250",
        "MssqlMcpServer__Security__DefaultTimeoutSeconds": "45"
      }
    }
  }
}
```

---

## 7. Configuración por Clientes

### Antigravity / Gemini CLI (`.agents/mcp_config.json`)
Ubica el archivo dentro de la carpeta `.agents/` del proyecto para que solo se cargue cuando abras `agy` en ese directorio:
```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/mssql-mcp-server/dist/mssql-mcp-server",
      "env": {
        "MSSQL_CONNECTION_STRING": "Server=...;Database=...;User Id=...;Password=...;"
      }
    }
  }
}
```

### Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "mssql": {
      "command": "/path/to/mssql-mcp-server/dist/mssql-mcp-server",
      "env": {
        "MSSQL_CONNECTION_STRING": "Server=...;Database=...;User Id=...;Password=...;"
      }
    }
  }
}
```

---

## 8. Bitácora de Auditoría

Cada operación realizada mediante las herramientas MCP queda registrada en formato JSONL en:
`logs/audit.jsonl`

Ejemplo de registro:
```json
{"timestamp":"2026-11-14T01:10:41.1234567Z","tool":"execute_sp","profile":"local-dev","database":"app_db_dev","parameters":{"sp_name":"usp_get_customer_orders","password":"***REDACTED***"},"success":true,"durationMs":12}
```
Todos los campos sensibles (`password`, `token`, `secret`, `credential`, `hash`, etc.) son automáticamente redactados antes de la persistencia en disco.
