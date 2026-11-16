# AGENTS.md — Protocolo de Desarrollo y Gobernanza del Servidor MSSQL MCP

> **Repositorio:** `tools/mssql-mcp-server`  
> **Stack Tecnológico:** .NET 10 | C# 13 | Microsoft SQL Server | MCP JSON-RPC 2.0 (stdio)  
> **Destinatarios:** Agentes de IA (Antigravity, subagentes) y Desarrolladores de Software.  
> **Última Actualización:** Noviembre 2026  

---

## 1. Regla de Oro: Sanitización Absoluta y Neutralidad de Dominio

> [!CAUTION]
> **PROHIBICIÓN ESTRICTA DE DATOS, NOMBRES Y ESQUEMAS REALES**  
> Este repositorio es una herramienta de infraestructura agnóstica y reutilizable. **Bajo ninguna circunstancia** se permite introducir en el código fuente, comentarios, pruebas unitarias, docstrings, descripciones de herramientas, esquemas JSON o documentación:
> - Nombres de empresas o razones sociales reales.
> - Nombres de bases de datos operativas reales (ej. `BaseUsuarios`, `BaseCICanguroNet`, etc.).
> - Direcciones IP, hosts de redes privadas, puertos internos o VPNs (ej. `192.168.*.*`, nombres de túneles `.ovpn`).
> - Nombres de usuario reales (`useria`, `sa`, etc.), credenciales, tokens, llaves o cadenas de conexión con contraseñas operativas.
> - Prefijos de tablas o procedimientos específicos de sistemas propietarios (ej. `car_*`, `gen_*`, `tes_*`, `zco_*`).

### Convención Obligatoria de Ejemplos Genéricos
Toda documentación, descripción de parámetros, esquema de entrada (`InputSchema`) y prueba unitaria (`[InlineData]`, mocks) **DEBE** utilizar exclusivamente nomenclaturas genéricas estándar de la industria:

* **Bases de datos:** `app_db_dev`, `app_db_staging`, `app_db_prod`, `inventory_db`, `sales_db`.
* **Hosts y Servidores:** `localhost,1433`, `sql-staging.example.internal`, `sql-prod.example.internal`.
* **Módulos y Prefijos:** `auth_*`, `billing_*`, `catalog_*`, `customers_*`, `orders_*`, `sales_*`, `finance_*`.
* **Tablas:** `orders`, `order_items`, `customers`, `catalog_items`, `invoices`, `users`, `audit_logs`.
* **Procedimientos:** `usp_get_customer_orders`, `usp_add_order`, `usp_calculate_tax`, `usp_get_catalog_items`.
* **Usuarios Ficticios:** `sa`, `appuser`, `auditor`, `test_user`.

---

## 2. Visión General del Proyecto

`mssql-mcp-server` es un servidor compatible con la especificación **Model Context Protocol (MCP)** desarrollado en **.NET 10**. Provee capacidades seguras de auditoría, lectura, introspección de esquemas y simulación de procedimientos almacenados para motores Microsoft SQL Server mediante comunicación `stdio` (JSON-RPC 2.0).

### Estructura de Directorios

```text
tools/mssql-mcp-server/
├── MssqlMcpServer.sln           # Solución global .NET 10
├── src/                         # Código fuente del servidor MCP
│   ├── Configuration/           # Settings, perfiles y reglas de seguridad
│   ├── Context/                 # Ciclo de vida de conexiones y sesiones multi-tenant
│   ├── Diagnostics/             # Logger de auditoría local (audit.jsonl)
│   ├── Protocol/                # Modelos y contratos JSON-RPC 2.0 / MCP
│   ├── Security/                # GuardrailsValidator, filtros DDL y regex de enmascaramiento
│   ├── Server/                  # McpServerHost (bucle de transporte stdio)
│   ├── Tools/                   # Implementaciones de IMcpToolHandler
│   ├── Program.cs               # Punto de entrada y cableado de dependencias
│   ├── appsettings.example.json # Plantilla de configuración sanitizada
│   └── mssql-mcp-server.csproj
├── tests/                       # Suite de pruebas automatizadas
│   └── McpServer.Tests/         # Pruebas unitarias xUnit (203+ pruebas)
└── dist/                        # Binarios compilados autónomos (ignorado en git)
```

---

## 3. Matriz de Herramientas Implementadas

| Herramienta | Contrato / Propósito | Parámetros Clave | Guardrails / Seguridad |
| :--- | :--- | :--- | :--- |
| `list_profiles_and_databases` | Lista perfiles configurados y base de datos activa. | Ninguno. | Oculta contraseñas y cadenas de conexión. |
| `switch_context` | Cambia el perfil o catálogo de base de datos en memoria. | `profile`, `database`. | Valida listas blancas de bases de datos por perfil. Auto-detecta `compatibilityLevel`. |
| `search_objects` | Búsqueda multi-patrón de tablas, vistas, SPs y funciones. | `pattern`/`patterns`/`search`/`query`, `object_type`/`types`. | Filtra tablas en listas negras (`DeniedTables`). |
| `get_table_schema` | Introspección detallada o compacta de esquemas de tablas. | `table_name`/`table_names`/aliases, `compact`, `no_cache`. | Caché en memoria (TTL 5m). Bloquea tablas de credenciales. |
| `get_database_summary` | Resumen ejecutivo de la BD agrupado por prefijos de módulo. | `include_empty_tables`, `indent`. | Agrupación modular sin volcado masivo de registros. |
| `get_sp_definition` | Definición T-SQL, parámetros y dependencias de SPs. | `sp_name`/`sp_names`/aliases, `summary_only`/`compact`, `include_dependencies`. | Modo `summary_only` para evitar explosión de tokens. |
| `get_procedure_signatures` | Firmas compactas tipadas de parámetros para SPs. | `pattern`/`patterns`, `sp_names`/aliases, `format`, `include_details`. | Compatible con SQL Server 2008+ (`compatibility_level 100+`) vía XML. |
| `execute_sp` | Ejecución controlada o simulación transaccional (rollback). | `sp_name`, `parameters`, `simulate`. | Bloqueado en perfiles de solo lectura. Modo simulación siempre seguro. |
| `read_query` | Consultas SQL de solo lectura (SELECT). | `query`, `format` ("objects" o "compact"), `indent`. | Bloquea DDL/DML destructivo (`DROP`, `DELETE`, etc.) y enmascara columnas sensibles. |

---

## 4. Políticas de Seguridad y Guardrails (`GuardrailsValidator`)

1. **Prevención de Modificación Destructiva**:
   - `read_query` bloquea mediante análisis léxico y expresiones regulares cualquier sentencia que contenga `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `CREATE`, `GRANT`, `REVOKE`, `EXEC`, o `EXECUTE`.
2. **Enmascaramiento de Datos Sensibles**:
   - Todo resultado de consulta procesado por `read_query` enmascara automáticamente valores de columnas que coincidan con patrones sensibles tanto en inglés como en español (`*Password*`, `*Token*`, `*Secret*`, `*Hash*`, `*Salt*`, `*Clave*`, `*Passw*`, `*Contrasen*`, `*Pin*`). Los valores son reemplazados por `"***RESTRICTED***"`.
3. **Compatibilidad SQL Universal**:
   - Toda introspección que utilice agregación de cadenas debe contemplar bases de datos con `compatibility_level` inferior a 140 (SQL Server 2008 / 2012 / 2014 / 2016), utilizando `FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)')` en lugar de asumir la disponibilidad de `STRING_AGG`.

---

## 5. Protocolo de Desarrollo y Verificación para Agentes

Al realizar modificaciones en el código de `mssql-mcp-server`:

### A. Delegación Multi-Agente
- Toda adición de nuevas herramientas, refactorizaciones modulares o suites de prueba debe ser delegada a **Subagentes Nativos de Antigravity (AGY)** con `Model: 'flash'`.
- El agente orquestador coordina la arquitectura, verifica que no se violen las reglas de sanitización y ejecuta la integración final.

### B. Ciclo de Calidad y Pruebas
Antes de dar por concluida cualquier tarea:
1. **Ejecutar la suite completa de pruebas unitarias**:
   ```bash
   dotnet test MssqlMcpServer.sln
   ```
   *Criterio de Aceptación:* **0 errores, 0 pruebas omitidas** (todas las pruebas deben superarse).
2. **Publicar el binario de producción actualizado**:
   ```bash
   dotnet publish src/mssql-mcp-server.csproj -c Release -o dist
   ```
3. **Auditoría de Sanitización Pre-Commit**:
   Verificar que no existan nombres o datos privados en el código modificado:
   ```bash
   git diff | grep -iE "canguro|cicanguro|baseusuarios|useria|192\.168"
   ```
   *(El resultado debe ser estrictamente vacío).*
4. **Control de Versiones (Git)**:
   - Commits descriptivos en español bajo formato Conventional Commits (`feat: ...`, `fix: ...`, `refactor: ...`, `test: ...`, `chore: ...`).
   - Sin firmas automáticas de IA ni metadatos publicitarios.
