using System;
using System.Collections.Generic;
using System.Security;
using MssqlMcpServer.Configuration;
using MssqlMcpServer.Security;
using Xunit;

namespace McpServer.Tests;

public class GuardrailsValidatorTests
{
    private readonly GlobalSecurity _security;
    private readonly GuardrailsValidator _validator;

    public GuardrailsValidatorTests()
    {
        _security = new GlobalSecurity
        {
            DeniedDatabases = new List<string> { "master", "msdb", "tempdb", "model" },
            DeniedTables = new List<string> { "*Password*", "*Token*", "*Secret*", "*Session*", "*Credential*" },
            DeniedColumns = new List<string> { "*Password*", "*Token*", "*Secret*", "*Hash*", "*Salt*", "*Conexion*", "*Connection*", "*ConnectionString*", "*CadenaConexion*" },
            ProhibitFourPartNames = true
        };
        _validator = new GuardrailsValidator(_security);
    }

    [Theory]
    [InlineData("master")]
    [InlineData("msdb")]
    [InlineData("tempdb")]
    [InlineData("model")]
    [InlineData("[master]")]
    [InlineData("MASTER")]
    public void ValidateDatabase_ShouldThrowSecurityException_ForDeniedDatabases(string dbName)
    {
        var profile = new ProfileConfig
        {
            Description = "Test Profile",
            AllowedDatabases = new List<string> { "*" }
        };

        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateDatabase(dbName, profile));
        Assert.Contains("denied by global security policy", ex.Message);
    }

    [Fact]
    public void ValidateDatabase_ShouldEnforceAllowedDatabases_WithWildcards()
    {
        var profile = new ProfileConfig
        {
            Description = "ERP Dev Profile",
            AllowedDatabases = new List<string> { "DB_*", "APP_*" }
        };

        // Allowed
        _validator.ValidateDatabase("DB_Test_Dev", profile);
        _validator.ValidateDatabase("APP_Prod_Copy", profile);

        // Not allowed
        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateDatabase("OtherEnterpriseDb", profile));
        Assert.Contains("not in the allowed databases list", ex.Message);
    }

    [Theory]
    [InlineData("Usuarios_Password")]
    [InlineData("dbo.AuthToken")]
    [InlineData("[dbo].[Token_Secret]")]
    [InlineData("UserSession")]
    [InlineData("UserCredentials")]
    [InlineData("dbo.ApiTokens")]
    public void ValidateTable_ShouldThrowSecurityException_ForDeniedTables(string tableName)
    {
        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateTable(tableName));
        Assert.Contains("blocked by security guardrails", ex.Message);
    }

    [Theory]
    [InlineData("Clientes")]
    [InlineData("dbo.Articulos")]
    [InlineData("[dbo].[BillingInvoices]")]
    [InlineData("OrderDetails")]
    [InlineData("InvoiceLines")]
    public void ValidateTable_ShouldAllow_SafeTables(string tableName)
    {
        // Should not throw
        _validator.ValidateTable(tableName);
    }

    [Theory]
    [InlineData("PasswordHash", true)]
    [InlineData("UserToken", true)]
    [InlineData("SecretKey", true)]
    [InlineData("PasswordSalt", true)]
    [InlineData("Nombre", false)]
    [InlineData("CodigoArticulo", false)]
    [InlineData("SaldoTotal", false)]
    public void IsColumnDenied_ShouldCorrectlyIdentifyRestrictedColumns(string columnName, bool expected)
    {
        bool result = _validator.IsColumnDenied(columnName);
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateExecutionPermissions_ShouldRejectLiveExecution_WhenReadOnly()
    {
        var readOnlyProfile = new ProfileConfig
        {
            IsReadOnly = true,
            AllowExecuteSp = true,
            AllowSimulation = true
        };

        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateExecutionPermissions(readOnlyProfile, simulate: false));
        Assert.Contains("read-only", ex.Message);

        // Simulation should still be permitted if AllowSimulation is true
        _validator.ValidateExecutionPermissions(readOnlyProfile, simulate: true);
    }

    [Fact]
    public void ValidateExecutionPermissions_ShouldRejectLiveExecution_WhenAllowExecuteSpIsFalse()
    {
        var noSpProfile = new ProfileConfig
        {
            IsReadOnly = false,
            AllowExecuteSp = false,
            AllowSimulation = true
        };

        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateExecutionPermissions(noSpProfile, simulate: false));
        Assert.Contains("disabled", ex.Message);
    }

    [Theory]
    [InlineData("SELECT * FROM dbo.Clientes")]
    [InlineData("SELECT id, nombre, email FROM Articulos WHERE activo = 1")]
    [InlineData("WITH SubTotal AS (SELECT cliente_id, SUM(total) AS total FROM Facturas GROUP BY cliente_id) SELECT * FROM SubTotal")]
    [InlineData("SELECT * FROM Audit WHERE notes = 'User tried to update password'")]
    [InlineData("/* block comment */ SELECT * FROM Clientes -- inline comment")]
    public void ValidateReadQuery_ShouldAccept_SafeReadQueries(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Expected safe query for: {sql}, but got error: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("DROP TABLE Clientes")]
    [InlineData("UPDATE Clientes SET activo = 0")]
    [InlineData("INSERT INTO Clientes (nombre) VALUES ('Test')")]
    [InlineData("DELETE FROM Clientes WHERE id = 1")]
    [InlineData("ALTER TABLE Clientes ADD nueva_col INT")]
    [InlineData("TRUNCATE TABLE Clientes")]
    [InlineData("EXEC dbo.usp_get_items")]
    [InlineData("EXECUTE sp_help")]
    [InlineData("MERGE Clientes AS target USING Source AS src ON target.id = src.id WHEN MATCHED THEN UPDATE SET target.nombre = src.nombre;")]
    [InlineData("GRANT SELECT ON Clientes TO guest")]
    [InlineData("SELECT * INTO BackupClientes FROM Clientes")]
    [InlineData("SELECT 1; DROP TABLE Clientes")]
    [InlineData("SELECT * FROM Clientes; DELETE FROM Pedidos")]
    [InlineData("EXEC xp_cmdshell 'dir'")]
    [InlineData("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=x;', 'SELECT 1')")]
    public void ValidateReadQuery_ShouldReject_DangerousOrModifyingQueries(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected as unsafe.");
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public void ValidateReadQuery_ShouldReject_UnclosedStringLiterals()
    {
        string badSql = "SELECT * FROM Clientes WHERE nombre = 'Unclosed";
        var result = _validator.ValidateReadQuery(badSql);
        Assert.False(result.IsSafe);
        Assert.Contains("unclosed", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateReadQuery_ShouldReject_EmptyOrWhitespaceQuery()
    {
        var result = _validator.ValidateReadQuery("   \n\t  ");
        Assert.False(result.IsSafe);
    }

    [Theory]
    [InlineData("Conexion", true)]
    [InlineData("CadenaConexion", true)]
    [InlineData("ConnectionString", true)]
    [InlineData("DefaultConnection", true)]
    [InlineData("RemoteConnectionString", true)]
    [InlineData("MiConexionSql", true)]
    [InlineData("Customer_Connection_Str", true)]
    [InlineData("Nombre", false)]
    [InlineData("CodigoArticulo", false)]
    [InlineData("SaldoTotal", false)]
    [InlineData("EmailAddress", false)]
    public void IsColumnDenied_ShouldMaskConnectionColumns(string columnName, bool expected)
    {
        bool result = _validator.IsColumnDenied(columnName);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("SELECT * FROM RemoteServer.FinanceDb.dbo.Customers")]
    [InlineData("SELECT * FROM [LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]")]
    [InlineData("SELECT * FROM RemoteServer.FinanceDb..Customers")]
    [InlineData("SELECT * FROM [LINKED_SRV].[RemoteDb]..[RemoteInvoices]")]
    [InlineData("SELECT * FROM RemoteServer...Customers")]
    [InlineData("SELECT * FROM [LINKED_SRV]...[RemoteInvoices]")]
    [InlineData("SELECT * FROM [LINKED_SRV]..[RemoteSchema].[RemoteInvoices]")]
    [InlineData("SELECT * FROM \"RemoteServer\".\"FinanceDb\".\"dbo\".\"Customers\"")]
    [InlineData("SELECT * FROM [LINKED_SRV]  .  [RemoteDb]  .  [dbo]  .  [RemoteInvoices]")]
    [InlineData("SELECT * FROM (SELECT * FROM [LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]) AS SubQuery")]
    [InlineData("SELECT a.Id, b.Name FROM LocalTable a INNER JOIN RemoteServer.FinanceDb.dbo.Customers b ON a.Id = b.Id")]
    [InlineData("SELECT a.Id, b.Name FROM LocalTable a LEFT JOIN [LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices] b ON a.Id = b.Id")]
    [InlineData("WITH CTE AS (SELECT * FROM [LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]) SELECT * FROM CTE")]
    public void ValidateReadQuery_ShouldReject_FourPartObjectIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for four-part identifiers.");
        Assert.Contains("strictly prohibited by security guardrails", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT * FROM Audit WHERE endpoint = 'https://api.example.internal/v1/data'")]
    [InlineData("SELECT * FROM Audit WHERE client_ip = '127.0.0.1'")]
    [InlineData("SELECT * FROM Audit WHERE note = 'Referenced [LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]'")]
    [InlineData("SELECT * FROM Clientes")]
    [InlineData("SELECT * FROM dbo.Clientes")]
    [InlineData("SELECT * FROM [dbo].[Clientes]")]
    [InlineData("SELECT * FROM LocalDatabase.dbo.Clientes")]
    [InlineData("SELECT * FROM [LocalDatabase].[dbo].[Clientes]")]
    [InlineData("SELECT * FROM LocalDatabase..Clientes")]
    [InlineData("SELECT c.Id, c.Nombre, o.Total FROM dbo.Clientes c INNER JOIN dbo.Pedidos o ON c.Id = o.ClienteId")]
    [InlineData("SELECT * FROM Products WHERE Price > 12.34 AND Discount <= 0.5")]
    [InlineData("SELECT t.a, t.b FROM dbo.MyTable t WHERE t.a = 1.0001")]
    public void ValidateReadQuery_ShouldNotHaveFalsePositives_ForUrlsIpsAndLocalIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("RemoteServer.FinanceDb.dbo.Customers")]
    [InlineData("[LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]")]
    [InlineData("RemoteServer.FinanceDb..Customers")]
    [InlineData("[LINKED_SRV].[RemoteDb]..[RemoteInvoices]")]
    [InlineData("RemoteServer...Customers")]
    [InlineData("[LINKED_SRV]...[RemoteInvoices]")]
    [InlineData("[LINKED_SRV]..[RemoteSchema].[RemoteInvoices]")]
    [InlineData("\"RemoteServer\".\"FinanceDb\".\"dbo\".\"Customers\"")]
    public void ValidateNoFourPartIdentifier_ShouldThrow_ForFourPartIdentifiers(string identifier)
    {
        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateNoFourPartIdentifier(identifier, "Object"));
        Assert.Contains("strictly prohibited by security guardrails", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Four-part object identifiers", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Clientes")]
    [InlineData("dbo.Clientes")]
    [InlineData("[dbo].[Clientes]")]
    [InlineData("LocalDb.dbo.Clientes")]
    [InlineData("[LocalDb].[dbo].[Clientes]")]
    [InlineData("LocalDb..Clientes")]
    public void ValidateNoFourPartIdentifier_ShouldAllow_OneTwoThreePartIdentifiers(string identifier)
    {
        // Should not throw
        _validator.ValidateNoFourPartIdentifier(identifier, "Object");
    }

    [Theory]
    [InlineData("RemoteServer.FinanceDb.dbo.Customers")]
    [InlineData("[LINKED_SRV].[RemoteDb].[dbo].[RemoteInvoices]")]
    [InlineData("[LINKED_SRV]...[RemoteInvoices]")]
    public void ValidateTable_ShouldThrow_ForFourPartTableNames(string tableName)
    {
        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateTable(tableName));
        Assert.Contains("Four-part object identifiers", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT [x'].* FROM remote_srv.db.dbo.users AS [x']")]
    [InlineData("SELECT [x'].* FROM [remote_srv].[db].[dbo].[users] AS [x']")]
    [InlineData("SELECT [x'].[id], [x'].[name] FROM remote_srv.remote_db.dbo.orders AS [x']")]
    [InlineData("SELECT [x'].* FROM remote_srv.db..users AS [x']")]
    [InlineData("SELECT [x'].* FROM remote_srv...users AS [x']")]
    [InlineData("SELECT a.[col'] FROM local_table a INNER JOIN remote_srv.db.dbo.users b ON a.id = b.id")]
    [InlineData("SELECT [x'].* FROM [link_srv].[catalog_db].[dbo].[invoices] AS [x']")]
    public void ValidateReadQuery_ShouldReject_FourPartNames_EvenWithApostropheInBracketedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for four-part identifiers.");
        Assert.Contains("strictly prohibited by security guardrails", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT [\"y\"].* FROM remote_srv.db.dbo.users AS [\"y\"]")]
    [InlineData("SELECT \"y\".* FROM remote_srv.db.dbo.users AS \"y\"")]
    [InlineData("SELECT \"x'\".* FROM remote_srv.db.dbo.users AS \"x'\"")]
    [InlineData("SELECT * FROM \"remote_srv\".\"db\".\"dbo\".\"users\" AS [\"y\"]")]
    [InlineData("SELECT * FROM [remote_srv].[db].[dbo].[users] AS \"y\"")]
    public void ValidateReadQuery_ShouldReject_FourPartNames_WithQuotedOrBracketedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for four-part identifiers.");
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT [x'].[id] FROM local_table AS [x']")]
    [InlineData("SELECT [x'].* FROM local_table AS [x']")]
    [InlineData("SELECT [customer's_id], [order's_total] FROM local_table")]
    [InlineData("SELECT [it's_a_column] FROM dbo.orders")]
    [InlineData("SELECT [a'b].[col'c] FROM [local_table] AS [a'b]")]
    [InlineData("SELECT \"col'name\" FROM \"local_table\"")]
    public void ValidateReadQuery_ShouldAllow_SafeQueries_WithApostrophesInDelimitedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("SELECT [foo]]bar] FROM local_table")]
    [InlineData("SELECT [col]]name], [other]]col] FROM dbo.local_table")]
    [InlineData("SELECT [[foo]]bar] FROM local_table")]
    [InlineData("SELECT [[[foo]]bar]]] FROM local_table")]
    [InlineData("SELECT \"foo\"\"bar\" FROM local_table")]
    [InlineData("SELECT [my]]table].[col]]name] FROM [my]]db].[dbo].[my]]table]")]
    public void ValidateReadQuery_ShouldAllow_DelimitedIdentifiers_WithEscapedBracketsOrQuotes(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("SELECT * FROM [remote]]srv].[db].[dbo].[users]")]
    [InlineData("SELECT * FROM \"remote\"\"srv\".\"db\".\"dbo\".\"users\"")]
    [InlineData("SELECT * FROM [remote_srv].[db].[dbo].[[foo]]bar]]]")]
    [InlineData("SELECT [col] FROM [remote]]srv]...[users]")]
    public void ValidateReadQuery_ShouldReject_FourPartNames_WithEscapedBracketsOrQuotes(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for four-part identifiers.");
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT [[foo]]bar]] FROM local_table")]
    [InlineData("SELECT [unclosed_col FROM local_table")]
    [InlineData("SELECT \"unclosed_col FROM local_table")]
    [InlineData("SELECT [escaped]]unclosed FROM local_table")]
    [InlineData("SELECT \"escaped\"\"unclosed FROM local_table")]
    public void ValidateReadQuery_ShouldReject_UnclosedDelimitedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for unclosed identifier.");
        Assert.Contains("unclosed", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("[remote]]srv].[db].[dbo].[users]")]
    [InlineData("\"remote\"\"srv\".\"db\".\"dbo\".\"users\"")]
    [InlineData("[link_srv].[db].[dbo].[[foo]]bar]]]")]
    public void ValidateNoFourPartIdentifier_ShouldThrow_ForFourPartIdentifiers_WithEscapedDelimiters(string identifier)
    {
        var ex = Assert.Throws<SecurityException>(() => _validator.ValidateNoFourPartIdentifier(identifier, "Object"));
        Assert.Contains("Four-part object identifiers", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("[[foo]]bar]]")]
    [InlineData("[foo]]bar]")]
    [InlineData("[[foo]]bar]")]
    [InlineData("\"foo\"\"bar\"")]
    [InlineData("[local]]db].[dbo].[local]]table]")]
    public void ValidateNoFourPartIdentifier_ShouldAllow_SafeIdentifiers_WithEscapedDelimiters(string identifier)
    {
        // Should not throw
        _validator.ValidateNoFourPartIdentifier(identifier, "Object");
    }

    [Theory]
    [InlineData("SELECT [table--name].* FROM [table--name]")]
    [InlineData("SELECT [col--1], [col/*test*/2] FROM local_table")]
    [InlineData("SELECT [table--name].[id] FROM [table--name]")]
    public void ValidateReadQuery_ShouldAllow_DelimitedIdentifiers_WithCommentsInside(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Fact]
    public void ValidateReadQuery_ShouldReject_FourPartName_WithCommentInsideDelimitedIdentifier()
    {
        string sql = "SELECT [table--name].* FROM remote_srv.db.dbo.[table--name]";
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe);
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("/* /* inner */ outer */ SELECT * FROM local_table")]
    [InlineData("SELECT /* /* level 2 */ level 1 */ id FROM local_table")]
    [InlineData("/* /* level 2 /* level 3 */ level 2 */ level 1 */ SELECT * FROM orders")]
    [InlineData("SELECT 1 /* comment /* nested */ */")]
    public void ValidateReadQuery_ShouldAllow_NestedBlockComments(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("/* /* inner */ SELECT * FROM local_table")]
    [InlineData("/* /* level 2 /* level 3 */ level 2 */ SELECT * FROM orders")]
    public void ValidateReadQuery_ShouldReject_UnclosedNestedBlockComments(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for unclosed block comment.");
        Assert.Contains("unclosed", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateReadQuery_ShouldReject_HazardousCommand_EvenIfDisguisedWithNestedComments()
    {
        string sql = "/* /* inner */ outer */ DROP TABLE local_table";
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe);
        Assert.Contains("DROP", result.ErrorMessage);
    }

    [Theory]
    // Delimited identifiers hiding a linked server reference
    [InlineData("SELECT [x'].* FROM LINKED_SRV.app_db_prod.dbo.users AS [x']")]
    [InlineData("SELECT \"x'\".* FROM LINKED_SRV.app_db_prod.dbo.users AS \"x'\"")]
    [InlineData("SELECT [a--b], * FROM LINKED_SRV.app_db_prod.dbo.users")]
    [InlineData("SELECT [a/*b], * FROM LINKED_SRV.app_db_prod.dbo.users AS [c*/d]")]
    // Delimited identifiers hiding stacked statements or hazardous keywords
    [InlineData("SELECT 1 AS [a'];DELETE FROM orders;SELECT 1 AS [b']")]
    [InlineData("SELECT [x'] FROM orders WHERE 1=(SELECT 1 FROM OPENQUERY(LINKED_SRV,'SELECT 1')) AND [y']=1")]
    // Anything after ';'
    [InlineData("SELECT 1;[app_db_prod].[dbo].[usp_add_order]")]
    [InlineData("SELECT 1;'x'")]
    // Unclosed delimited identifiers
    [InlineData("SELECT [abc FROM orders")]
    [InlineData("SELECT \"abc FROM orders")]
    public void ValidateReadQuery_ShouldReject_GuardrailEvasionThroughDelimitedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected.");
    }

    [Theory]
    [InlineData("SELECT [Col]]Name] FROM orders")]
    [InlineData("SELECT \"Col\"\"Name\" FROM orders")]
    [InlineData("SELECT [Delete], [Insert] FROM audit_logs")]
    [InlineData("SELECT [o'brien] FROM customers")]
    [InlineData("SELECT * FROM [app_db_dev].[dbo].[orders]")]
    [InlineData("SELECT * FROM audit_logs WHERE note = 'see [LINKED_SRV].[db].[dbo].[t]'")]
    [InlineData("SELECT * FROM orders;")]
    [InlineData("SELECT * FROM orders; -- done")]
    public void ValidateReadQuery_ShouldAllow_ValidDelimitedIdentifiers(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' was unexpectedly rejected: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("SELECT app_db.dbo.orders.order_id FROM orders")]
    [InlineData("SELECT app_db.dbo.orders.order_id, app_db.dbo.orders.total FROM orders")]
    [InlineData("SELECT app_db.dbo.orders.order_id FROM app_db.dbo.orders")]
    [InlineData("SELECT [app_db].[dbo].[orders].[order_id] FROM [app_db].[dbo].[orders]")]
    [InlineData("SELECT \"app_db\".\"dbo\".\"orders\".\"order_id\" FROM \"app_db\".\"dbo\".\"orders\"")]
    [InlineData("SELECT a.id FROM orders a INNER JOIN customers b ON a.id = app_db.dbo.customers.customer_id")]
    [InlineData("SELECT * FROM orders WHERE app_db.dbo.orders.order_id = 5")]
    [InlineData("SELECT * FROM orders GROUP BY app_db.dbo.orders.customer_id")]
    [InlineData("SELECT * FROM orders ORDER BY app_db.dbo.orders.created_at")]
    [InlineData("SELECT * FROM orders HAVING COUNT(app_db.dbo.orders.order_id) > 1")]
    [InlineData("SELECT (SELECT app_db.dbo.orders.order_id FROM orders) FROM audit_logs")]
    [InlineData("WITH CTE AS (SELECT app_db.dbo.orders.order_id FROM orders) SELECT * FROM CTE")]
    public void ValidateReadQuery_ShouldAllow_FourPartQualifiedColumnsInNonTableContexts(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.True(result.IsSafe, $"Query '{sql}' should have been allowed as 4-part qualified column, but got error: {result.ErrorMessage}");
    }

    [Theory]
    [InlineData("SELECT app_db..orders.order_id FROM orders")]
    [InlineData("SELECT app_db...order_id FROM orders")]
    [InlineData("SELECT [app_db]..[orders].[order_id] FROM orders")]
    [InlineData("SELECT [app_db]...[order_id] FROM orders")]
    [InlineData("SELECT * FROM orders WHERE app_db...order_id = 1")]
    public void ValidateReadQuery_ShouldReject_FourPartIdentifiersWithOmittedPartsEvenInSelectOrExpressions(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected for omitted parts.");
        Assert.Contains("strictly prohibited by security guardrails", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT * FROM remote_srv.app_db.dbo.orders")]
    [InlineData("SELECT * FROM orders o INNER JOIN remote_srv.app_db.dbo.orders_ext e ON o.id = e.id")]
    [InlineData("SELECT * FROM orders o CROSS APPLY remote_srv.app_db.dbo.orders_fn(o.id) f")]
    [InlineData("SELECT * FROM orders o OUTER APPLY remote_srv.app_db.dbo.orders_fn(o.id) f")]
    [InlineData("SELECT * FROM orders, remote_srv.app_db.dbo.customers")]
    [InlineData("SELECT * FROM ((remote_srv.app_db.dbo.customers))")]
    public void ValidateReadQuery_ShouldReject_FourPartNamesInTableSourceContexts(string sql)
    {
        var result = _validator.ValidateReadQuery(sql);
        Assert.False(result.IsSafe, $"Query '{sql}' should have been rejected as a 4-part table source.");
        Assert.Contains("Four-part object identifiers", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WildcardMatcher_PatternCache_ShouldCacheAndMatchAccurately()
    {
        Assert.True(WildcardMatcher.IsMatch("orders_2026", "orders_*"));
        Assert.True(WildcardMatcher.IsMatch("orders_2026", "orders_*")); // cached hit
        Assert.True(WildcardMatcher.IsMatch("item_123", "item_???"));
        Assert.False(WildcardMatcher.IsMatch("item_1234", "item_???"));
        Assert.True(WildcardMatcher.MatchesAny("customer_token", new[] { "*secret*", "*token*" }));
        Assert.False(WildcardMatcher.MatchesAny("customer_name", new[] { "*secret*", "*token*" }));
    }

    [Fact]
    public void GuardrailsValidator_PrecompiledDeniedColumns_ShouldHandleEmptyAndCustomPatterns()
    {
        var emptySecurity = new GlobalSecurity { DeniedColumns = new List<string>() };
        var emptyValidator = new GuardrailsValidator(emptySecurity);
        Assert.False(emptyValidator.IsColumnDenied("Password"));

        var customSecurity = new GlobalSecurity { DeniedColumns = new List<string> { "*Auth*", "SpecialKey" } };
        var customValidator = new GuardrailsValidator(customSecurity);
        Assert.True(customValidator.IsColumnDenied("UserAuthToken"));
        Assert.True(customValidator.IsColumnDenied("SpecialKey"));
        Assert.False(customValidator.IsColumnDenied("RegularColumn"));
    }
}
