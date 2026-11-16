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
}
