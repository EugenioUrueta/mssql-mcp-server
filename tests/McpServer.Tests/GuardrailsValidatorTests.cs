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
            DeniedColumns = new List<string> { "*Password*", "*Token*", "*Secret*", "*Hash*", "*Salt*" }
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
    [InlineData("[dbo].[fac_facturas]")]
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
}
