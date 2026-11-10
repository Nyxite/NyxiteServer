using System.Reflection;
using NetArchTest.Rules;

namespace Nyxite.UnitTests.Architecture;

/// <summary>
/// Layering rules of server 01 §1.2/§1.3 and P0.1-CORE-4: the shared libraries consumed by the desktop app must not
/// depend on the host, persistence, ASP.NET Core or EF Core, and the server must run no CRDT engine.
/// </summary>
public sealed class ArchitectureTests
{
    private static readonly string[] HostAndInfrastructure =
    [
        "Nyxite.Server",
        "Nyxite.Application",
        "Nyxite.Persistence",
        "Nyxite.BlobStore",
        "Microsoft.AspNetCore",
        "Microsoft.EntityFrameworkCore",
        "Npgsql",
    ];

    public static TheoryData<string> SharedAssemblies() => new()
    {
        typeof(Nyxite.Domain.AssemblyMarker).Assembly.GetName().Name!,
        typeof(Nyxite.Contracts.AssemblyMarker).Assembly.GetName().Name!,
        typeof(Nyxite.Crypto.AssemblyMarker).Assembly.GetName().Name!,
        typeof(Nyxite.Crdt.AssemblyMarker).Assembly.GetName().Name!,
    };

    [Theory]
    [MemberData(nameof(SharedAssemblies))]
    public void SharedLibrary_DoesNotDependOnHostOrInfrastructure(string assemblyName)
    {
        var assembly = Assembly.Load(assemblyName);

        var result = Types.InAssembly(assembly).ShouldNot().HaveDependencyOnAny(HostAndInfrastructure).GetResult();

        Assert.True(result.IsSuccessful, Describe(result));
    }

    [Theory]
    [MemberData(nameof(SharedAssemblies))]
    public void SharedLibrary_ReferencesNoHostAssembly(string assemblyName)
    {
        var referenced = Assembly.Load(assemblyName).GetReferencedAssemblies().Select(a => a.Name!).ToList();

        var offending = referenced.Where(r => HostAndInfrastructure.Any(h => r.StartsWith(h, StringComparison.Ordinal))).ToList();

        Assert.Empty(offending);
    }

    [Fact]
    public void Server_DoesNotReferenceCrdtEngine()
    {
        var crdt = typeof(Nyxite.Crdt.AssemblyMarker).Assembly.GetName().Name!;
        var serverSide = new[]
        {
            typeof(Program).Assembly,
            typeof(Nyxite.Application.AssemblyMarker).Assembly,
            typeof(Nyxite.Persistence.AssemblyMarker).Assembly,
        };

        foreach (var assembly in serverSide)
        {
            Assert.DoesNotContain(assembly.GetReferencedAssemblies(), a => a.Name == crdt);
        }
    }

    [Fact]
    public void Domain_HasNoDependencyOnOtherNyxiteLayers()
    {
        var result = Types.InAssembly(typeof(Nyxite.Domain.AssemblyMarker).Assembly)
            .ShouldNot().HaveDependencyOnAny("Nyxite.Contracts", "Nyxite.Crypto", "Nyxite.Crdt")
            .GetResult();

        Assert.True(result.IsSuccessful, Describe(result));
    }

    [Fact]
    public void Persistence_DoesNotDependOnApplicationOrServer()
    {
        var result = Types.InAssembly(typeof(Nyxite.Persistence.AssemblyMarker).Assembly)
            .ShouldNot().HaveDependencyOnAny("Nyxite.Application", "Nyxite.Server", "Microsoft.AspNetCore")
            .GetResult();

        Assert.True(result.IsSuccessful, Describe(result));
    }

    private static readonly Assembly[] ServerAssemblies =
    [
        typeof(Nyxite.Application.AssemblyMarker).Assembly,
        typeof(Program).Assembly,
        typeof(Nyxite.Persistence.AssemblyMarker).Assembly,
    ];

    /// <summary>
    /// P0.1-TC-4 (automated part): the login password only ever reaches the verifier. Argon2id is used on the server by
    /// <c>PasswordHasher</c> alone, and only the native login flow and the password change/reset hand it a password; nothing derives a key from it.
    /// </summary>
    [Fact]
    public void LoginPassword_OnlyFeedsThePasswordVerifier()
    {
        // AuthOptions only carries the Argon2id parameter record (configuration), it derives nothing.
        var argonUsers = Types.InAssemblies(ServerAssemblies).That().HaveDependencyOn("Nyxite.Crypto.Argon2id")
            .Should().HaveNameMatching("^(PasswordHasher|AuthOptions)$").GetResult();
        var hasherUsers = Types.InAssemblies(ServerAssemblies).That().HaveDependencyOn("Nyxite.Application.Auth.PasswordHasher")
            .Should().HaveNameMatching("^(PasswordHasher|NativeAuthService|AccountSecurityService|ServiceCollectionExtensions)$").GetResult();

        Assert.True(argonUsers.IsSuccessful, Describe(argonUsers));
        Assert.True(hasherUsers.IsSuccessful, Describe(hasherUsers));
    }

    private static string Describe(NetArchTest.Rules.TestResult result) =>
        result.IsSuccessful ? string.Empty : "Offending types: " + string.Join(", ", result.FailingTypeNames ?? []);
}
