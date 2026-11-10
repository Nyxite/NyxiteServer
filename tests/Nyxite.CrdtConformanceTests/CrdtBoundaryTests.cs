namespace Nyxite.CrdtConformanceTests;

/// <summary>
/// Placeholder suite for the Yrs wire-protocol conformance vectors (P0.1-CORE-3).
/// Until the vectors exist it only proves the shared CRDT library loads stand-alone.
/// </summary>
public sealed class CrdtBoundaryTests
{
    [Fact]
    public void CrdtLibrary_Loads_WithoutServerAssemblies()
    {
        var references = typeof(Nyxite.Crdt.AssemblyMarker).Assembly.GetReferencedAssemblies();

        Assert.DoesNotContain(references, r => r.Name!.StartsWith("Nyxite.", StringComparison.Ordinal));
    }
}
