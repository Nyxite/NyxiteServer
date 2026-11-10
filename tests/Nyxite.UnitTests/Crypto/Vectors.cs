namespace Nyxite.UnitTests.Crypto;

/// <summary>
/// The shared conformance vectors (P0.1-CORE-2, P0.1-CORE-5) in <c>Resources/vectors</c>. The same files are checked
/// into every client repo, so a change here is a wire-format change for all four codebases.
/// </summary>
internal static class Vectors
{
    public static string Directory => Path.Combine(AppContext.BaseDirectory, "Resources", "vectors");

    public static string Read(string name) => File.ReadAllText(Path.Combine(Directory, name));
}
