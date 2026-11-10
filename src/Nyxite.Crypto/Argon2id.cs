using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nyxite.Crypto;

/// <summary>Argon2id (RFC 9106, version 0x13). Pinned v1 parameters are <see cref="Default"/> (07 §7.3).</summary>
public static class Argon2id
{
    /// <summary>m = 64 MiB, t = 3, p = 1.</summary>
    public static readonly Argon2idParameters Default = new(MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 1);

    public static byte[] Derive(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Argon2idParameters parameters, int outputLength = 32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(salt.Length, 8, nameof(salt));
        var p = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithMemoryAsKB(parameters.MemoryKiB)
            .WithIterations(parameters.Iterations)
            .WithParallelism(parameters.Parallelism)
            .WithSalt(salt.ToArray())
            .Build();
        var generator = new Argon2BytesGenerator();
        generator.Init(p);
        var output = new byte[outputLength];
        generator.GenerateBytes(password.ToArray(), output);
        return output;
    }
}

public sealed record Argon2idParameters(int MemoryKiB, int Iterations, int Parallelism);
