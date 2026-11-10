using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Nyxite.Crypto;

namespace Nyxite.Application.Auth;

/// <summary>
/// Account-password verifier (08 §8.1(a)): <c>Argon2id(HMAC-SHA256(pepper, password), salt)</c>, stored as a PHC string
/// <c>$argon2id$v=19$m=..,t=..,p=..$salt$hash</c>. The pepper is account-auth defense-in-depth only: the result unlocks
/// an API token and is never used to derive any key.
/// </summary>
public sealed class PasswordHasher
{
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private readonly VersionedSecret _pepper;
    private readonly Argon2idParameters _parameters;
    private readonly byte[] _dummyVerifier;
    private readonly SemaphoreSlim _slots;
    private readonly TimeSpan _queueTimeout;

    public PasswordHasher(IOptions<AuthOptions> options)
    {
        _pepper = VersionedSecret.Parse(options.Value.PasswordPepper, "Auth:PasswordPepper");
        _parameters = options.Value.PasswordHashing;
        _dummyVerifier = Hash("nyxite-timing-equalizer").Verifier;
        var slots = options.Value.MaxConcurrentPasswordHashes;
        if (slots < 0) throw new InvalidOperationException("Auth:MaxConcurrentPasswordHashes must not be negative.");
        _slots = new SemaphoreSlim(slots == 0 ? Environment.ProcessorCount : slots);
        _queueTimeout = options.Value.PasswordHashQueueTimeout;
    }

    // The async variants are what request code uses: they run the derivation off the request thread and under the
    // concurrency cap, so sign-ins can never hold more than slots x memory at once (13 §13.5).

    public Task<(byte[] Verifier, int PepperVersion)> HashAsync(string password, CancellationToken ct) =>
        RunAsync(() => Hash(password), ct);

    public Task<PasswordCheck> VerifyAsync(string password, byte[] verifier, int pepperVersion, CancellationToken ct) =>
        RunAsync(() => Verify(password, verifier, pepperVersion), ct);

    public Task DummyVerifyAsync(string password, CancellationToken ct) =>
        RunAsync(() => { DummyVerify(password); return true; }, ct);

    private async Task<T> RunAsync<T>(Func<T> work, CancellationToken ct)
    {
        if (!await _slots.WaitAsync(_queueTimeout, ct)) throw AuthException.RateLimited(TimeSpan.FromSeconds(1));
        try
        {
            return await Task.Run(work, ct);
        }
        finally
        {
            _slots.Release();
        }
    }

    public int CurrentPepperVersion => _pepper.CurrentVersion;

    public (byte[] Verifier, int PepperVersion) Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, _pepper.Current, salt, _parameters);
        var phc = $"$argon2id$v=19$m={_parameters.MemoryKiB},t={_parameters.Iterations},p={_parameters.Parallelism}" +
                  $"${ToB64(salt)}${ToB64(hash)}";
        return (Encoding.ASCII.GetBytes(phc), _pepper.CurrentVersion);
    }

    /// <summary>Checks a password. <c>NeedsRehash</c> is set when the verifier uses an old pepper or old parameters.</summary>
    public PasswordCheck Verify(string password, byte[] verifier, int pepperVersion)
    {
        if (!TryParse(verifier, out var parameters, out var salt, out var expected) || !_pepper.TryGet(pepperVersion, out var pepper))
        {
            DummyVerify(password);
            return new PasswordCheck(false, false);
        }

        var actual = Derive(password, pepper, salt, parameters);
        var ok = CryptographicOperations.FixedTimeEquals(actual, expected);
        return new PasswordCheck(ok, ok && (pepperVersion != _pepper.CurrentVersion || parameters != _parameters));
    }

    /// <summary>Spends the same work as a real check, so an unknown account is not distinguishable by timing.</summary>
    public void DummyVerify(string password)
    {
        TryParse(_dummyVerifier, out var parameters, out var salt, out _);
        Derive(password, _pepper.Current, salt, parameters);
    }

    private static byte[] Derive(string password, byte[] pepper, byte[] salt, Argon2idParameters parameters)
    {
        var preHash = HMACSHA256.HashData(pepper, Encoding.UTF8.GetBytes(password));
        try { return Argon2id.Derive(preHash, salt, parameters, HashBytes); }
        finally { CryptographicOperations.ZeroMemory(preHash); }
    }

    private static bool TryParse(byte[] verifier, out Argon2idParameters parameters, out byte[] salt, out byte[] hash)
    {
        parameters = Argon2id.Default;
        salt = hash = [];
        var parts = Encoding.ASCII.GetString(verifier).Split('$');
        if (parts.Length != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19") return false;
        int m = 0, t = 0, p = 0;
        foreach (var kv in parts[3].Split(','))
        {
            var pair = kv.Split('=');
            if (pair.Length != 2 || !int.TryParse(pair[1], out var n)) return false;
            switch (pair[0]) { case "m": m = n; break; case "t": t = n; break; case "p": p = n; break; default: return false; }
        }

        if (m <= 0 || t <= 0 || p <= 0) return false;
        try { salt = FromB64(parts[4]); hash = FromB64(parts[5]); }
        catch (FormatException) { return false; }
        parameters = new Argon2idParameters(m, t, p);
        return salt.Length >= 8 && hash.Length == HashBytes;
    }

    private static string ToB64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=');

    private static byte[] FromB64(string s) => Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
}

public readonly record struct PasswordCheck(bool Valid, bool NeedsRehash);
