using Microsoft.Extensions.Options;
using Nyxite.Application.Auth;
using Nyxite.Crypto;

namespace Nyxite.UnitTests.Auth;

public sealed class PasswordHashCapTests
{
    [Fact]
    public async Task A_hash_beyond_the_concurrency_cap_is_answered_429_instead_of_run()
    {
        var options = TestAuthOptions.Create().Value;
        options.MaxConcurrentPasswordHashes = 1;
        options.PasswordHashQueueTimeout = TimeSpan.Zero;
        // Slow enough that the first derivation still holds the only slot when the second one asks for it.
        options.PasswordHashing = new Argon2idParameters(MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 1);
        var hasher = new PasswordHasher(Options.Create(options));

        var first = hasher.HashAsync("correct horse battery staple", CancellationToken.None);
        var second = await Assert.ThrowsAsync<AuthException>(() => hasher.HashAsync("another password!", CancellationToken.None));

        Assert.Equal(429, second.Status);
        Assert.NotNull(second.RetryAfter);
        Assert.NotEmpty((await first).Verifier);
    }

    [Fact]
    public async Task Waiting_requests_get_a_slot_when_one_frees_up()
    {
        var options = TestAuthOptions.Create().Value;
        options.MaxConcurrentPasswordHashes = 1;
        var hasher = new PasswordHasher(Options.Create(options));

        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(i => hasher.HashAsync($"password number {i}", CancellationToken.None)));

        Assert.All(results, r => Assert.NotEmpty(r.Verifier));
    }
}
