using Nyxite.Application.Auth;

namespace Nyxite.UnitTests.Auth;

public sealed class OneTimeCodesTests
{
    [Fact]
    public void Email_codes_have_eight_digits_and_vary()
    {
        var codes = Enumerable.Range(0, 50).Select(_ => OneTimeCodes.NewEmailCode()).ToList();
        Assert.All(codes, c => Assert.True(OneTimeCodes.IsEmailCode(c)));
        Assert.True(codes.Distinct().Count() > 45);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1234567")]
    [InlineData("123456789")]
    [InlineData("1234567a")]
    [InlineData("１２３４５６７８")]
    public void Malformed_email_codes_are_rejected(string? code) => Assert.False(OneTimeCodes.IsEmailCode(code));

    [Fact]
    public void Backup_codes_use_the_unambiguous_alphabet_in_two_groups()
    {
        var code = OneTimeCodes.NewBackupCode();
        Assert.Matches("^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$", code);
        Assert.Equal(code.Replace("-", ""), OneTimeCodes.NormalizeBackupCode(code));
    }

    [Theory]
    [InlineData("abcde-fghjk", "ABCDEFGHJK")]
    [InlineData(" ABCDE FGHJK ", "ABCDEFGHJK")]
    [InlineData("o0ilO-11111", "0011011111")]
    public void Backup_code_input_is_normalized(string typed, string expected) =>
        Assert.Equal(expected, OneTimeCodes.NormalizeBackupCode(typed));

    [Theory]
    [InlineData(null)]
    [InlineData("ABCDE-FGHJ")]
    [InlineData("ABCDE-FGHJKM")]
    [InlineData("ABCDE-FGHJU")]
    [InlineData("ABCDE_FGHJK")]
    public void Malformed_backup_codes_normalize_to_null(string? typed) => Assert.Null(OneTimeCodes.NormalizeBackupCode(typed));

    [Fact]
    public void Hash_verifies_only_the_same_code_and_purpose()
    {
        var codes = new OneTimeCodes(TestAuthOptions.Create());
        var (hash, version) = codes.Hash("email_login", "12345678");

        Assert.Equal(1, version);
        Assert.True(codes.Verify("email_login", "12345678", hash, version));
        Assert.False(codes.Verify("email_login", "12345679", hash, version));
        Assert.False(codes.Verify("email_verify", "12345678", hash, version));
        Assert.False(codes.Verify("email_login", null, hash, version));
        Assert.False(codes.Verify("email_login", "12345678", hash, 7));
    }

    [Fact]
    public void Hash_is_keyed_by_the_pepper_and_survives_rotation()
    {
        var v1 = new OneTimeCodes(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)}"));
        var other = new OneTimeCodes(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(3)}"));
        var rotated = new OneTimeCodes(TestAuthOptions.Create(pepper: $"1:{TestAuthOptions.Key(1)};2:{TestAuthOptions.Key(2)}"));
        var (hash, version) = v1.Hash("backup_code", "ABCDEFGHJK");

        Assert.False(other.Verify("backup_code", "ABCDEFGHJK", hash, version));
        Assert.True(rotated.Verify("backup_code", "ABCDEFGHJK", hash, version));
        Assert.Equal(2, rotated.Hash("backup_code", "ABCDEFGHJK").Version);
    }
}
