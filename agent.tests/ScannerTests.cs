// OpenDLP Agent tests - GPL-3.0-only
using System.Text.Json;
using OpenDLP.Agent;
using Xunit;

public class ValidatorTests
{
    [Theory]
    [InlineData("A123456789", true)]   // classic valid sample
    [InlineData("A123456788", false)]  // bad checksum
    [InlineData("Z999999999", false)]
    [InlineData("A12345678", false)]   // too short
    public void TaiwanNationalIdChecksum(string id, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidTwNationalId(id));

    [Theory]
    [InlineData("4111 1111 1111 1111", true)]
    [InlineData("5500-0000-0000-0004", true)]
    [InlineData("4111 1111 1111 1112", false)]
    [InlineData("1234 5678 9012 3456", false)] // leading digit outside card ranges
    public void CardLuhn(string card, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidCard(card));

    [Theory]
    [InlineData("GB82 WEST 1234 5698 7654 32", true)]
    [InlineData("DE89 3704 0044 0532 0130 00", true)]
    [InlineData("GB82 WEST 1234 5698 7654 33", false)]
    public void IbanMod97(string iban, bool expected) =>
        Assert.Equal(expected, ContentScanner.IsValidIban(iban));

    [Fact]
    public void MaskHidesMiddle()
    {
        Assert.Equal("A1******89", ContentScanner.Mask("A123456789"));
        Assert.Equal("****", ContentScanner.Mask("abcd"));
    }
}

public class ScannerTests
{
    private static ContentScanner Build(params object[] rules)
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var store = new PolicyStore(Path.Combine(dir, "cache.json"), Path.Combine(dir, "missing.json"));
        var env = new PolicyEnvelope
        {
            Version = 1,
            PolicyJson = JsonSerializer.Serialize(new { rules }),
            Sig = "unverified-in-unit-test"
        };
        Assert.True(store.Apply(env));
        return new ContentScanner(store);
    }

    [Fact]
    public void DetectsNationalIdAndMasksSample()
    {
        var sc = Build(new { id = "NID", type = "builtin", detector = "tw_national_id", minMatches = 1, severity = "high", action = "alert" });
        var hits = sc.Scan("客戶身分證 A123456789，另一個無效 A123456788");
        var h = Assert.Single(hits);
        Assert.Equal("NID", h.RuleId);
        Assert.Equal(1, h.Count);
        Assert.DoesNotContain("A123456789", h.Sample);
    }

    [Fact]
    public void MinMatchesIsRespected()
    {
        var sc = Build(new { id = "MOB", type = "builtin", detector = "tw_mobile", minMatches = 3 });
        Assert.Empty(sc.Scan("0912-345-678 0922333444"));
        Assert.Single(sc.Scan("0912-345-678 0922333444 0933 555 666"));
    }

    [Fact]
    public void KeywordsAreCaseInsensitive()
    {
        var sc = Build(new { id = "KW", type = "keywords", keywords = new[] { "confidential", "機密" } });
        var h = Assert.Single(sc.Scan("This is CONFIDENTIAL. 本文件為機密。"));
        Assert.Equal(2, h.Count);
    }

    [Fact]
    public void CustomRegexWorksAndBadRegexIsSkipped()
    {
        var sc = Build(
            new { id = "PRJ", type = "regex", pattern = @"PRJ-\d{4}" },
            new { id = "BAD", type = "regex", pattern = "(" });
        var hits = sc.Scan("ticket PRJ-1234 and PRJ-9999");
        var h = Assert.Single(hits);
        Assert.Equal("PRJ", h.RuleId);
        Assert.Equal(2, h.Count);
    }

    [Fact]
    public void DetectsSecrets()
    {
        var sc = Build(
            new { id = "API", type = "builtin", detector = "api_key" },
            new { id = "PK", type = "builtin", detector = "private_key" });
        var hits = sc.Scan("aws_key = AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        Assert.Contains(hits, h => h.RuleId == "API");
        Assert.Contains(hits, h => h.RuleId == "PK");
    }

    [Fact]
    public void PassportNeedsContextWord()
    {
        var sc = Build(new { id = "PP", type = "builtin", detector = "tw_passport" });
        Assert.Empty(sc.Scan("order 312345678"));
        Assert.Single(sc.Scan("護照號碼: 312345678"));
    }

    [Fact]
    public void DetectsUsSsnAndMultilingualPassport()
    {
        var sc = Build(
            new { id = "SSN", type = "builtin", detector = "us_ssn" },
            new { id = "PP", type = "builtin", detector = "passport" });
        var hits = sc.Scan("SSN 123-45-6789 but not 000-12-3456 or 666-12-3456. Reisepass Nr. C01X00T47. 여권 M12345678");
        Assert.Equal(1, Assert.Single(hits, h => h.RuleId == "SSN").Count);
        Assert.Equal(2, Assert.Single(hits, h => h.RuleId == "PP").Count);
    }

    [Fact]
    public void SummaryReportsWorstSeverity()
    {
        var hits = new[]
        {
            new ScanHit("A", "a", "medium", "log", 1, "x"),
            new ScanHit("B", "b", "critical", "alert", 2, "y"),
        };
        Assert.Equal("critical", ContentScanner.WorstSeverity(hits));
        Assert.StartsWith("severity=critical rules=Ax1,Bx2", ContentScanner.Summarize(hits));
    }
}

public class HeuristicTests
{
    [Theory]
    [InlineData(".jpg", "PE_EXECUTABLE", true)]
    [InlineData(".txt", "ZIP_OR_OOXML", true)]
    [InlineData(".docx", "ZIP_OR_OOXML", false)]
    [InlineData(".exe", "PE_EXECUTABLE", false)]
    public void ExtensionMismatch(string ext, string detected, bool expected) =>
        Assert.Equal(expected, new MagicBytesChecker().IsExtensionMismatch(ext, detected));

    [Fact]
    public void MagicBytesDetectsPngAndPe()
    {
        var png = Path.GetTempFileName();
        File.WriteAllBytes(png, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
        var pe = Path.GetTempFileName();
        File.WriteAllBytes(pe, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 });
        var m = new MagicBytesChecker();
        Assert.Equal("PNG", m.DetectFileType(png));
        Assert.Equal("PE_EXECUTABLE", m.DetectFileType(pe));
    }

    [Fact]
    public void EntropyOfRandomBytesIsHigh()
    {
        var f = Path.GetTempFileName();
        var buf = new byte[65536];
        Random.Shared.NextBytes(buf);
        File.WriteAllBytes(f, buf);
        Assert.True(new EntropyAnalyzer().Estimate(f) > 7.5);
        File.WriteAllBytes(f, new byte[65536]); // all zeros
        Assert.True(new EntropyAnalyzer().Estimate(f) < 0.1);
    }
}

public class PolicyStoreTests
{
    [Fact]
    public void ApplyPersistsAndReloads()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        var cache = Path.Combine(dir, "policy.json");
        var store = new PolicyStore(cache, Path.Combine(dir, "none.json"));
        var env = new PolicyEnvelope { Version = 42, PolicyJson = """{"rules":[],"usb":{"mode":"block"}}""", Sig = "x" };
        Assert.True(store.Apply(env));
        Assert.Equal(42, store.Current.Version);
        Assert.Equal("block", store.Current.Usb.Mode);

        var again = new PolicyStore(cache, Path.Combine(dir, "none.json"));
        again.LoadFromDisk();
        Assert.Equal(42, again.Current.Version);
    }

    [Fact]
    public void InvalidJsonIsRejected()
    {
        var dir = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"));
        var store = new PolicyStore(Path.Combine(dir, "p.json"), Path.Combine(dir, "d.json"));
        Assert.False(store.Apply(new PolicyEnvelope { Version = 1, PolicyJson = "{not json", Sig = "x" }));
    }
}

public class SignatureTests
{
    [Fact]
    public void EcdsaSignatureRoundTrip()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var data = System.Text.Encoding.UTF8.GetBytes("{\"rules\":[]}");
        var sig = key.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.DSASignatureFormat.Rfc3279DerSequence);
        var pem = key.ExportSubjectPublicKeyInfoPem();

        using var pub = PolicySignature.LoadPublicKey(pem)!;
        Assert.True(PolicySignature.Verify(pub, data, Convert.ToBase64String(sig)));
        Assert.False(PolicySignature.Verify(pub, System.Text.Encoding.UTF8.GetBytes("{\"rules\":[1]}"), Convert.ToBase64String(sig)));
        Assert.False(PolicySignature.Verify(pub, data, "not-base64!"));
        Assert.False(PolicySignature.Verify(pub, data, null));
    }

    [Fact]
    public void NoPublicKeyMeansNull() => Assert.Null(PolicySignature.LoadPublicKey(""));
}

public class EnrollmentTests
{
    [Fact]
    public void TokenRoundTripsThroughDpapi()
    {
        var path = Path.Combine(Path.GetTempPath(), "opendlp-tests", Guid.NewGuid().ToString("N"), "cred.bin");
        Enrollment.SaveToken(path, "secret-token-123");
        Assert.Equal("secret-token-123", Enrollment.LoadToken(path));
        Assert.NotEqual("secret-token-123", System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(path)));
        File.WriteAllBytes(path, new byte[] { 1, 2, 3 });
        Assert.Null(Enrollment.LoadToken(path));
        Assert.Null(Enrollment.LoadToken(path + ".missing"));
    }
}
