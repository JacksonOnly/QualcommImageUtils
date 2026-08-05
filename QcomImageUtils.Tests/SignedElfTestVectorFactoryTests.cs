using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Buffers.Binary;
using System.Numerics;

namespace QcomImageUtils.Tests;

public sealed class SignedElfTestVectorFactoryTests
{
    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void CreateSigned_ProducesValidHashesSignatureAndCertificateChain(int version)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(version);
        ReadOnlySpan<byte> image = vector.Image;
        ReadOnlySpan<byte> hashTable = image.Slice(
            vector.HashTableOffset,
            vector.HashTableLength);

        Assert.Equal(
            SHA256.HashData(image[..vector.ElfHeaderLength]),
            hashTable[..32].ToArray());
        Assert.True(IsAllZero(hashTable.Slice(32, 32)));
        Assert.Equal(
            SHA256.HashData(image.Slice(vector.FirstContentOffset, vector.FirstContentLength)),
            hashTable.Slice(64, 32).ToArray());
        Assert.Equal(
            SHA256.HashData(image.Slice(vector.SecondContentOffset, vector.SecondContentLength)),
            hashTable.Slice(96, 32).ToArray());

        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(vector.LeafCertificateDer);
        using RSA? publicKey = leaf.GetRSAPublicKey();
        Assert.NotNull(publicKey);
        Assert.True(VerifySignature(version, publicKey, vector));

        using X509Certificate2 root = X509CertificateLoader.LoadCertificate(vector.RootCertificateDer);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf), FormatChainErrors(chain));
        Assert.Equal(
            vector.RootCertificateSha256,
            Convert.ToHexString(SHA256.HashData(vector.RootCertificateDer)));
    }

    [Fact]
    public void CreateBrokenCertificateChain_PreservesSignatureButBreaksIssuerPath()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateBrokenCertificateChain(3);

        using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(vector.LeafCertificateDer);
        using RSA? publicKey = leaf.GetRSAPublicKey();
        Assert.NotNull(publicKey);
        Assert.True(VerifySignature(3, publicKey, vector));

        using X509Certificate2 unrelatedRoot =
            X509CertificateLoader.LoadCertificate(vector.RootCertificateDer);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(unrelatedRoot);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.False(chain.Build(leaf));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void CreateUnsigned_OmitsOnlySignature(int version)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateUnsigned(version);

        Assert.Equal(0, vector.SignatureLength);
        Assert.True(vector.CertificateChainLength > 0);
        Assert.Throws<InvalidOperationException>(vector.CreateSignatureTamperedImage);
    }

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        for (int index = 0; index < data.Length; index++)
        {
            if (data[index] != 0)
                return false;
        }

        return true;
    }

    private static bool VerifySignature(
        int version,
        RSA publicKey,
        SignedElfTestVector vector)
    {
        ReadOnlySpan<byte> signedData = vector.Image.AsSpan(
            vector.SignedDataOffset,
            vector.SignedDataLength);
        ReadOnlySpan<byte> signature = vector.Image.AsSpan(
            vector.SignatureOffset,
            vector.SignatureLength);
        if (version == 5)
        {
            return publicKey.VerifyData(
                signedData,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }

        byte[] digest = ComputeLegacyDigest(signedData);
        RSAParameters parameters = publicKey.ExportParameters(false);
        byte[] modulusBytes = parameters.Modulus
                              ?? throw new CryptographicException("RSA modulus is missing.");
        byte[] exponentBytes = parameters.Exponent
                               ?? throw new CryptographicException("RSA exponent is missing.");
        var modulus = new BigInteger(modulusBytes, true, true);
        var exponent = new BigInteger(exponentBytes, true, true);
        var signatureValue = new BigInteger(signature, true, true);
        byte[] recovered = BigInteger.ModPow(signatureValue, exponent, modulus)
            .ToByteArray(true, true);
        Span<byte> encodedMessage = stackalloc byte[modulusBytes.Length];
        recovered.CopyTo(encodedMessage[(encodedMessage.Length - recovered.Length)..]);
        int delimiterOffset = encodedMessage.Length - digest.Length - 1;
        if (encodedMessage[0] != 0 || encodedMessage[1] != 1 || encodedMessage[delimiterOffset] != 0)
            return false;
        for (int index = 2; index < delimiterOffset; index++)
        {
            if (encodedMessage[index] != 0xFF)
                return false;
        }

        return CryptographicOperations.FixedTimeEquals(encodedMessage[(delimiterOffset + 1)..], digest);
    }

    private static byte[] ComputeLegacyDigest(ReadOnlySpan<byte> data)
    {
        Span<byte> firstDigest = stackalloc byte[32];
        Span<byte> secondDigest = stackalloc byte[32];
        Span<byte> input = stackalloc byte[40];

        SHA256.HashData(data, firstDigest);
        BinaryPrimitives.WriteUInt64BigEndian(
            input,
            SignedElfTestVectorFactory.LegacySoftwareId ^ 0x3636363636363636);
        firstDigest.CopyTo(input[8..]);
        SHA256.HashData(input, secondDigest);
        BinaryPrimitives.WriteUInt64BigEndian(
            input,
            SignedElfTestVectorFactory.LegacyHardwareId ^ 0x5C5C5C5C5C5C5C5C);
        secondDigest.CopyTo(input[8..]);
        return SHA256.HashData(input);
    }

    private static string FormatChainErrors(X509Chain chain)
    {
        return string.Join(
            "; ",
            chain.ChainStatus.Select(status => $"{status.Status}: {status.StatusInformation.Trim()}"));
    }
}
