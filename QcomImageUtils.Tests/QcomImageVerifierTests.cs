using System.Buffers.Binary;
using System.Security.Cryptography;
using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class QcomImageVerifierTests
{
    [Theory]
    [InlineData(1, 20)]
    [InlineData(2, 32)]
    [InlineData(3, 48)]
    [InlineData(4, 64)]
    public void VerifyMetadataRootHash_UsesDeclaredAlgorithm(uint algorithm, int digestLength)
    {
        byte[] rootCertificate = Enumerable.Range(0, 137).Select(value => (byte)value).ToArray();
        byte[] slot = new byte[64];
        HashAlgorithmName hashAlgorithm = algorithm switch
        {
            1 => HashAlgorithmName.SHA1,
            2 => HashAlgorithmName.SHA256,
            3 => HashAlgorithmName.SHA384,
            4 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
        using IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);
        hash.AppendData(rootCertificate);
        Assert.True(hash.TryGetHashAndReset(slot, out int bytesWritten));
        Assert.Equal(digestLength, bytesWritten);

        QcomVerificationStatus status = QcomImageVerifier.VerifyMetadataRootHash(
            slot,
            algorithm,
            [rootCertificate]);

        Assert.Equal(QcomVerificationStatus.Valid, status);
    }

    [Fact]
    public void VerifyMetadataRootHash_DoesNotTryAnUndeclaredAlgorithm()
    {
        byte[] rootCertificate = Enumerable.Range(0, 137).Select(value => (byte)value).ToArray();
        byte[] slot = new byte[64];
        SHA256.HashData(rootCertificate, slot);

        QcomVerificationStatus status = QcomImageVerifier.VerifyMetadataRootHash(
            slot,
            3,
            [rootCertificate]);

        Assert.Equal(QcomVerificationStatus.Invalid, status);
    }

    [Fact]
    public void VerifyMetadataRootHash_RejectsUnknownAlgorithm()
    {
        QcomVerificationStatus status = QcomImageVerifier.VerifyMetadataRootHash(
            new byte[64],
            uint.MaxValue,
            [new byte[] { 1, 2, 3 }]);

        Assert.Equal(QcomVerificationStatus.Unsupported, status);
    }

    [Theory]
    [InlineData(3, "RSA-QCOM-HMAC-SHA256")]
    [InlineData(5, "RSA-PSS-SHA256")]
    public void TryVerify_ValidSignedElf_ReturnsVerified(
        int version,
        string expectedAlgorithm)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(version);
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.True(result.IsVerified);
        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.MetadataRootHashStatus);
        Assert.Equal(4, result.ExpectedHashCount);
        Assert.Equal(4, result.VerifiedHashCount);
        Assert.Equal(-1, result.FailedSegmentIndex);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.QualcommSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.QualcommSignature.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.OemSignature.CertificateChainStatus);
        Assert.Equal(expectedAlgorithm, result.OemSignature.Algorithm);
        Assert.Equal(2, result.OemSignature.CertificateCount);
        Assert.Equal(vector.RootCertificateSha256, result.OemSignature.RootCertificateSha256);
        Assert.Empty(result.Issues);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void TryVerify_TamperedSegment_ReturnsInvalidHashTable(int version)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(version);
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.CreateContentTamperedImage(), out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Invalid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(4, result.ExpectedHashCount);
        Assert.Equal(2, result.VerifiedHashCount);
        Assert.Equal(2, result.FailedSegmentIndex);
        Assert.NotEmpty(result.Issues);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void TryVerify_TamperedSignature_ReturnsInvalidSignature(int version)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(version);
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.CreateSignatureTamperedImage(), out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.False(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.NotEmpty(result.Issues);
    }

    [Fact]
    public void TryVerify_BrokenCertificateChain_ReturnsInvalidChain()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateBrokenCertificateChain(3);
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.False(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.OemSignature.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.TrustedRootStatus);
        Assert.NotEmpty(result.Issues);
    }

    [Fact]
    public void TryVerify_UntrustedRoot_ReturnsAuthenticButNotVerified()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(5);
        QcomImageVerifier verifier = CreateVerifier(vector.CreateMismatchedRootSha256());

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsAuthentic);
        Assert.False(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.TrustedRootStatus);
        Assert.NotEmpty(result.Issues);
    }

    [Fact]
    public void TryVerify_UnsignedElf_ReturnsNotPresentAndNotAuthentic()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateUnsigned(3);
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.True(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.False(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
    }

    [Fact]
    public void TryVerify_ConcatenatedSignedElfs_VerifiesEveryComponent()
    {
        SignedElfTestVector first = SignedElfTestVectorFactory.CreateSigned(3);
        SignedElfTestVector second = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] image = Concatenate(first.Image, second.Image);
        QcomImageVerifier verifier = CreateVerifier(
            first.RootCertificateSha256,
            second.RootCertificateSha256);

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.True(result.IsVerified);
        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(8, result.ExpectedHashCount);
        Assert.Equal(8, result.VerifiedHashCount);
        Assert.Equal(2, result.Components.Count);
        Assert.Equal(0, result.Components[0].ComponentIndex);
        Assert.Equal(0, result.Components[0].ImageOffset);
        Assert.Equal(1, result.Components[1].ComponentIndex);
        Assert.Equal(first.Image.Length, result.Components[1].ImageOffset);
        Assert.All(result.Components, component => Assert.True(component.IsVerified));
        Assert.All(
            result.Components,
            component => Assert.Equal(QcomVerificationStatus.Valid, component.HashTableStatus));
        Assert.All(
            result.Components,
            component => Assert.Equal(QcomVerificationStatus.Valid, component.SignatureStatus));
        Assert.All(
            result.Components,
            component => Assert.Equal(QcomVerificationStatus.Valid, component.CertificateChainStatus));
        Assert.All(
            result.Components,
            component => Assert.Equal(QcomVerificationStatus.Valid, component.TrustedRootStatus));
        Assert.Equal("RSA-QCOM-HMAC-SHA256", result.Components[0].OemSignature.Algorithm);
        Assert.Equal("RSA-PSS-SHA256", result.Components[1].OemSignature.Algorithm);
        Assert.All(
            result.Components,
            component => Assert.Equal(
                QcomVerificationStatus.NotPresent,
                component.QualcommSignature.SignatureStatus));
    }

    [Fact]
    public void TryVerify_TooManyElfComponents_FailsContainer()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] combined = BinaryImageFactory.Append(vector.Image, vector.Image);
        var verifier = new QcomImageVerifier(new QcomImageVerifierOptions
        {
            MaximumElfComponentCount = 1,
            TrustedRootCertificateHashes = [vector.RootCertificateSha256]
        });

        bool completed = verifier.TryVerify(combined, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.False(result.IsVerified);
        Assert.Equal(2, result.Components.Count);
        Assert.Contains(result.Components[1].Issues, issue => issue.Contains("组件数量超过", StringComparison.Ordinal));
    }

    [Fact]
    public void TryVerify_ConcatenatedSignedElfsWithTamperedSecondComponent_FailsContainer()
    {
        SignedElfTestVector first = SignedElfTestVectorFactory.CreateSigned(3);
        SignedElfTestVector second = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] image = Concatenate(first.Image, second.CreateContentTamperedImage());
        QcomImageVerifier verifier = CreateVerifier(
            first.RootCertificateSha256,
            second.RootCertificateSha256);

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Invalid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(8, result.ExpectedHashCount);
        Assert.Equal(6, result.VerifiedHashCount);
        Assert.Equal(2, result.Components.Count);
        Assert.True(result.Components[0].IsVerified);
        Assert.False(result.Components[1].IsVerified);
        Assert.False(result.Components[1].IsIntegrityValid);
        Assert.Equal(QcomVerificationStatus.Invalid, result.Components[1].HashTableStatus);
        Assert.Contains(result.Issues, issue => issue.Contains("ELF 组件 1", StringComparison.Ordinal));
    }

    [Fact]
    public void TryVerify_ConcatenatedSignedElfsWithInvalidSecondMbnHeader_FailsContainer()
    {
        SignedElfTestVector first = SignedElfTestVectorFactory.CreateSigned(3);
        SignedElfTestVector second = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] corruptedSecond = second.CopyImage();
        BinaryPrimitives.WriteUInt32LittleEndian(
            corruptedSecond.AsSpan(second.SignedDataOffset + 16, sizeof(uint)),
            uint.MaxValue);
        byte[] image = Concatenate(first.Image, corruptedSecond);
        QcomImageVerifier verifier = CreateVerifier(
            first.RootCertificateSha256,
            second.RootCertificateSha256);

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Invalid, result.HashTableStatus);
        Assert.Equal(2, result.Components.Count);
        Assert.True(result.Components[0].IsVerified);
        Assert.False(result.Components[1].IsVerified);
        Assert.Equal(QcomVerificationStatus.Invalid, result.Components[1].HashTableStatus);
        Assert.Equal(first.Image.Length, result.Components[1].ImageOffset);
    }

    [Fact]
    public void TryVerify_ConcatenatedSignedElfsWithInvalidSecondProgramHeader_FailsContainer()
    {
        SignedElfTestVector first = SignedElfTestVectorFactory.CreateSigned(3);
        SignedElfTestVector second = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] corruptedSecond = second.CopyImage();
        BinaryPrimitives.WriteUInt32LittleEndian(
            corruptedSecond.AsSpan(28, sizeof(uint)),
            uint.MaxValue);
        byte[] image = Concatenate(first.Image, corruptedSecond);
        QcomImageVerifier verifier = CreateVerifier(
            first.RootCertificateSha256,
            second.RootCertificateSha256);

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.Equal(QcomVerificationStatus.Invalid, result.HashTableStatus);
        Assert.Equal(2, result.Components.Count);
        Assert.True(result.Components[0].IsVerified);
        Assert.False(result.Components[1].IsVerified);
        Assert.Equal(QcomVerificationStatus.Invalid, result.Components[1].HashTableStatus);
        Assert.Equal(first.Image.Length, result.Components[1].ImageOffset);
    }

    [Fact]
    public void TryVerify_UnsignedOuterElfWithSignedInnerElf_IgnoresOuterWrapper()
    {
        byte[] outer = BinaryImageFactory.CreateElf(BinaryImageFactory.CreateV3(), false);
        BinaryPrimitives.WriteUInt32LittleEndian(outer.AsSpan(52 + 24, sizeof(uint)), 0);
        SignedElfTestVector inner = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] image = Concatenate(outer, inner.Image);
        QcomImageVerifier verifier = CreateVerifier(inner.RootCertificateSha256);

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.True(result.IsVerified);
        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsAuthentic);
        Assert.Single(result.Components);
        Assert.Equal(outer.Length, result.Components[0].ImageOffset);
        Assert.True(result.Components[0].IsVerified);
    }

    [Fact]
    public void TryVerify_AuthenticatedNestedNonQualcommElf_IgnoresNestedPayload()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSignedWithAuthenticatedNestedElf();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsVerified);
        Assert.Single(result.Components);
        Assert.Equal(QcomVerificationStatus.Valid, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
    }

    [Fact]
    public void TryVerify_SblContainingSignedElf_UsesSblEnvelope()
    {
        SignedElfTestVector embedded = SignedElfTestVectorFactory.CreateSigned(5);
        byte[] image = BinaryImageFactory.CreateSbl(embedded.Image);
        var verifier = new QcomImageVerifier();

        bool completed = verifier.TryVerify(image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.SignatureStatus);
        Assert.Empty(result.Components);
    }

    private static QcomImageVerifier CreateVerifier(params string[] trustedRootHashes)
    {
        return new QcomImageVerifier(new QcomImageVerifierOptions
        {
            TrustedRootCertificateHashes = trustedRootHashes
        });
    }

    private static byte[] Concatenate(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[checked(first.Length + second.Length)];
        first.CopyTo(result);
        second.CopyTo(result.AsSpan(first.Length));
        return result;
    }
}
