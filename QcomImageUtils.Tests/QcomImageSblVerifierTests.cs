using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class QcomImageSblVerifierTests
{
    [Fact]
    public void TryVerify_ValidSignedSbl_ReturnsVerified()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateSigned();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.True(result.IsVerified);
        Assert.True(result.IsIntegrityValid);
        Assert.True(result.IsAuthentic);
        Assert.True(result.IsTrusted);
        Assert.True(result.Image.IsSbl);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.OemSignature.CertificateChainStatus);
        Assert.Equal("RSA-QCOM-HMAC-SHA256", result.OemSignature.Algorithm);
        Assert.Equal(2, result.OemSignature.CertificateCount);
        Assert.Equal(vector.RootCertificateSha256, result.OemSignature.RootCertificateSha256);
        Assert.Empty(result.Issues);
    }

    [Fact]
    public void TryVerify_TamperedSblHeader_ReturnsInvalidSignature()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateSigned();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.CreateHeaderTamperedImage(), out var result);

        AssertInvalidSignature(completed, result);
    }

    [Fact]
    public void TryVerify_TamperedSblCode_ReturnsInvalidSignature()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateSigned();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.CreateCodeTamperedImage(), out var result);

        AssertInvalidSignature(completed, result);
    }

    [Fact]
    public void TryVerify_SblSignedOverCodeOnly_ReturnsInvalidSignature()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateCodeOnlySigned();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        AssertInvalidSignature(completed, result);
    }

    [Fact]
    public void TryVerify_UnsignedSbl_ReturnsNotPresent()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateUnsigned();
        var verifier = new QcomImageVerifier();

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.Null(result.IsTrusted);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.NotChecked, result.TrustedRootStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.OemSignature.CertificateChainStatus);
        Assert.Empty(result.Issues);
    }

    [Fact]
    public void TryVerify_SignedSblWithPreamble_ReturnsVerified()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateSignedWithPreamble();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(vector.ImageSource > 80);
        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal("RSA-QCOM-HMAC-SHA256", result.OemSignature.Algorithm);
    }

    [Fact]
    public void TryVerify_TamperedSblPreamble_ReturnsInvalidSignature()
    {
        SignedSblTestVector vector = SignedSblTestVectorFactory.CreateSignedWithPreamble();
        QcomImageVerifier verifier = CreateVerifier(vector.RootCertificateSha256);

        bool completed = verifier.TryVerify(vector.CreatePreambleTamperedImage(), out var result);

        Assert.True(vector.PreambleLength > 0);
        AssertInvalidSignature(completed, result);
    }

    private static QcomImageVerifier CreateVerifier(string trustedRootHash)
    {
        return new QcomImageVerifier(new QcomImageVerifierOptions
        {
            TrustedRootCertificateHashes = [trustedRootHash]
        });
    }

    private static void AssertInvalidSignature(
        bool completed,
        QcomImageUtils.Models.QcomImageVerificationResult result)
    {
        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.VerificationCompleted);
        Assert.False(result.IsVerified);
        Assert.False(result.IsIntegrityValid);
        Assert.False(result.IsAuthentic);
        Assert.True(result.IsTrusted);
        Assert.Equal(QcomVerificationStatus.NotPresent, result.HashTableStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.CertificateChainStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.TrustedRootStatus);
        Assert.Equal(QcomVerificationStatus.Invalid, result.OemSignature.SignatureStatus);
        Assert.Equal(QcomVerificationStatus.Valid, result.OemSignature.CertificateChainStatus);
        Assert.NotEmpty(result.Issues);
    }
}
