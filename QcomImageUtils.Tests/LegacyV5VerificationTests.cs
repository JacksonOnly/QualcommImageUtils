using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class LegacyV5VerificationTests
{
    [Fact]
    public void TryVerify_V5LegacySignature_ReturnsVerified()
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSignedV5Legacy();
        var verifier = new QcomImageVerifier();

        bool completed = verifier.TryVerify(vector.Image, out var result);

        Assert.True(completed, result.ErrorMessage);
        Assert.True(result.IsVerified);
        Assert.Equal(QcomVerificationStatus.Valid, result.SignatureStatus);
        Assert.Equal("RSA-QCOM-HMAC-SHA256", result.OemSignature.Algorithm);
    }
}
