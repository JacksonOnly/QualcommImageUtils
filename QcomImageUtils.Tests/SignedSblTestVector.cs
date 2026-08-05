namespace QcomImageUtils.Tests;

internal sealed class SignedSblTestVector(
    byte[] image,
    string rootCertificateSha256,
    int imageSource,
    int codeLength,
    int signatureLength,
    int certificateChainLength)
{
    private const int HeaderTamperOffset = 12;
    private const int HeaderLength = 80;

    public byte[] Image { get; } = image;
    public string RootCertificateSha256 { get; } = rootCertificateSha256;
    public int ImageSource { get; } = imageSource;
    public int CodeLength { get; } = codeLength;
    public int SignatureOffset => checked(ImageSource + CodeLength);
    public int SignatureLength { get; } = signatureLength;
    public int CertificateChainOffset => checked(SignatureOffset + SignatureLength);
    public int CertificateChainLength { get; } = certificateChainLength;
    public int PreambleLength => ImageSource - HeaderLength;

    public byte[] CreateHeaderTamperedImage()
    {
        return CopyAndFlip(HeaderTamperOffset);
    }

    public byte[] CreateCodeTamperedImage()
    {
        return CopyAndFlip(ImageSource + CodeLength / 2);
    }

    public byte[] CreatePreambleTamperedImage()
    {
        if (PreambleLength == 0)
            throw new InvalidOperationException("The vector does not contain a preamble.");

        return CopyAndFlip(HeaderLength + PreambleLength / 2);
    }

    public SignedSblTestVector Copy()
    {
        return new SignedSblTestVector(
            [.. Image],
            RootCertificateSha256,
            ImageSource,
            CodeLength,
            SignatureLength,
            CertificateChainLength);
    }

    private byte[] CopyAndFlip(int offset)
    {
        byte[] copy = [.. Image];
        copy[offset] ^= 0x01;
        return copy;
    }
}
