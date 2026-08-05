namespace QcomImageUtils.Tests;

internal sealed class SignedElfTestVector(
    byte[] image,
    string rootCertificateSha256,
    byte[] leafCertificateDer,
    byte[] rootCertificateDer,
    int elfHeaderLength,
    int signedDataOffset,
    int signedDataLength,
    int hashTableOffset,
    int hashTableLength,
    int signatureOffset,
    int signatureLength,
    int certificateChainOffset,
    int certificateChainLength,
    int firstContentOffset,
    int firstContentLength,
    int secondContentOffset,
    int secondContentLength)
{
    public byte[] Image { get; } = image;
    public string RootCertificateSha256 { get; } = rootCertificateSha256;
    public byte[] LeafCertificateDer { get; } = leafCertificateDer;
    public byte[] RootCertificateDer { get; } = rootCertificateDer;
    public int ElfHeaderLength { get; } = elfHeaderLength;
    public int SignedDataOffset { get; } = signedDataOffset;
    public int SignedDataLength { get; } = signedDataLength;
    public int HashTableOffset { get; } = hashTableOffset;
    public int HashTableLength { get; } = hashTableLength;
    public int SignatureOffset { get; } = signatureOffset;
    public int SignatureLength { get; } = signatureLength;
    public int CertificateChainOffset { get; } = certificateChainOffset;
    public int CertificateChainLength { get; } = certificateChainLength;
    public int FirstContentOffset { get; } = firstContentOffset;
    public int FirstContentLength { get; } = firstContentLength;
    public int SecondContentOffset { get; } = secondContentOffset;
    public int SecondContentLength { get; } = secondContentLength;

    public byte[] CopyImage()
    {
        return [.. Image];
    }

    public byte[] CreateContentTamperedImage()
    {
        return CopyAndFlip(FirstContentOffset + FirstContentLength / 2);
    }

    public byte[] CreateSignatureTamperedImage()
    {
        if (SignatureLength == 0)
            throw new InvalidOperationException("The vector does not contain a signature.");

        return CopyAndFlip(SignatureOffset + SignatureLength / 2);
    }

    public string CreateMismatchedRootSha256()
    {
        byte[] hash = Convert.FromHexString(RootCertificateSha256);
        hash[0] ^= 0xFF;
        return Convert.ToHexString(hash);
    }

    public SignedElfTestVector Copy()
    {
        return new SignedElfTestVector(
            [.. Image],
            RootCertificateSha256,
            [.. LeafCertificateDer],
            [.. RootCertificateDer],
            ElfHeaderLength,
            SignedDataOffset,
            SignedDataLength,
            HashTableOffset,
            HashTableLength,
            SignatureOffset,
            SignatureLength,
            CertificateChainOffset,
            CertificateChainLength,
            FirstContentOffset,
            FirstContentLength,
            SecondContentOffset,
            SecondContentLength);
    }

    private byte[] CopyAndFlip(int offset)
    {
        byte[] copy = CopyImage();
        copy[offset] ^= 0x01;
        return copy;
    }
}
