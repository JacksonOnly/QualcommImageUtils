using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace QcomImageUtils.Tests;

public sealed class QcomImageParserRobustnessTests
{
    [Fact]
    public void TryParse_EmptyAndTruncatedImages_ReturnsFailure()
    {
        var parser = new QcomImageParser();
        byte[] validImage = BinaryImageFactory.CreateV3();
        byte[] truncatedImage = validImage[..^1];

        bool emptySuccess = parser.TryParse([], out var emptyResult);
        bool truncatedSuccess = parser.TryParse(truncatedImage, out var truncatedResult);

        Assert.False(emptySuccess);
        Assert.False(emptyResult.IsSuccess);
        Assert.False(string.IsNullOrEmpty(emptyResult.ErrorMessage));
        Assert.False(truncatedSuccess);
        Assert.False(truncatedResult.IsSuccess);
        Assert.False(string.IsNullOrEmpty(truncatedResult.ErrorMessage));
    }

    [Fact]
    public void TryParse_OverflowingMbnLengths_ReturnsFailure()
    {
        byte[] image = BinaryImageFactory.CreateV5WithOverflowingLengths();
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.False(success);
        Assert.False(result.IsSuccess);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public void TryParse_OverflowingElfSegmentOffset_ReturnsFailure()
    {
        byte[] image = BinaryImageFactory.CreateElf64WithOverflowingSegmentOffset();
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.False(success);
        Assert.False(result.IsSuccess);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public void TryParse_InvalidDer_ReturnsFailure()
    {
        byte[] invalidDer = [0x30, 0x82, 0x01, 0x00];
        byte[] image = BinaryImageFactory.CreateV3(invalidDer);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.False(success);
        Assert.False(result.IsSuccess);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public void TryParse_MixedZeroAndFfCertificatePadding_ReturnsSuccess()
    {
        byte[] chain = CertificateChainFactory.CreateWithOuMetadata();
        byte[] paddedChain = BinaryImageFactory.Append(chain, [0x00, 0xFF, 0x00, 0xFF]);
        byte[] image = BinaryImageFactory.CreateV3(paddedChain);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(2, result.CertChains.Count);
    }

    [Fact]
    public void TryParse_NonPaddingCertificateTail_ReturnsFailure()
    {
        byte[] chain = CertificateChainFactory.CreateWithOuMetadata();
        byte[] paddedChain = BinaryImageFactory.Append(chain, [0x00, 0x01]);
        byte[] image = BinaryImageFactory.CreateV3(paddedChain);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.False(success);
        Assert.False(result.IsSuccess);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public void TryParse_InvalidElfBeforeValidElf_UsesOnlyValidCandidate()
    {
        byte[] invalidSegment = BinaryImageFactory.Append(
            BinaryImageFactory.CreateV7(32, 12, 240),
            [0x30, 0x82, 0x01, 0x00]);
        BinaryPrimitives.WriteUInt32LittleEndian(
            invalidSegment.AsSpan(36, sizeof(uint)),
            4);
        byte[] invalidElf = BinaryImageFactory.CreateElf(invalidSegment, false);
        byte[] validElf = BinaryImageFactory.CreateElf(
            BinaryImageFactory.CreateV5(),
            true);
        byte[] image = BinaryImageFactory.Append(invalidElf, validElf);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("ELF", result.ImageFormat);
        Assert.Equal(5u, result.HeaderVersion);
        Assert.Empty(result.RootCaHash);
        Assert.Empty(result.CertChains);
    }

    [Fact]
    public void TryParse_SblContainingElf_PreservesTopLevelFormat()
    {
        byte[] sbl = BinaryImageFactory.CreateSbl();
        byte[] elf = BinaryImageFactory.CreateElf(
            BinaryImageFactory.CreateV5(),
            false);
        byte[] image = BinaryImageFactory.Append(sbl, elf);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.True(result.IsSbl);
        Assert.Equal("MBN", result.ImageFormat);
        Assert.Equal(0u, result.HeaderVersion);
    }

    [Fact]
    public void TryParse_FileAndSpanPaths_ReturnEquivalentResults()
    {
        byte[] metadata = Encoding.ASCII.GetBytes(
            "QC_IMAGE_VERSION_STRING=TEST.QC\0" +
            "OEM_IMAGE_VERSION_STRING=TEST.OEM\0" +
            "IMAGE_VARIANT_STRING=TEST.VARIANT\0");
        byte[] image = BinaryImageFactory.Append(
            BinaryImageFactory.CreateV7(32, 12, 240),
            metadata);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            CalculateFileSha256 = true
        });
        string filePath = Path.Combine(
            Path.GetTempPath(),
            $"qcom-image-utils-{Guid.NewGuid():N}.mbn");

        try
        {
            File.WriteAllBytes(filePath, image);

            bool spanSuccess = parser.TryParse(image, out var spanResult);
            bool fileSuccess = parser.TryParse(filePath, out var fileResult);

            Assert.True(spanSuccess, spanResult.ErrorMessage);
            Assert.True(fileSuccess, fileResult.ErrorMessage);
            Assert.Equal(spanResult.ImageFormat, fileResult.ImageFormat);
            Assert.Equal(spanResult.HeaderVersion, fileResult.HeaderVersion);
            Assert.Equal(spanResult.FileSha256, fileResult.FileSha256);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(image)), fileResult.FileSha256);
            Assert.Equal(spanResult.SwId, fileResult.SwId);
            Assert.Equal(spanResult.SocHwVersion, fileResult.SocHwVersion);
            Assert.Equal(spanResult.OemId, fileResult.OemId);
            Assert.Equal(spanResult.ModelId, fileResult.ModelId);
            Assert.Equal(spanResult.RootCaHash, fileResult.RootCaHash);
            Assert.Equal("TEST.QC", fileResult.QcVersion);
            Assert.Equal("TEST.OEM", fileResult.OemVersion);
            Assert.Equal("TEST.VARIANT", fileResult.ImageVariant);
            Assert.Equal(Path.GetFullPath(filePath), fileResult.OriginalFilePath);
            Assert.Equal(Path.GetFileName(filePath), fileResult.OriginalFileName);
        }
        finally
        {
            File.Delete(filePath);
        }
    }
}
