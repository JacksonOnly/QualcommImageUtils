using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class QcomImageParserTests
{
    [Theory]
    [InlineData(false, 16 * 1024, 6, BootMemoryType.Unknown)]
    [InlineData(false, 16 * 1024 + 1, 6, BootMemoryType.Lite)]
    [InlineData(true, 1024 * 1024 - 1, 6, BootMemoryType.Lite)]
    [InlineData(true, 1024 * 1024, 6, BootMemoryType.Unknown)]
    [InlineData(false, 1024 * 1024 + 1, 6, BootMemoryType.Ddr)]
    [InlineData(true, 2 * 1024 * 1024, 7, BootMemoryType.Unknown)]
    public void TryParse_ElfMemoryOnlySegment_ClassifiesBootMemory(
        bool is64Bit,
        uint memorySize,
        uint flags,
        BootMemoryType expected)
    {
        byte[] image = BinaryImageFactory.CreateElf(
            BinaryImageFactory.CreateV3(),
            is64Bit,
            memoryOnlySegmentSize: memorySize,
            memoryOnlySegmentFlags: flags);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(expected, result.BootMemoryType);
    }

    [Theory]
    [InlineData("", DramGeneration.Unknown)]
    [InlineData("DRAM Vref DQ CDC perbit", DramGeneration.Ddr4)]
    [InlineData("DRAM_LP5", DramGeneration.Ddr5)]
    [InlineData("DRAM_LP5_training", DramGeneration.Ddr5)]
    [InlineData("DRAM Vref DQ CDC perbit\0DRAM_LP5_anything", DramGeneration.Combo)]
    public void TryParse_DramMarkers_ClassifiesGeneration(
        string markers,
        DramGeneration expected)
    {
        byte[] hashSegment = BinaryImageFactory.Append(
            BinaryImageFactory.CreateV3(),
            System.Text.Encoding.ASCII.GetBytes(markers));
        byte[] image = BinaryImageFactory.CreateElf(hashSegment, false);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(expected, result.DramGeneration);
    }

    [Theory]
    [InlineData(false, 3)]
    [InlineData(false, 5)]
    [InlineData(false, 6)]
    [InlineData(false, 7)]
    [InlineData(true, 3)]
    [InlineData(true, 5)]
    [InlineData(true, 6)]
    [InlineData(true, 7)]
    public void TryParse_Elf32AndElf64Versions_ReturnsExpectedHeader(
        bool is64Bit,
        int version)
    {
        byte[] hashSegment = BinaryImageFactory.CreateHashSegment(version);
        byte[] image = BinaryImageFactory.CreateElf(hashSegment, is64Bit, prefixLength: 13);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.True(result.IsSuccess);
        Assert.Equal("ELF", result.ImageFormat);
        Assert.Equal(checked((uint)version), result.HeaderVersion);
        if (version == 7)
            Assert.Null(result.ImageId);
        else
            Assert.Equal(BinaryImageFactory.ImageId, result.ImageId);
    }

    [Fact]
    public void TryParse_FlatV3Mbn_ReturnsImageIdentity()
    {
        byte[] image = BinaryImageFactory.CreateV3();
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("MBN", result.ImageFormat);
        Assert.Equal(3u, result.HeaderVersion);
        Assert.Equal(BinaryImageFactory.ImageId, result.ImageId);
        Assert.True(result.IsProgrammer);
        Assert.False(result.HasOemId);
        Assert.Equal(QualcommOemType.Unknown, result.OemType);
        Assert.False(result.IsSbl);
    }

    [Fact]
    public void TryParse_V3Sha1Elf_ReturnsExpectedHeader()
    {
        byte[] image = BinaryImageFactory.CreateElf(
            BinaryImageFactory.CreateV3Sha1(),
            false);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("ELF", result.ImageFormat);
        Assert.Equal(3u, result.HeaderVersion);
        Assert.Equal(BinaryImageFactory.ImageId, result.ImageId);
    }

    [Theory]
    [InlineData((uint)QcomImageType.NoneImg)]
    [InlineData((uint)QcomImageType.EhostdlImg)]
    [InlineData((uint)QcomImageType.Sbl1Img)]
    public void TryParse_LegacyFirehoseCandidateWithoutStructure_IsNotProgrammer(uint imageId)
    {
        byte[] image = BinaryImageFactory.CreateElf(
            BinaryImageFactory.CreateV3(imageId: imageId),
            true);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal((QcomImageType)imageId, result.ImageType);
        Assert.False(result.IsProgrammer);
        Assert.Empty(result.SupportedCommands);
    }

    [Fact]
    public void TryParse_EightyByteSbl_ReturnsArchitectureAndImageIdentity()
    {
        byte[] image = BinaryImageFactory.CreateSbl();
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("MBN", result.ImageFormat);
        Assert.True(result.IsSbl);
        Assert.Equal(SblType.SblAarch64, result.SblType);
        Assert.Equal(BinaryImageFactory.ImageId, result.ImageId);
        Assert.True(result.IsProgrammer);
    }

    [Fact]
    public void TryParse_V6VariableMetadata_UsesDeclaredOffsets()
    {
        byte[] image = BinaryImageFactory.CreateV6(28, 144);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(6u, result.HeaderVersion);
        Assert.Equal(BinaryImageFactory.SoftwareId, result.SwId);
        Assert.Equal(BinaryImageFactory.HardwareId, result.HwId);
        Assert.Equal(BinaryImageFactory.OemId, result.OemId);
        Assert.True(result.HasOemId);
        Assert.Equal(BinaryImageFactory.ModelId, result.ModelId);
        Assert.Equal(BinaryImageFactory.SocHardwareVersion, result.SocHwVersion);
        Assert.Equal(BinaryImageFactory.AntiRollbackVersion, result.AntiRollbackVersion);
    }

    [Fact]
    public void TryParse_V6WithV7ProgrammerSoftwareId_IsNotProgrammer()
    {
        byte[] image = BinaryImageFactory.CreateV6(
            16,
            128,
            BinaryImageFactory.ModernProgrammerSoftwareId);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(6u, result.HeaderVersion);
        Assert.Equal(BinaryImageFactory.ModernProgrammerSoftwareId, result.SwId);
        Assert.False(result.IsProgrammer);
    }

    [Fact]
    public void TryParse_V7VariableMetadata_UsesDeclaredOffsets()
    {
        byte[] image = BinaryImageFactory.CreateV7(36, 20, 248);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(7u, result.HeaderVersion);
        Assert.Equal(BinaryImageFactory.SoftwareId, result.SwId);
        Assert.Equal(BinaryImageFactory.OemId, result.OemId);
        Assert.Equal(BinaryImageFactory.ModelId, result.ModelId);
        Assert.Equal(BinaryImageFactory.SocHardwareVersion, result.SocHwVersion);
        Assert.Equal(BinaryImageFactory.AntiRollbackVersion, result.AntiRollbackVersion);
        Assert.Equal(BinaryImageFactory.ExpectedV7RootHash(), result.RootCaHash);
    }

    [Fact]
    public void TryParse_CertificateOuMetadata_MapsAttributesAndChain()
    {
        byte[] certificateChain = CertificateChainFactory.CreateWithOuMetadata();
        byte[] image = BinaryImageFactory.CreateV3(certificateChain);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(3ul, result.SwId);
        Assert.Equal(0x1000u, result.SwSize);
        Assert.Equal(0x1234567800AB00CDul, result.HwId);
        Assert.Equal(0x12345678u, result.MsmId);
        Assert.Equal(0xABu, result.OemId);
        Assert.Equal(0xCDu, result.ModelId);
        Assert.Equal(2, result.CertChains.Count);
        Assert.All(result.CertChains, item => Assert.Equal(CertificateChainType.Oem, item.ChainType));
        Assert.All(result.CertChains, item => Assert.Empty(item.CertPem));
        Assert.False(result.CertChains[0].IsRoot);
        Assert.True(result.CertChains[1].IsRoot);
        Assert.Contains("Qcom Test Root", result.RootCaSubject, StringComparison.Ordinal);
        Assert.NotEmpty(result.RootCaHash);
    }

    [Fact]
    public void TryParse_CertificateSoftwareIdWithAntiRollbackVersion_IsProgrammer()
    {
        const ulong softwareId = 0x0000000200000003;
        byte[] certificateChain = CertificateChainFactory.CreateWithOuMetadata(softwareId);
        byte[] image = BinaryImageFactory.CreateV3(certificateChain);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            AnalyzeFirehoseCommands = false,
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(softwareId, result.SwId);
        Assert.True(result.IsProgrammer);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void TryParse_SignedElfVector_ReturnsCertificatesAndHeader(int version)
    {
        SignedElfTestVector vector = SignedElfTestVectorFactory.CreateSigned(version);
        var parser = new QcomImageParser();

        bool success = parser.TryParse(vector.Image, out var result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("ELF", result.ImageFormat);
        Assert.Equal(checked((uint)version), result.HeaderVersion);
        Assert.Equal(2, result.CertChains.Count);
        Assert.Equal(vector.RootCertificateSha256, result.RootCaHash);
    }
}
