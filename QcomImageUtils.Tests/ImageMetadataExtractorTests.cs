using System.Buffers.Binary;
using System.Text;
using QcomImageUtils.Models;
using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class ImageMetadataExtractorTests
{
    [Fact]
    public void TryParse_Arm64VersionStringsFromReferencedCalls_ExtractsMetadata()
    {
        byte[] image = MetadataImageFactory.CreateArm64VersionImage();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);
        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
    }

    [Fact]
    public void TryParse_Arm32VersionStringsFromReferencedCalls_ExtractsMetadata()
    {
        byte[] image = MetadataImageFactory.CreateArm32VersionImage();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);
        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TryParse_ArmVersionStringsPassedDirectlyInArgumentRegister_ExtractsMetadata(
        bool isArm64)
    {
        byte[] image = isArm64
            ? MetadataImageFactory.CreateArm64VersionImage(
                useDirectVersionArguments: true)
            : MetadataImageFactory.CreateArm32VersionImage(
                useDirectVersionArguments: true);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
    }

    [Fact]
    public void TryParse_ThumbVersionStringsPassedDirectlyInArgumentRegister_ExtractsMetadata()
    {
        byte[] image = MetadataImageFactory.CreateThumbDirectVersionArgumentImage();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TryParse_ArmBuildTimeFromReferencedCall_ExtractsBuildTime(bool isArm64)
    {
        byte[] image = isArm64
            ? MetadataImageFactory.CreateArm64VersionImage(includeBuildTimeCall: true)
            : MetadataImageFactory.CreateArm32VersionImage(includeBuildTimeCall: true);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out QcomImageParseResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_Arm64MoveWideBuildTimeAddresses_ExtractsBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateArm64VersionImage(
            includeBuildTimeCall: true,
            useMoveWideBuildTimeAddresses: true);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_Arm32MoveImmediateBuildTimeFormat_ExtractsBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateArm32VersionImage(
            includeBuildTimeCall: true,
            useMoveImmediateBuildFormat: true);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_ThumbBuildTimeFromReferencedCall_ExtractsBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateThumbBuildTimeImage();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_Thumb2WideLiteralBuildTimeFromReferencedCall_ExtractsBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateThumbWideLiteralBuildTimeImage();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_Thumb2MoveWideBetweenArgumentsAndCall_PreservesBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateThumbBuildTimeImageWithWideMoveImmediate();
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_ThumbBuildTimeFromRegisterCall_ExtractsBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateThumbBuildTimeImage(
            useRegisterCall: true);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void TryParse_ThumbRegisterOffsetLoadOverwritesArgument_DoesNotExtractStaleBuildTime(
        int destinationRegister)
    {
        byte[] image = MetadataImageFactory.CreateThumbBuildTimeImageWithRegisterOffsetOverwrite(
            destinationRegister);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Null(result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void TryParse_ThumbMoveFromUnknownSourceOverwritesArgument_DoesNotExtractStaleBuildTime(
        int destinationRegister)
    {
        byte[] image = MetadataImageFactory.CreateThumbBuildTimeImageWithUnknownMoveOverwrite(
            destinationRegister);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Null(result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_ArmImageWithUnreferencedBuildTimeStrings_DoesNotExtractBuildTime()
    {
        byte[] image = MetadataImageFactory.CreateArm64VersionImage(
            includeBuildTimeStrings: true);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Null(result.BuildTime);
        Assert.Null(result.BuildTimeDebug);
    }

    [Fact]
    public void TryParse_MultipleArmElfs_SelectsOneMetadataComponentWithoutMixingFields()
    {
        byte[] firstComponent = MetadataImageFactory.CreateArm64VersionImage(
            includeOemVersionCall: false,
            includeImageVariantCall: false);
        byte[] secondComponent = MetadataImageFactory.CreateArm64VersionImage(
            includeBuildTimeCall: true,
            includeQcVersionCall: false);
        byte[] image = MetadataImageFactory.Combine(firstComponent, secondComponent);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Empty(result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
    }

    [Fact]
    public void TryParse_MultipleArmElfs_CombinesCoherentVersionSetWithReferencedBuildTime()
    {
        byte[] versionComponent = MetadataImageFactory.CreateArm64VersionImage();
        byte[] buildTimeComponent = MetadataImageFactory.CreateArm64VersionImage(
            includeBuildTimeCall: true,
            includeQcVersionCall: false,
            includeOemVersionCall: false,
            includeImageVariantCall: false);
        byte[] image = MetadataImageFactory.Combine(versionComponent, buildTimeComponent);
        var result = new QcomImageParseResult();

        ImageMetadataExtractor.Extract(image, 256, result);

        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Equal("c4-miui-ota-bd108.bj", result.OemVersion);
        Assert.Equal("Soc8250LAA", result.ImageVariant);
        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
    }

    [Fact]
    public void TryParse_MultipleArmElfs_KeepsSelectedVersionSetAndFindsBuildTime()
    {
        byte[] selectedComponent = MetadataImageFactory.CreateArm64VersionImage(
            includeOemVersionCall: false,
            includeImageVariantCall: false);
        byte[] otherComponent = MetadataImageFactory.CreateArm64VersionImage(
            includeBuildTimeCall: true);
        byte[] image = MetadataImageFactory.Combine(selectedComponent, otherComponent);
        var parser = new QcomImageParser(new QcomImageParserOptions
        {
            ExportCertificatePem = false
        });

        bool success = parser.TryParse(image, out QcomImageParseResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal("BOOT.XF.3.2-00304-SM8250-2", result.QcVersion);
        Assert.Empty(result.OemVersion);
        Assert.Empty(result.ImageVariant);
        Assert.Equal("2025-10-11 08:00:26", result.BuildTime);
    }

    private static class MetadataImageFactory
    {
        private const int ElfHeaderSize32 = 52;
        private const int ElfHeaderSize64 = 64;
        private const int ProgramHeaderSize32 = 32;
        private const int ProgramHeaderSize64 = 56;
        private const int CodeOffset = 0x200;
        private const int DataOffset = 0x400;
        private const int HashOffset = 0xC00;
        private const int CodeSize = 0x200;
        private const int DataSize = 0x200;
        private const uint HashSegmentFlags = 0x02200000;
        private const ulong CodeAddress = 0x100000;
        private const ulong DataAddress = 0x200000;
        private const ulong HashAddress = 0x300000;

        public static byte[] CreateArm64VersionImage(
            bool includeBuildTimeCall = false,
            bool includeBuildTimeStrings = false,
            bool includeQcVersionCall = true,
            bool includeOemVersionCall = true,
            bool includeImageVariantCall = true,
            bool useMoveWideBuildTimeAddresses = false,
            bool useDirectVersionArguments = false)
        {
            byte[] image = CreateElfImage(is64Bit: true, machine: 183);
            Span<byte> code = image.AsSpan(CodeOffset, CodeSize);
            Span<byte> data = image.AsSpan(DataOffset, DataSize);

            int literalOffset = 0x100;
            int instructionOffset = 0;
            ulong fmtLiteral = CodeAddress + (ulong)literalOffset;
            ulong qcLiteral = fmtLiteral + 8;
            ulong variantLiteral = qcLiteral + 8;
            ulong oemLiteral = variantLiteral + 8;

            ulong fmtAddress = WriteString(data, "fmt", "%s");
            ulong qcAddress = WriteString(data, "qc", "QC_IMAGE_VERSION_STRING=BOOT.XF.3.2-00304-SM8250-2");
            ulong variantAddress = WriteString(data, "variant", "IMAGE_VARIANT_STRING=Soc8250LAA");
            ulong oemAddress = WriteString(data, "oem", "OEM_IMAGE_VERSION_STRING=c4-miui-ota-bd108.bj");
            ulong buildFormatAddress = 0;
            ulong buildDateAddress = 0;
            ulong buildTimeAddress = 0;
            if (includeBuildTimeCall || includeBuildTimeStrings)
            {
                WriteBuildTimeStrings(
                    data,
                    out buildFormatAddress,
                    out buildDateAddress,
                    out buildTimeAddress);
            }

            WriteUInt64(code, literalOffset, fmtAddress);
            WriteUInt64(code, literalOffset + 8, qcAddress);
            WriteUInt64(code, literalOffset + 16, variantAddress);
            WriteUInt64(code, literalOffset + 24, oemAddress);

            if (includeQcVersionCall)
            {
                if (!useDirectVersionArguments)
                    WriteArm64Instruction(code, instructionOffset += 0x00, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, fmtLiteral, 2));
                WriteArm64Instruction(code, instructionOffset += useDirectVersionArguments ? 0x00 : 0x04, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, qcLiteral, useDirectVersionArguments ? 6 : 3));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64MoveImmediate(1, 96));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));
            }

            if (includeImageVariantCall)
            {
                if (!useDirectVersionArguments)
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, fmtLiteral, 2));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, variantLiteral, useDirectVersionArguments ? 5 : 3));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64MoveImmediate(1, 96));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));
            }

            if (includeOemVersionCall)
            {
                if (!useDirectVersionArguments)
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, fmtLiteral, 2));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64LiteralLoad(CodeAddress + (ulong)instructionOffset, oemLiteral, useDirectVersionArguments ? 4 : 3));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64MoveImmediate(1, 96));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));
            }

            if (includeBuildTimeCall)
            {
                if (useMoveWideBuildTimeAddresses)
                {
                    WriteArm64MoveWideAddress(code, ref instructionOffset, buildFormatAddress, 1);
                    WriteArm64MoveWideAddress(code, ref instructionOffset, buildDateAddress, 2);
                    WriteArm64MoveWideAddress(code, ref instructionOffset, buildTimeAddress, 3);
                }
                else
                {
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64Adrp(CodeAddress + (ulong)instructionOffset, buildFormatAddress, 1));
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64Adrp(CodeAddress + (ulong)instructionOffset, buildDateAddress, 2));
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64Adrp(CodeAddress + (ulong)instructionOffset, buildTimeAddress, 3));
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64AddAddress(buildFormatAddress, 1));
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64AddAddress(buildDateAddress, 2));
                    WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64AddAddress(buildTimeAddress, 3));
                }
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64MoveImmediate(0, 4));
                WriteArm64Instruction(code, instructionOffset += 0x04, EncodeArm64BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));
            }
            WriteArm64Instruction(code, 0x180, 0xD65F03C0u);

            return image;
        }

        public static byte[] Combine(params byte[][] images)
        {
            int totalLength = 0;
            for (int index = 0; index < images.Length; index++)
                totalLength = checked(totalLength + images[index].Length);

            var combined = new byte[totalLength];
            int offset = 0;
            for (int index = 0; index < images.Length; index++)
            {
                byte[] image = images[index];
                image.CopyTo(combined.AsSpan(offset));
                offset += image.Length;
            }
            return combined;
        }

        public static byte[] CreateArm32VersionImage(
            bool includeBuildTimeCall = false,
            bool useMoveImmediateBuildFormat = false,
            bool useDirectVersionArguments = false)
        {
            byte[] image = CreateElfImage(is64Bit: false, machine: 40);
            Span<byte> code = image.AsSpan(CodeOffset, CodeSize);
            Span<byte> data = image.AsSpan(DataOffset, DataSize);

            int literalOffset = 0x100;
            int instructionOffset = 0;
            ulong fmtLiteral = CodeAddress + (ulong)literalOffset;
            ulong qcLiteral = fmtLiteral + 4;
            ulong variantLiteral = qcLiteral + 4;
            ulong oemLiteral = variantLiteral + 4;

            ulong fmtAddress = WriteString(data, "fmt", "%s");
            ulong qcAddress = WriteString(data, "qc", "QC_IMAGE_VERSION_STRING=BOOT.XF.3.2-00304-SM8250-2");
            ulong variantAddress = WriteString(data, "variant", "IMAGE_VARIANT_STRING=Soc8250LAA");
            ulong oemAddress = WriteString(data, "oem", "OEM_IMAGE_VERSION_STRING=c4-miui-ota-bd108.bj");
            ulong buildFormatAddress = 0;
            ulong buildDateAddress = 0;
            ulong buildTimeAddress = 0;
            if (includeBuildTimeCall)
            {
                if (useMoveImmediateBuildFormat)
                {
                    int formatOffset = 0;
                    buildFormatAddress = WriteStringAtOffset(
                        data,
                        ref formatOffset,
                        "Binary build date: %s @ %s");
                    int dateOffset = 0x100;
                    buildDateAddress = WriteStringAtOffset(
                        data,
                        ref dateOffset,
                        "Oct 11 2025");
                    buildTimeAddress = WriteStringAtOffset(
                        data,
                        ref dateOffset,
                        "08:00:26");
                }
                else
                {
                    WriteBuildTimeStrings(
                        data,
                        out buildFormatAddress,
                        out buildDateAddress,
                        out buildTimeAddress);
                }
            }

            WriteUInt32(code, literalOffset, checked((uint)fmtAddress));
            WriteUInt32(code, literalOffset + 4, checked((uint)qcAddress));
            WriteUInt32(code, literalOffset + 8, checked((uint)variantAddress));
            WriteUInt32(code, literalOffset + 12, checked((uint)oemAddress));
            if (includeBuildTimeCall)
            {
                if (!useMoveImmediateBuildFormat)
                    WriteUInt32(code, literalOffset + 16, checked((uint)buildFormatAddress));
                WriteUInt32(code, literalOffset + 20, checked((uint)buildDateAddress));
                WriteUInt32(code, literalOffset + 24, checked((uint)buildTimeAddress));
            }

            if (!useDirectVersionArguments)
                WriteArm32Instruction(code, instructionOffset += 0x00, EncodeArm32LiteralLoad(2, CodeAddress + 0x00, fmtLiteral));
            WriteArm32Instruction(code, instructionOffset += useDirectVersionArguments ? 0x00 : 0x04, EncodeArm32LiteralLoad(useDirectVersionArguments ? 0 : 3, CodeAddress + (ulong)instructionOffset, qcLiteral));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32MoveImmediate(1, 96));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));

            if (!useDirectVersionArguments)
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(2, CodeAddress + (ulong)instructionOffset, fmtLiteral));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(useDirectVersionArguments ? 0 : 3, CodeAddress + (ulong)instructionOffset, variantLiteral));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32MoveImmediate(1, 96));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));

            if (!useDirectVersionArguments)
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(2, CodeAddress + (ulong)instructionOffset, fmtLiteral));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(useDirectVersionArguments ? 0 : 3, CodeAddress + (ulong)instructionOffset, oemLiteral));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32MoveImmediate(1, 96));
            WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));

            if (includeBuildTimeCall)
            {
                WriteArm32Instruction(
                    code,
                    instructionOffset += 0x04,
                    useMoveImmediateBuildFormat
                        ? EncodeArm32MoveModifiedImmediate(1, immediate: 2, rotation: 6)
                        : EncodeArm32LiteralLoad(1, CodeAddress + (ulong)instructionOffset, fmtLiteral + 16));
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(2, CodeAddress + (ulong)instructionOffset, fmtLiteral + 20));
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32LiteralLoad(3, CodeAddress + (ulong)instructionOffset, fmtLiteral + 24));
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32MoveImmediate(0, 4));
                WriteArm32Instruction(code, instructionOffset += 0x04, EncodeArm32BranchLink(CodeAddress + (ulong)instructionOffset, CodeAddress + 0x180));
            }
            WriteArm32Instruction(code, 0x180, 0xE12FFF1Eu);

            return image;
        }

        public static byte[] CreateThumbDirectVersionArgumentImage()
        {
            byte[] image = CreateElfImage(is64Bit: false, machine: 40);
            WriteUInt32(image, 24, checked((uint)(CodeAddress | 1UL)));
            Span<byte> code = image.AsSpan(CodeOffset, CodeSize);
            Span<byte> data = image.AsSpan(DataOffset, DataSize);

            ulong qcAddress = WriteString(
                data,
                "qc",
                "QC_IMAGE_VERSION_STRING=BOOT.XF.3.2-00304-SM8250-2");
            ulong variantAddress = WriteString(
                data,
                "variant",
                "IMAGE_VARIANT_STRING=Soc8250LAA");
            ulong oemAddress = WriteString(
                data,
                "oem",
                "OEM_IMAGE_VERSION_STRING=c4-miui-ota-bd108.bj");

            const int literalOffset = 0x100;
            WriteUInt32(code, literalOffset, checked((uint)qcAddress));
            WriteUInt32(code, literalOffset + 4, checked((uint)variantAddress));
            WriteUInt32(code, literalOffset + 8, checked((uint)oemAddress));

            WriteUInt16(
                code,
                0x00,
                EncodeThumbLiteralLoad(0, CodeAddress, CodeAddress + literalOffset));
            WriteUInt32(
                code,
                0x02,
                EncodeThumbBranchLink(CodeAddress + 0x02, CodeAddress + 0x180));
            WriteUInt16(
                code,
                0x06,
                EncodeThumbLiteralLoad(1, CodeAddress + 0x06, CodeAddress + literalOffset + 4));
            WriteUInt32(
                code,
                0x08,
                EncodeThumbBranchLink(CodeAddress + 0x08, CodeAddress + 0x180));
            WriteUInt16(
                code,
                0x0C,
                EncodeThumbLiteralLoad(2, CodeAddress + 0x0C, CodeAddress + literalOffset + 8));
            WriteUInt32(
                code,
                0x0E,
                EncodeThumbBranchLink(CodeAddress + 0x0E, CodeAddress + 0x180));
            WriteUInt16(code, 0x180, 0x4770); // BX LR

            return image;
        }

        public static byte[] CreateThumbBuildTimeImage(bool useRegisterCall = false)
        {
            return CreateThumbBuildTimeImage(
                firstArgumentRegister: 1,
                interveningInstruction: 0x2004, // MOVS R0, #4
                useRegisterCall);
        }

        public static byte[] CreateThumbWideLiteralBuildTimeImage()
        {
            return CreateThumbBuildTimeImage(
                firstArgumentRegister: 1,
                interveningInstruction: 0x2004, // MOVS R0, #4
                useRegisterCall: false,
                useWideLiteralLoads: true);
        }

        public static byte[] CreateThumbBuildTimeImageWithWideMoveImmediate()
        {
            return CreateThumbBuildTimeImage(
                firstArgumentRegister: 1,
                interveningInstruction: 0x0004F04Fu, // MOV.W R0, #4
                useRegisterCall: false,
                interveningInstructionSize: sizeof(uint));
        }

        public static byte[] CreateThumbBuildTimeImageWithRegisterOffsetOverwrite(
            int destinationRegister)
        {
            return CreateThumbBuildTimeImage(
                firstArgumentRegister: 0,
                interveningInstruction: EncodeThumbRegisterOffsetLoad(
                    destinationRegister,
                    baseRegister: 5,
                    offsetRegister: 4),
                useRegisterCall: false);
        }

        public static byte[] CreateThumbBuildTimeImageWithUnknownMoveOverwrite(
            int destinationRegister)
        {
            return CreateThumbBuildTimeImage(
                firstArgumentRegister: 0,
                interveningInstruction: EncodeThumbMove(
                    destinationRegister,
                    sourceRegister: 7),
                useRegisterCall: false);
        }

        private static byte[] CreateThumbBuildTimeImage(
            int firstArgumentRegister,
            uint interveningInstruction,
            bool useRegisterCall,
            bool useWideLiteralLoads = false,
            int interveningInstructionSize = sizeof(ushort))
        {
            byte[] image = CreateElfImage(is64Bit: false, machine: 40);
            WriteUInt32(image, 24, checked((uint)(CodeAddress | 1UL)));
            Span<byte> code = image.AsSpan(CodeOffset, CodeSize);
            Span<byte> data = image.AsSpan(DataOffset, DataSize);

            int stringOffset = 0x20;
            ulong formatAddress = WriteStringAtOffset(
                data,
                ref stringOffset,
                "Binary build date: %s @ %s");
            ulong dateAddress = WriteStringAtOffset(data, ref stringOffset, "Oct 11 2025");
            ulong timeAddress = WriteStringAtOffset(data, ref stringOffset, "08:00:26");

            const int literalOffset = 0x100;
            WriteUInt32(code, literalOffset, checked((uint)formatAddress));
            WriteUInt32(code, literalOffset + 4, checked((uint)dateAddress));
            WriteUInt32(code, literalOffset + 8, checked((uint)timeAddress));
            WriteUInt32(code, literalOffset + 12, checked((uint)(CodeAddress + 0x181)));

            int interveningOffset;
            if (useWideLiteralLoads)
            {
                WriteUInt32(
                    code,
                    0x00,
                    EncodeThumbWideLiteralLoad(
                        firstArgumentRegister,
                        CodeAddress,
                        CodeAddress + (ulong)literalOffset));
                WriteUInt32(
                    code,
                    0x04,
                    EncodeThumbWideLiteralLoad(
                        firstArgumentRegister + 1,
                        CodeAddress + 4,
                        CodeAddress + (ulong)(literalOffset + 4)));
                WriteUInt32(
                    code,
                    0x08,
                    EncodeThumbWideLiteralLoad(
                        firstArgumentRegister + 2,
                        CodeAddress + 8,
                        CodeAddress + (ulong)(literalOffset + 8)));
                interveningOffset = 0x0C;
            }
            else
            {
                WriteUInt16(
                    code,
                    0x00,
                    EncodeThumbLiteralLoad(
                        firstArgumentRegister,
                        CodeAddress,
                        CodeAddress + (ulong)literalOffset));
                WriteUInt16(
                    code,
                    0x02,
                    EncodeThumbLiteralLoad(
                        firstArgumentRegister + 1,
                        CodeAddress + 2,
                        CodeAddress + (ulong)(literalOffset + 4)));
                WriteUInt16(
                    code,
                    0x04,
                    EncodeThumbLiteralLoad(
                        firstArgumentRegister + 2,
                        CodeAddress + 4,
                        CodeAddress + (ulong)(literalOffset + 8)));
                interveningOffset = 0x06;
            }

            if (interveningInstructionSize == sizeof(uint))
                WriteUInt32(code, interveningOffset, interveningInstruction);
            else
                WriteUInt16(code, interveningOffset, checked((ushort)interveningInstruction));
            int callOffset = interveningOffset + interveningInstructionSize;
            if (useRegisterCall)
            {
                WriteUInt16(
                    code,
                    callOffset,
                    EncodeThumbLiteralLoad(
                        4,
                        CodeAddress + checked((ulong)callOffset),
                        CodeAddress + literalOffset + 12));
                WriteUInt16(
                    code,
                    callOffset + sizeof(ushort),
                    EncodeThumbBranchLinkExchange(4));
            }
            else
            {
                WriteUInt32(
                    code,
                    callOffset,
                    EncodeThumbBranchLink(
                        CodeAddress + checked((ulong)callOffset),
                        CodeAddress + 0x180));
            }
            WriteUInt16(code, 0x180, 0x4770); // BX LR

            return image;
        }

        private static byte[] CreateElfImage(bool is64Bit, ushort machine)
        {
            int headerSize = is64Bit ? ElfHeaderSize64 : ElfHeaderSize32;
            int programHeaderSize = is64Bit ? ProgramHeaderSize64 : ProgramHeaderSize32;
            byte[] hashSegment = BinaryImageFactory.CreateHashSegment(3);
            int totalLength = HashOffset + hashSegment.Length;
            var image = new byte[totalLength];

            image[0] = 0x7F;
            image[1] = (byte)'E';
            image[2] = (byte)'L';
            image[3] = (byte)'F';
            image[4] = is64Bit ? (byte)2 : (byte)1;
            image[5] = 1;
            image[6] = 1;
            WriteUInt16(image, 16, 2);
            WriteUInt16(image, 18, machine);
            WriteUInt32(image, 20, 1);

            if (is64Bit)
            {
                WriteUInt64(image, 24, CodeAddress);
                WriteUInt64(image, 32, (ulong)headerSize);
                WriteUInt16(image, 52, (ushort)headerSize);
                WriteUInt16(image, 54, (ushort)programHeaderSize);
                WriteUInt16(image, 56, 3);
            }
            else
            {
                WriteUInt32(image, 24, (uint)CodeAddress);
                WriteUInt32(image, 28, (uint)headerSize);
                WriteUInt16(image, 40, (ushort)headerSize);
                WriteUInt16(image, 42, (ushort)programHeaderSize);
                WriteUInt16(image, 44, 3);
            }

            WriteProgramHeader(image, headerSize, is64Bit, CodeOffset, CodeAddress, CodeSize, 5);
            WriteProgramHeader(
                image,
                headerSize + programHeaderSize,
                is64Bit,
                DataOffset,
                DataAddress,
                DataSize,
                6);
            WriteProgramHeader(
                image,
                headerSize + programHeaderSize * 2,
                is64Bit,
                HashOffset,
                HashAddress,
                hashSegment.Length,
                HashSegmentFlags);

            hashSegment.CopyTo(image.AsSpan(HashOffset, hashSegment.Length));

            return image;
        }

        private static void WriteArm64Instruction(Span<byte> image, int offset, uint instruction)
        {
            WriteUInt32(image, offset, instruction);
        }

        private static void WriteArm32Instruction(Span<byte> image, int offset, uint instruction)
        {
            WriteUInt32(image, offset, instruction);
        }

        private static uint EncodeArm64LiteralLoad(ulong instructionAddress, ulong literalAddress, int register)
        {
            long delta = checked((long)literalAddress - (long)instructionAddress);
            Assert.Equal(0, delta & 3);
            long immediate = delta >> 2;
            Assert.InRange(immediate, -(1L << 18), (1L << 18) - 1);
            return 0x58000000u | (unchecked((uint)immediate) << 5) | checked((uint)register);
        }

        private static uint EncodeArm64MoveImmediate(int destinationRegister, int immediate)
        {
            Assert.InRange(immediate, 0, 0xFFFF);
            return 0x52800000u
                   | (checked((uint)immediate) << 5)
                   | checked((uint)destinationRegister);
        }

        private static void WriteArm64MoveWideAddress(
            Span<byte> image,
            ref int instructionOffset,
            ulong address,
            int destinationRegister)
        {
            Assert.InRange(address, 0UL, uint.MaxValue);
            WriteArm64Instruction(
                image,
                instructionOffset += sizeof(uint),
                EncodeArm64MoveWide(
                    destinationRegister,
                    checked((ushort)(address & 0xFFFFUL)),
                    shift: 0,
                    keepsOtherBits: false));
            WriteArm64Instruction(
                image,
                instructionOffset += sizeof(uint),
                EncodeArm64MoveWide(
                    destinationRegister,
                    checked((ushort)((address >> 16) & 0xFFFFUL)),
                    shift: 16,
                    keepsOtherBits: true));
        }

        private static uint EncodeArm64MoveWide(
            int destinationRegister,
            ushort immediate,
            int shift,
            bool keepsOtherBits)
        {
            Assert.InRange(destinationRegister, 0, 30);
            Assert.True(shift is 0 or 16 or 32 or 48);
            uint opcode = keepsOtherBits ? 0xF2800000u : 0xD2800000u;
            return opcode
                   | (checked((uint)(shift / 16)) << 21)
                   | (checked((uint)immediate) << 5)
                   | checked((uint)destinationRegister);
        }

        private static uint EncodeArm64Adrp(
            ulong instructionAddress,
            ulong targetAddress,
            int destinationRegister)
        {
            long pageDelta = checked(
                ((long)(targetAddress & ~0xFFFUL) - (long)(instructionAddress & ~0xFFFUL)) >> 12);
            Assert.InRange(pageDelta, -(1L << 20), (1L << 20) - 1);
            uint immediate = unchecked((uint)pageDelta) & 0x1FFFFFu;
            return 0x90000000u
                   | ((immediate & 0x3u) << 29)
                   | (((immediate >> 2) & 0x7FFFFu) << 5)
                   | checked((uint)destinationRegister);
        }

        private static uint EncodeArm64AddAddress(ulong address, int register)
        {
            uint immediate = checked((uint)(address & 0xFFFUL));
            return 0x91000000u
                   | (immediate << 10)
                   | (checked((uint)register) << 5)
                   | checked((uint)register);
        }

        private static uint EncodeArm64BranchLink(ulong instructionAddress, ulong targetAddress)
        {
            long delta = checked((long)targetAddress - (long)instructionAddress);
            Assert.Equal(0, delta & 3);
            long immediate = delta >> 2;
            Assert.InRange(immediate, -(1L << 25), (1L << 25) - 1);
            return 0x94000000u | (unchecked((uint)immediate) & 0x03FFFFFFu);
        }

        private static uint EncodeArm32LiteralLoad(int destinationRegister, ulong instructionAddress, ulong literalAddress)
        {
            long delta = checked((long)literalAddress - checked((long)instructionAddress + 8));
            Assert.Equal(0, delta & 3);
            Assert.InRange(delta, -4095L, 4095L);
            uint opcode = delta >= 0 ? 0xE59F0000u : 0xE51F0000u;
            return opcode
                   | (checked((uint)destinationRegister) << 12)
                   | checked((uint)Math.Abs(delta));
        }

        private static uint EncodeArm32MoveImmediate(int destinationRegister, int immediate)
        {
            Assert.InRange(immediate, 0, 255);
            return 0xE3A00000u
                   | (checked((uint)destinationRegister) << 12)
                   | checked((uint)immediate);
        }

        private static uint EncodeArm32MoveModifiedImmediate(
            int destinationRegister,
            int immediate,
            int rotation)
        {
            Assert.InRange(destinationRegister, 0, 14);
            Assert.InRange(immediate, 0, 255);
            Assert.InRange(rotation, 0, 15);
            return 0xE3A00000u
                   | (checked((uint)destinationRegister) << 12)
                   | (checked((uint)rotation) << 8)
                   | checked((uint)immediate);
        }

        private static uint EncodeArm32BranchLink(ulong instructionAddress, ulong targetAddress)
        {
            long delta = checked((long)targetAddress - checked((long)instructionAddress + 8));
            Assert.Equal(0, delta & 3);
            long immediate = delta >> 2;
            Assert.InRange(immediate, -(1L << 23), (1L << 23) - 1);
            return 0xEB000000u | (unchecked((uint)immediate) & 0x00FFFFFFu);
        }

        private static ushort EncodeThumbLiteralLoad(
            int destinationRegister,
            ulong instructionAddress,
            ulong literalAddress)
        {
            ulong alignedPc = (instructionAddress + 4) & ~3UL;
            long delta = checked((long)literalAddress - (long)alignedPc);
            Assert.True(delta >= 0 && delta % 4 == 0);
            Assert.InRange(delta / 4, 0L, 255L);
            return checked((ushort)(0x4800u
                                    | (checked((uint)destinationRegister) << 8)
                                    | checked((uint)(delta / 4))));
        }

        private static uint EncodeThumbWideLiteralLoad(
            int destinationRegister,
            ulong instructionAddress,
            ulong literalAddress)
        {
            Assert.InRange(destinationRegister, 0, 14);
            ulong alignedPc = (instructionAddress + 4) & ~3UL;
            long delta = checked((long)literalAddress - (long)alignedPc);
            Assert.InRange(delta, -4095L, 4095L);
            ushort first = delta >= 0 ? (ushort)0xF8DF : (ushort)0xF85F;
            ushort second = checked((ushort)(
                (checked((uint)destinationRegister) << 12)
                | checked((uint)Math.Abs(delta))));
            return (uint)first | ((uint)second << 16);
        }

        private static uint EncodeThumbBranchLink(ulong instructionAddress, ulong targetAddress)
        {
            long delta = checked((long)targetAddress - checked((long)instructionAddress + 4));
            Assert.Equal(0, delta & 1);
            Assert.InRange(delta, -(1L << 24), (1L << 24) - 2);
            uint encoded = unchecked((uint)delta) & 0x01FFFFFFu;
            uint sign = (encoded >> 24) & 1u;
            uint i1 = (encoded >> 23) & 1u;
            uint i2 = (encoded >> 22) & 1u;
            uint j1 = (~(i1 ^ sign)) & 1u;
            uint j2 = (~(i2 ^ sign)) & 1u;
            ushort first = checked((ushort)(
                0xF000u
                | (sign << 10)
                | ((encoded >> 12) & 0x03FFu)));
            ushort second = checked((ushort)(
                0xD000u
                | (j1 << 13)
                | (j2 << 11)
                | ((encoded >> 1) & 0x07FFu)));
            return (uint)first | ((uint)second << 16);
        }

        private static ushort EncodeThumbBranchLinkExchange(int register)
        {
            Assert.InRange(register, 0, 15);
            return checked((ushort)(0x4780u | (checked((uint)register) << 3)));
        }

        private static ushort EncodeThumbRegisterOffsetLoad(
            int destinationRegister,
            int baseRegister,
            int offsetRegister)
        {
            Assert.InRange(destinationRegister, 0, 7);
            Assert.InRange(baseRegister, 0, 7);
            Assert.InRange(offsetRegister, 0, 7);
            return checked((ushort)(0x5800u
                                    | (checked((uint)offsetRegister) << 6)
                                    | (checked((uint)baseRegister) << 3)
                                    | checked((uint)destinationRegister)));
        }

        private static ushort EncodeThumbMove(int destinationRegister, int sourceRegister)
        {
            Assert.InRange(destinationRegister, 0, 14);
            Assert.InRange(sourceRegister, 0, 15);
            return checked((ushort)(0x4600u
                                    | (checked((uint)sourceRegister) << 3)
                                    | checked((uint)(destinationRegister & 7))
                                    | (checked((uint)(destinationRegister & 8)) << 4)));
        }

        private static ulong WriteString(Span<byte> image, string label, string value)
        {
            int offset = label switch
            {
                "fmt" => 0x20,
                "qc" => 0x40,
                "variant" => 0x80,
                "oem" => 0xC0,
                _ => throw new ArgumentOutOfRangeException(nameof(label))
            };

            byte[] bytes = Encoding.ASCII.GetBytes(value);
            bytes.CopyTo(image.Slice(offset, bytes.Length));
            image[offset + bytes.Length] = 0;
            return DataAddress + checked((ulong)offset);
        }

        private static void WriteBuildTimeStrings(
            Span<byte> image,
            out ulong formatAddress,
            out ulong dateAddress,
            out ulong timeAddress)
        {
            int offset = 0x100;
            formatAddress = WriteStringAtOffset(image, ref offset, "Binary build date: %s @ %s");
            dateAddress = WriteStringAtOffset(image, ref offset, "Oct 11 2025");
            timeAddress = WriteStringAtOffset(image, ref offset, "08:00:26");
        }

        private static ulong WriteStringAtOffset(Span<byte> image, ref int offset, string value)
        {
            int stringOffset = offset;
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            bytes.CopyTo(image.Slice(stringOffset, bytes.Length));
            offset = stringOffset + bytes.Length;
            image[offset++] = 0;
            return DataAddress + checked((ulong)stringOffset);
        }

        private static void WriteProgramHeader(
            Span<byte> image,
            int offset,
            bool is64Bit,
            int fileOffset,
            ulong virtualAddress,
            int fileSize,
            uint flags)
        {
            WriteUInt32(image, offset, 1);
            if (is64Bit)
            {
                WriteUInt32(image, offset + 4, flags);
                WriteUInt64(image, offset + 8, checked((ulong)fileOffset));
                WriteUInt64(image, offset + 16, virtualAddress);
                WriteUInt64(image, offset + 24, virtualAddress);
                WriteUInt64(image, offset + 32, checked((ulong)fileSize));
                WriteUInt64(image, offset + 40, checked((ulong)fileSize));
                WriteUInt64(image, offset + 48, 0x1000);
            }
            else
            {
                WriteUInt32(image, offset + 4, checked((uint)fileOffset));
                WriteUInt32(image, offset + 8, checked((uint)virtualAddress));
                WriteUInt32(image, offset + 12, checked((uint)virtualAddress));
                WriteUInt32(image, offset + 16, checked((uint)fileSize));
                WriteUInt32(image, offset + 20, checked((uint)fileSize));
                WriteUInt32(image, offset + 24, flags);
                WriteUInt32(image, offset + 28, 0x1000);
            }
        }

        private static void WriteUInt16(Span<byte> destination, int offset, ushort value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(offset, 2), value);
        }

        private static void WriteUInt32(Span<byte> destination, int offset, uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset, 4), value);
        }

        private static void WriteUInt64(Span<byte> destination, int offset, ulong value)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(offset, 8), value);
        }
    }
}
