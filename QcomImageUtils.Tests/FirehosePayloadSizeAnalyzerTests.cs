using System.Buffers.Binary;
using System.Text;
using QcomImageUtils.Models;
using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class FirehosePayloadSizeAnalyzerTests
{
    private const int CodeOffset = 0x200;
    private const int DataOffset = 0x400;
    private const ulong CodeAddress = 0x100000;
    private const ulong DataAddress = 0x200000;

    [Fact]
    public void TryAnalyze_Arm64ConditionalSupportedValue_ReturnsOneMiB()
    {
        byte[] image = CreateElf(is64Bit: true);
        ulong stringAddress = WriteString(
            image,
            "MaxPayloadSizeToTargetInBytesSupported");
        const ulong loggerAddress = CodeAddress + 0x100;

        WriteUInt32(image, CodeOffset + 0x00, EncodeArm64Adrp(CodeAddress, stringAddress, 1));
        WriteUInt32(image, CodeOffset + 0x04, EncodeArm64Add(stringAddress, 1));
        WriteUInt32(image, CodeOffset + 0x08, 0x320C03E8u); // MOV W8, #0x100000
        WriteUInt32(image, CodeOffset + 0x0C, EncodeArm64Csel(2, 8, 31, condition: 1));
        WriteUInt32(
            image,
            CodeOffset + 0x10,
            EncodeArm64BranchLink(CodeAddress + 0x10, loggerAddress));
        WriteUInt32(image, CodeOffset + 0x14, 0xD65F03C0u);
        WriteUInt32(image, CodeOffset + 0x100, 0xD65F03C0u);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(0x100000UL, result.MaxPayloadSizeToTargetInBytesSupported);
        Assert.Empty(result.Commands);
    }

    [Fact]
    public void TryAnalyze_Arm64ConstantReturnHelper_ReturnsTwoMiB()
    {
        byte[] image = CreateElf(is64Bit: true);
        ulong stringAddress = WriteString(
            image,
            "NAK: MaxPayloadSizeToTargetInBytes sent by host %d larger than supported %d");
        const ulong helperAddress = CodeAddress + 0x100;
        const ulong loggerAddress = CodeAddress + 0x120;

        WriteUInt32(
            image,
            CodeOffset + 0x00,
            EncodeArm64BranchLink(CodeAddress, helperAddress));
        WriteUInt32(image, CodeOffset + 0x04, EncodeArm64WordExtension(3, 0));
        WriteUInt32(image, CodeOffset + 0x08, EncodeArm64Adrp(CodeAddress + 0x08, stringAddress, 1));
        WriteUInt32(image, CodeOffset + 0x0C, EncodeArm64Add(stringAddress, 1));
        WriteUInt32(
            image,
            CodeOffset + 0x10,
            EncodeArm64BranchLink(CodeAddress + 0x10, loggerAddress));
        WriteUInt32(image, CodeOffset + 0x14, 0xD65F03C0u);
        WriteUInt32(
            image,
            CodeOffset + 0x100,
            EncodeArm64MoveWide(0, 0x20, halfword: 1));
        WriteUInt32(image, CodeOffset + 0x104, 0xD65F03C0u);
        WriteUInt32(image, CodeOffset + 0x120, 0xD65F03C0u);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(0x200000UL, result.MaxPayloadSizeToTargetInBytesSupported);
    }

    [Fact]
    public void TryAnalyze_Arm64StructFieldValue_ReturnsOneMiB()
    {
        byte[] image = CreateElf(is64Bit: true);
        ulong stringAddress = WriteString(
            image,
            "MaxPayloadSizeToTargetInBytesSupported");
        const ulong loggerAddress = CodeAddress + 0x120;

        WriteUInt32(image, CodeOffset + 0x00, 0x320C03EFu); // MOV W15, #0x100000
        WriteUInt32(image, CodeOffset + 0x04, 0xF9081A6Fu); // STR X15, [X19,#0x1030]
        WriteUInt32(image, CodeOffset + 0x08, 0xD65F03C0u);
        WriteUInt32(image, CodeOffset + 0x40, 0xF9481AC3u); // LDR X3, [X22,#0x1030]
        WriteUInt32(image, CodeOffset + 0x44, EncodeArm64Adrp(CodeAddress + 0x44, stringAddress, 2));
        WriteUInt32(image, CodeOffset + 0x48, EncodeArm64Add(stringAddress, 2));
        WriteUInt32(
            image,
            CodeOffset + 0x4C,
            EncodeArm64BranchLink(CodeAddress + 0x4C, loggerAddress));
        WriteUInt32(image, CodeOffset + 0x50, 0xD65F03C0u);
        WriteUInt32(image, CodeOffset + 0x120, 0xD65F03C0u);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(0x100000UL, result.MaxPayloadSizeToTargetInBytesSupported);
    }

    [Fact]
    public void TryAnalyze_Arm32MoveWideSupportedValue_ReturnsOneMiB()
    {
        byte[] image = CreateElf(is64Bit: false);
        ulong stringAddress = WriteString(
            image,
            "MaxPayloadSizeToTargetInBytesSupported");
        const ulong loggerAddress = CodeAddress + 0x80;

        WriteUInt32(image, CodeOffset + 0x00, 0xE59F1038u); // LDR R1, [PC,#0x38]
        WriteUInt32(image, CodeOffset + 0x04, EncodeArm32MoveWide(2, 0, isHighHalf: false));
        WriteUInt32(image, CodeOffset + 0x08, EncodeArm32MoveWide(2, 0x10, isHighHalf: true));
        WriteUInt32(
            image,
            CodeOffset + 0x0C,
            EncodeArm32BranchLink(CodeAddress + 0x0C, loggerAddress));
        WriteUInt32(image, CodeOffset + 0x10, 0xE12FFF1Eu);
        WriteUInt32(image, CodeOffset + 0x40, checked((uint)stringAddress));
        WriteUInt32(image, CodeOffset + 0x80, 0xE12FFF1Eu);

        var analyzer = new FirehoseCommandAnalyzer();

        bool success = analyzer.TryAnalyze(image, out FirehoseCommandAnalysisResult result);

        Assert.True(success, result.ErrorMessage);
        Assert.Equal(0x100000UL, result.MaxPayloadSizeToTargetInBytesSupported);
    }

    [Fact]
    public void TryDecodeArm64ConditionalSelect_ReturnsAllRegisters()
    {
        uint instruction = EncodeArm64Csel(2, 8, 31, condition: 1);

        bool success = ArmInstructionDecoder.TryDecodeArm64ConditionalSelect(
            instruction,
            out int destination,
            out int firstSource,
            out int secondSource);

        Assert.True(success);
        Assert.Equal(2, destination);
        Assert.Equal(8, firstSource);
        Assert.Equal(31, secondSource);
    }

    [Fact]
    public void TryDecodeArm64MoveBitmaskImmediate_DecodesMovAlias()
    {
        bool success = ArmInstructionDecoder.TryDecodeArm64MoveBitmaskImmediate(
            0x320C03E3u,
            out int destination,
            out ulong value);

        Assert.True(success);
        Assert.Equal(3, destination);
        Assert.Equal(0x100000UL, value);
    }

    [Fact]
    public void TryDecodeArm64WordExtension_DecodesSxtwAlias()
    {
        bool success = ArmInstructionDecoder.TryDecodeArm64WordExtension(
            EncodeArm64WordExtension(3, 0),
            out int destination,
            out int source,
            out bool signExtends);

        Assert.True(success);
        Assert.Equal(3, destination);
        Assert.Equal(0, source);
        Assert.True(signExtends);
    }

    [Fact]
    public void TryDecodeArm64UnsignedImmediateTransfer_DecodesStructLoad()
    {
        bool success = ArmInstructionDecoder.TryDecodeArm64UnsignedImmediateTransfer(
            0xF9481AC3u,
            out int valueRegister,
            out int baseRegister,
            out ulong offset,
            out bool isLoad);

        Assert.True(success);
        Assert.Equal(3, valueRegister);
        Assert.Equal(22, baseRegister);
        Assert.Equal(0x1030UL, offset);
        Assert.True(isLoad);
    }

    [Fact]
    public void TryDecodeThumbLogicalShiftLeftImmediate_DecodesPayloadCalculation()
    {
        const ushort instruction = 0x020B; // LSLS R3, R1, #8

        bool success = ArmInstructionDecoder.TryDecodeThumbLogicalShiftLeftImmediate(
            instruction,
            out int destination,
            out int source,
            out int shift);

        Assert.True(success);
        Assert.Equal(3, destination);
        Assert.Equal(1, source);
        Assert.Equal(8, shift);
    }

    [Fact]
    public void ThumbLegacyPayloadInstructions_DecodeExpectedValues()
    {
        Assert.True(ArmInstructionDecoder.TryDecodeThumbMoveImmediate(
            0xF44F,
            0x5180,
            out int constantRegister,
            out uint constant));
        Assert.Equal(1, constantRegister);
        Assert.Equal(0x1000u, constant);

        Assert.True(ArmInstructionDecoder.TryDecodeThumbAddress(
            0xA793,
            0,
            0x0802CF7A,
            out int addressRegister,
            out ulong address,
            out int instructionSize,
            out bool isLiteral));
        Assert.Equal(7, addressRegister);
        Assert.Equal(0x0802D1C8UL, address);
        Assert.Equal(sizeof(ushort), instructionSize);
        Assert.False(isLiteral);
    }

    private static byte[] CreateElf(bool is64Bit)
    {
        const int codeSize = 0x200;
        const int dataSize = 0x400;
        int headerSize = is64Bit ? 64 : 52;
        int programHeaderSize = is64Bit ? 56 : 32;
        var image = new byte[DataOffset + dataSize];

        image[0] = 0x7F;
        image[1] = (byte)'E';
        image[2] = (byte)'L';
        image[3] = (byte)'F';
        image[4] = is64Bit ? (byte)2 : (byte)1;
        image[5] = 1;
        image[6] = 1;
        WriteUInt16(image, 16, 2);
        WriteUInt16(image, 18, is64Bit ? (ushort)183 : (ushort)40);
        WriteUInt32(image, 20, 1);

        if (is64Bit)
        {
            WriteUInt64(image, 24, CodeAddress);
            WriteUInt64(image, 32, checked((ulong)headerSize));
            WriteUInt16(image, 52, checked((ushort)headerSize));
            WriteUInt16(image, 54, checked((ushort)programHeaderSize));
            WriteUInt16(image, 56, 2);
        }
        else
        {
            WriteUInt32(image, 24, checked((uint)CodeAddress));
            WriteUInt32(image, 28, checked((uint)headerSize));
            WriteUInt16(image, 40, checked((ushort)headerSize));
            WriteUInt16(image, 42, checked((ushort)programHeaderSize));
            WriteUInt16(image, 44, 2);
        }

        WriteProgramHeader(
            image,
            headerSize,
            is64Bit,
            CodeOffset,
            CodeAddress,
            codeSize,
            flags: 5);
        WriteProgramHeader(
            image,
            headerSize + programHeaderSize,
            is64Bit,
            DataOffset,
            DataAddress,
            dataSize,
            flags: 6);
        return image;
    }

    private static void WriteProgramHeader(
        byte[] image,
        int offset,
        bool is64Bit,
        int fileOffset,
        ulong virtualAddress,
        int size,
        uint flags)
    {
        WriteUInt32(image, offset, 1);
        if (is64Bit)
        {
            WriteUInt32(image, offset + 4, flags);
            WriteUInt64(image, offset + 8, checked((ulong)fileOffset));
            WriteUInt64(image, offset + 16, virtualAddress);
            WriteUInt64(image, offset + 24, virtualAddress);
            WriteUInt64(image, offset + 32, checked((ulong)size));
            WriteUInt64(image, offset + 40, checked((ulong)size));
            WriteUInt64(image, offset + 48, 0x1000);
        }
        else
        {
            WriteUInt32(image, offset + 4, checked((uint)fileOffset));
            WriteUInt32(image, offset + 8, checked((uint)virtualAddress));
            WriteUInt32(image, offset + 12, checked((uint)virtualAddress));
            WriteUInt32(image, offset + 16, checked((uint)size));
            WriteUInt32(image, offset + 20, checked((uint)size));
            WriteUInt32(image, offset + 24, flags);
            WriteUInt32(image, offset + 28, 0x1000);
        }
    }

    private static ulong WriteString(byte[] image, string value)
    {
        byte[] text = Encoding.ASCII.GetBytes(value);
        text.CopyTo(image, DataOffset);
        image[DataOffset + text.Length] = 0;
        return DataAddress;
    }

    private static uint EncodeArm64Adrp(
        ulong instructionAddress,
        ulong targetAddress,
        int register)
    {
        long pageDelta = checked((long)(targetAddress >> 12) - (long)(instructionAddress >> 12));
        ulong encoded = unchecked((ulong)pageDelta) & 0x1FFFFFul;
        return 0x90000000u
               | checked((uint)(encoded & 3) << 29)
               | checked((uint)(encoded >> 2) << 5)
               | checked((uint)register);
    }

    private static uint EncodeArm64Add(ulong targetAddress, int register) =>
        0x91000000u
        | checked((uint)(targetAddress & 0xFFF) << 10)
        | checked((uint)register << 5)
        | checked((uint)register);

    private static uint EncodeArm64MoveWide(int register, ushort immediate, int halfword) =>
        0x52800000u
        | checked((uint)halfword << 21)
        | checked((uint)immediate << 5)
        | checked((uint)register);

    private static uint EncodeArm64Move(int destination, int source) =>
        0xAA0003E0u | checked((uint)source << 16) | checked((uint)destination);

    private static uint EncodeArm64WordExtension(int destination, int source) =>
        0x93407C00u | checked((uint)source << 5) | checked((uint)destination);

    private static uint EncodeArm64Csel(
        int destination,
        int firstSource,
        int secondSource,
        int condition) =>
        0x9A800000u
        | checked((uint)secondSource << 16)
        | checked((uint)condition << 12)
        | checked((uint)firstSource << 5)
        | checked((uint)destination);

    private static uint EncodeArm64BranchLink(ulong instructionAddress, ulong targetAddress)
    {
        long offset = checked((long)targetAddress - (long)instructionAddress);
        return 0x94000000u | (unchecked((uint)(offset >> 2)) & 0x03FFFFFFu);
    }

    private static uint EncodeArm32MoveWide(int register, ushort immediate, bool isHighHalf) =>
        (isHighHalf ? 0xE3400000u : 0xE3000000u)
        | ((uint)immediate & 0xF000u) << 4
        | checked((uint)register << 12)
        | ((uint)immediate & 0x0FFFu);

    private static uint EncodeArm32BranchLink(ulong instructionAddress, ulong targetAddress)
    {
        long offset = checked((long)targetAddress - (long)(instructionAddress + 8));
        return 0xEB000000u | (unchecked((uint)(offset >> 2)) & 0x00FFFFFFu);
    }

    private static void WriteUInt16(byte[] image, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(offset, sizeof(ushort)), value);

    private static void WriteUInt32(byte[] image, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(offset, sizeof(uint)), value);

    private static void WriteUInt64(byte[] image, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(offset, sizeof(ulong)), value);
}
