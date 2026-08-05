using System.Buffers.Binary;
using QcomImageUtils.Constants;

namespace QcomImageUtils.Utilities;

internal struct ElfImageInfo
{
    public bool Is64Bit;
    public int HeaderSize;
    public ulong ProgramHeaderOffset;
    public ushort ProgramHeaderSize;
    public ushort ProgramHeaderCount;
    public int HashSegmentIndex;
    public int HashSegmentOffset;
    public int HashSegmentLength;
}

internal struct ElfProgramHeader
{
    public uint Type;
    public uint Flags;
    public ulong FileOffset;
    public ulong VirtualAddress;
    public ulong FileSize;
}

internal enum ElfHashSegmentReadStatus
{
    NotElf,
    InvalidElf,
    HashSegmentNotFound,
    Success
}

/// <summary>
/// 验证 ELF32/ELF64 程序头并定位 Qualcomm 哈希段。
/// </summary>
internal static class ElfHashSegmentReader
{
    private const int Elf32HeaderSize = 52;
    private const int Elf64HeaderSize = 64;
    private const int Elf32ProgramHeaderSize = 32;
    private const int Elf64ProgramHeaderSize = 56;

    public static bool TryGetHashSegment(
        ReadOnlySpan<byte> image,
        out ReadOnlySpan<byte> hashSegment)
    {
        return TryGetHashSegment(image, out hashSegment, out _);
    }

    public static bool TryGetHashSegment(
        ReadOnlySpan<byte> image,
        out ReadOnlySpan<byte> hashSegment,
        out ElfImageInfo info)
    {
        return TryGetHashSegment(image, out hashSegment, out info, out _);
    }

    public static bool TryGetHashSegment(
        ReadOnlySpan<byte> image,
        out ReadOnlySpan<byte> hashSegment,
        out ElfImageInfo info,
        out ElfHashSegmentReadStatus status)
    {
        hashSegment = default;
        info = default;
        if (image.Length < 16
            || image[0] != 0x7F
            || image[1] != (byte)'E'
            || image[2] != (byte)'L'
            || image[3] != (byte)'F'
            || image[5] != 1
            || image[6] != 1)
        {
            status = ElfHashSegmentReadStatus.NotElf;
            return false;
        }

        bool success;
        bool structureValid;
        switch (image[4])
        {
            case 1:
                success = TryGetHashSegment32(
                    image,
                    out hashSegment,
                    out info,
                    out structureValid);
                break;
            case 2:
                success = TryGetHashSegment64(
                    image,
                    out hashSegment,
                    out info,
                    out structureValid);
                break;
            default:
                status = ElfHashSegmentReadStatus.NotElf;
                return false;
        }

        status = success
            ? ElfHashSegmentReadStatus.Success
            : structureValid
                ? ElfHashSegmentReadStatus.HashSegmentNotFound
                : ElfHashSegmentReadStatus.InvalidElf;
        return success;
    }

    public static bool TryGetProgramHeader(
        ReadOnlySpan<byte> image,
        ElfImageInfo info,
        int index,
        out ElfProgramHeader programHeader)
    {
        programHeader = default;
        if ((uint)index >= info.ProgramHeaderCount)
            return false;

        ulong offset = info.ProgramHeaderOffset + (ulong)index * info.ProgramHeaderSize;
        if (!BinaryDataReader.IsRangeInside(offset, info.ProgramHeaderSize, image.Length))
            return false;

        ReadOnlySpan<byte> header = image.Slice(checked((int)offset), info.ProgramHeaderSize);
        programHeader.Type = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(0, 4));
        if (info.Is64Bit)
        {
            programHeader.Flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(4, 4));
            programHeader.FileOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(8, 8));
            programHeader.VirtualAddress = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(16, 8));
            programHeader.FileSize = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(32, 8));
        }
        else
        {
            programHeader.FileOffset = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(4, 4));
            programHeader.VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8, 4));
            programHeader.FileSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(16, 4));
            programHeader.Flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(24, 4));
        }

        return true;
    }

    private static bool TryGetHashSegment32(
        ReadOnlySpan<byte> image,
        out ReadOnlySpan<byte> hashSegment,
        out ElfImageInfo info,
        out bool structureValid)
    {
        hashSegment = default;
        info = default;
        structureValid = false;
        if (image.Length < Elf32HeaderSize)
            return false;

        uint programHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(28, 4));
        ushort headerSize = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(40, 2));
        ushort programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(42, 2));
        ushort programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(44, 2));
        if (headerSize < Elf32HeaderSize
            || headerSize > image.Length
            || programHeaderSize < Elf32ProgramHeaderSize)
            return false;

        return TryFindHashSegment(
            image,
            headerSize,
            programHeaderOffset,
            programHeaderSize,
            programHeaderCount,
            flagsOffset: 24,
            fileOffsetOffset: 4,
            fileSizeOffset: 16,
            is64Bit: false,
            out hashSegment,
            out info,
            out structureValid);
    }

    private static bool TryGetHashSegment64(
        ReadOnlySpan<byte> image,
        out ReadOnlySpan<byte> hashSegment,
        out ElfImageInfo info,
        out bool structureValid)
    {
        hashSegment = default;
        info = default;
        structureValid = false;
        if (image.Length < Elf64HeaderSize)
            return false;

        ulong programHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(image.Slice(32, 8));
        ushort headerSize = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(52, 2));
        ushort programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(54, 2));
        ushort programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(56, 2));
        if (headerSize < Elf64HeaderSize
            || headerSize > image.Length
            || programHeaderSize < Elf64ProgramHeaderSize)
            return false;

        return TryFindHashSegment(
            image,
            headerSize,
            programHeaderOffset,
            programHeaderSize,
            programHeaderCount,
            flagsOffset: 4,
            fileOffsetOffset: 8,
            fileSizeOffset: 32,
            is64Bit: true,
            out hashSegment,
            out info,
            out structureValid);
    }

    private static bool TryFindHashSegment(
        ReadOnlySpan<byte> image,
        int headerSize,
        ulong programHeaderOffset,
        ushort programHeaderSize,
        ushort programHeaderCount,
        int flagsOffset,
        int fileOffsetOffset,
        int fileSizeOffset,
        bool is64Bit,
        out ReadOnlySpan<byte> hashSegment,
        out ElfImageInfo info,
        out bool structureValid)
    {
        hashSegment = default;
        info = default;
        structureValid = false;
        if (programHeaderCount == 0 || programHeaderCount > ImageConstants.MaxPhdrCount)
            return false;

        ulong tableLength = (ulong)programHeaderSize * programHeaderCount;
        if (!BinaryDataReader.IsRangeInside(programHeaderOffset, tableLength, image.Length))
            return false;

        for (uint index = 0; index < programHeaderCount; index++)
        {
            ulong headerOffset = programHeaderOffset + index * programHeaderSize;
            ReadOnlySpan<byte> header = image.Slice(checked((int)headerOffset), programHeaderSize);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(flagsOffset, 4));
            uint segmentType = (flags & ImageConstants.MiPbtFlagSegmentTypeMask)
                               >> ImageConstants.MiPbtFlagSegmentTypeShift;
            if (segmentType != ImageConstants.MiPbtHashSegment)
                continue;

            ulong fileOffset = is64Bit
                ? BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(fileOffsetOffset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(fileOffsetOffset, 4));
            ulong fileSize = is64Bit
                ? BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(fileSizeOffset, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(fileSizeOffset, 4));
            if (fileSize == 0 || !BinaryDataReader.IsRangeInside(fileOffset, fileSize, image.Length))
                return false;

            hashSegment = image.Slice(checked((int)fileOffset), checked((int)fileSize));
            info = new ElfImageInfo
            {
                Is64Bit = is64Bit,
                HeaderSize = headerSize,
                ProgramHeaderOffset = programHeaderOffset,
                ProgramHeaderSize = programHeaderSize,
                ProgramHeaderCount = programHeaderCount,
                HashSegmentIndex = checked((int)index),
                HashSegmentOffset = checked((int)fileOffset),
                HashSegmentLength = checked((int)fileSize)
            };
            structureValid = true;
            return true;
        }

        structureValid = true;
        return false;
    }
}
