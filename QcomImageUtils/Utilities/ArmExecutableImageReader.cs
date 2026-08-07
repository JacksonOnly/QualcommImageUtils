using System.Buffers.Binary;
using System.Collections.Generic;

namespace QcomImageUtils.Utilities;

internal sealed class ArmExecutableImage(
    int imageOffset,
    int pointerSize,
    ushort machine,
    List<ArmExecutableSegment> segments)
{
    public int ImageOffset { get; } = imageOffset;
    public int PointerSize { get; } = pointerSize;
    public ushort Machine { get; } = machine;
    public List<ArmExecutableSegment> Segments { get; } = segments;
}

internal readonly struct ArmExecutableSegment(
    ulong fileOffset,
    ulong virtualAddress,
    ulong fileSize,
    uint flags)
{
    public ulong FileOffset { get; } = fileOffset;
    public ulong VirtualAddress { get; } = virtualAddress;
    public ulong FileSize { get; } = fileSize;
    public uint Flags { get; } = flags;
    public bool IsExecutable => (Flags & ArmExecutableImageReader.ExecutableFlag) != 0;
}

/// <summary>
/// Reads the load mapping shared by metadata and Firehose ARM analysis.
/// </summary>
internal static class ArmExecutableImageReader
{
    public const ushort ArmMachine = 40;
    public const ushort Arm64Machine = 183;
    public const uint ExecutableFlag = 1;
    public const uint SblCodeword = 0x844BDCD1;
    public const uint SblMagic = 0x73D71034;
    public const int SblHeaderSize = 0x50;

    private const uint LoadSegmentType = 1;
    private const int MaximumProgramHeaderCount = 4096;

    public static bool TryReadSblMbn(
        ReadOnlySpan<byte> image,
        out ArmExecutableImage executableImage)
    {
        executableImage = null!;
        if (image.Length < SblHeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(0, 4)) != SblCodeword
            || BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(4, 4)) != SblMagic)
        {
            return false;
        }

        uint sourceOffset = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(20, 4));
        uint destinationAddress = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(24, 4));
        uint imageSize = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(28, 4));
        uint codeSize = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(32, 4));
        uint bootConfiguration = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(60, 4));
        if (!TryDecodeSblArchitecture(bootConfiguration, out bool isArm64))
            return false;

        if (sourceOffset < SblHeaderSize
            || (sourceOffset & 3) != 0
            || destinationAddress is 0 or uint.MaxValue
            || codeSize == 0
            || codeSize > imageSize
            || !BinaryDataReader.IsRangeInside(sourceOffset, imageSize, image.Length)
            || (ulong)destinationAddress + codeSize > (ulong)uint.MaxValue + 1)
        {
            return false;
        }

        executableImage = new ArmExecutableImage(
            0,
            isArm64 ? sizeof(ulong) : sizeof(uint),
            isArm64 ? Arm64Machine : ArmMachine,
            [new ArmExecutableSegment(
                sourceOffset,
                destinationAddress,
                codeSize,
                ExecutableFlag)]);
        return true;
    }

    public static bool TryDecodeSblArchitecture(
        uint bootConfiguration,
        out bool isArm64)
    {
        uint architecture = bootConfiguration & 0xF;
        if (bootConfiguration == uint.MaxValue || architecture == 0)
        {
            isArm64 = false;
            return true;
        }
        if (architecture == 0xF)
        {
            isArm64 = true;
            return true;
        }

        isArm64 = false;
        return false;
    }

    public static bool TryReadElf(
        ReadOnlySpan<byte> image,
        int imageOffset,
        out ArmExecutableImage executableImage)
    {
        executableImage = null!;
        if (imageOffset < 0
            || !BinaryDataReader.IsRangeInside(imageOffset, 16, image.Length)
            || image[imageOffset] != 0x7F
            || image[imageOffset + 1] != (byte)'E'
            || image[imageOffset + 2] != (byte)'L'
            || image[imageOffset + 3] != (byte)'F'
            || image[imageOffset + 5] != 1
            || image[imageOffset + 6] != 1)
        {
            return false;
        }

        byte elfClass = image[imageOffset + 4];
        bool is64Bit;
        int minimumHeaderSize;
        int minimumProgramHeaderSize;
        ushort declaredHeaderSize;
        ulong programHeaderOffset;
        ushort programHeaderSize;
        ushort programHeaderCount;
        switch (elfClass)
        {
            case 1:
                is64Bit = false;
                minimumHeaderSize = 52;
                minimumProgramHeaderSize = 32;
                if (!BinaryDataReader.IsRangeInside(imageOffset, minimumHeaderSize, image.Length))
                    return false;
                programHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(
                    image.Slice(imageOffset + 28, 4));
                declaredHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 40, 2));
                programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 42, 2));
                programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 44, 2));
                break;
            case 2:
                is64Bit = true;
                minimumHeaderSize = 64;
                minimumProgramHeaderSize = 56;
                if (!BinaryDataReader.IsRangeInside(imageOffset, minimumHeaderSize, image.Length))
                    return false;
                programHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(
                    image.Slice(imageOffset + 32, 8));
                declaredHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 52, 2));
                programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 54, 2));
                programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(
                    image.Slice(imageOffset + 56, 2));
                break;
            default:
                return false;
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(image.Slice(imageOffset + 18, 2));
        if ((machine == ArmMachine && is64Bit)
            || (machine == Arm64Machine && !is64Bit))
        {
            return false;
        }

        if (declaredHeaderSize < minimumHeaderSize
            || !BinaryDataReader.IsRangeInside(imageOffset, declaredHeaderSize, image.Length)
            || programHeaderOffset < declaredHeaderSize
            || programHeaderCount == 0
            || programHeaderCount > MaximumProgramHeaderCount
            || programHeaderSize < minimumProgramHeaderSize
            || !TryAddImageOffset(imageOffset, programHeaderOffset, out ulong absoluteHeaderOffset))
        {
            return false;
        }

        ulong programHeaderTableLength = (ulong)programHeaderSize * programHeaderCount;
        if (!BinaryDataReader.IsRangeInside(
                absoluteHeaderOffset,
                programHeaderTableLength,
                image.Length))
        {
            return false;
        }

        var segments = new List<ArmExecutableSegment>();
        for (int index = 0; index < programHeaderCount; index++)
        {
            ulong headerOffset = absoluteHeaderOffset + (ulong)index * programHeaderSize;
            ReadOnlySpan<byte> header = image.Slice(checked((int)headerOffset), programHeaderSize);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(0, 4)) != LoadSegmentType)
                continue;

            uint flags;
            ulong segmentOffset;
            ulong virtualAddress;
            ulong fileSize;
            if (is64Bit)
            {
                flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(4, 4));
                segmentOffset = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(8, 8));
                virtualAddress = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(16, 8));
                fileSize = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(32, 8));
            }
            else
            {
                segmentOffset = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(4, 4));
                virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(8, 4));
                fileSize = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(16, 4));
                flags = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(24, 4));
            }

            if (fileSize == 0)
                continue;
            if (virtualAddress > ulong.MaxValue - fileSize
                || (!is64Bit && virtualAddress + fileSize > (ulong)uint.MaxValue + 1)
                || !TryAddImageOffset(imageOffset, segmentOffset, out ulong absoluteSegmentOffset)
                || !BinaryDataReader.IsRangeInside(absoluteSegmentOffset, fileSize, image.Length))
            {
                return false;
            }

            segments.Add(new ArmExecutableSegment(
                absoluteSegmentOffset,
                virtualAddress,
                fileSize,
                flags));
        }

        if (segments.Count == 0)
            return false;

        executableImage = new ArmExecutableImage(
            imageOffset,
            is64Bit ? sizeof(ulong) : sizeof(uint),
            machine,
            segments);
        return true;
    }

    public static bool TryMapVirtualAddress(
        ArmExecutableImage executableImage,
        ulong virtualAddress,
        out ulong fileOffset,
        out ulong available)
    {
        for (int index = 0; index < executableImage.Segments.Count; index++)
        {
            ArmExecutableSegment segment = executableImage.Segments[index];
            if (virtualAddress < segment.VirtualAddress)
                continue;
            ulong localOffset = virtualAddress - segment.VirtualAddress;
            if (localOffset >= segment.FileSize)
                continue;

            fileOffset = segment.FileOffset + localOffset;
            available = segment.FileSize - localOffset;
            return true;
        }

        fileOffset = 0;
        available = 0;
        return false;
    }

    public static bool TryMapVirtualRange(
        ArmExecutableImage executableImage,
        ulong virtualAddress,
        ulong length,
        out ulong fileOffset)
    {
        if (TryMapVirtualAddress(executableImage, virtualAddress, out fileOffset, out ulong available)
            && length <= available)
        {
            return true;
        }

        fileOffset = 0;
        return false;
    }

    public static bool TryReadPointer(
        ReadOnlySpan<byte> image,
        ulong fileOffset,
        int pointerSize,
        out ulong value)
    {
        value = 0;
        if (pointerSize is not (sizeof(uint) or sizeof(ulong))
            || !BinaryDataReader.IsRangeInside(
                fileOffset,
                (ulong)pointerSize,
                image.Length))
        {
            return false;
        }

        ReadOnlySpan<byte> data = image.Slice(checked((int)fileOffset), pointerSize);
        value = pointerSize == sizeof(ulong)
            ? BinaryPrimitives.ReadUInt64LittleEndian(data)
            : BinaryPrimitives.ReadUInt32LittleEndian(data);
        return true;
    }

    public static bool IsExecutableAddress(
        ArmExecutableImage executableImage,
        ulong address)
    {
        ulong normalizedAddress = executableImage.Machine == ArmMachine
            ? address & ~1UL
            : address;
        for (int index = 0; index < executableImage.Segments.Count; index++)
        {
            ArmExecutableSegment segment = executableImage.Segments[index];
            if (segment.IsExecutable
                && normalizedAddress >= segment.VirtualAddress
                && normalizedAddress - segment.VirtualAddress < segment.FileSize)
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryAddImageOffset(
        int imageOffset,
        ulong relativeOffset,
        out ulong absoluteOffset)
    {
        ulong baseOffset = checked((uint)imageOffset);
        if (relativeOffset > ulong.MaxValue - baseOffset)
        {
            absoluteOffset = 0;
            return false;
        }

        absoluteOffset = baseOffset + relativeOffset;
        return true;
    }
}
