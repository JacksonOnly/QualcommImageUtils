using System.Buffers.Binary;
using System.Security.Cryptography;
using QcomImageUtils.Constants;
using QcomImageUtils.Types;
using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class ElfHashTableVerifierTests
{
    private const int ProgramHeaderOffset = 64;
    private const int ProgramHeaderSize = 56;
    private const int PageSize = 4096;

    [Fact]
    public void Verify_PagedSegmentBeforeFirstPage_HashesCompletePage()
    {
        const int segmentOffset = 256;
        var image = new byte[segmentOffset + PageSize];
        for (int index = 0; index < PageSize; index++)
            image[segmentOffset + index] = (byte)((index * 31 + 7) & byte.MaxValue);
        WriteProgramHeader(image, segmentOffset, 0x1000, PageSize);

        byte[] hashTable = SHA256.HashData(image.AsSpan(segmentOffset, PageSize));
        ElfImageInfo elfInfo = CreateElfInfo();
        HashSegmentInfo hashInfo = CreateHashInfo();

        ElfHashTableVerifier.Verify(
            image,
            elfInfo,
            hashTable,
            hashInfo,
            out QcomVerificationStatus status,
            out int expectedHashCount,
            out int verifiedHashCount,
            out int failedSegmentIndex,
            out string error);

        Assert.Equal(QcomVerificationStatus.Valid, status);
        Assert.Equal(1, expectedHashCount);
        Assert.Equal(1, verifiedHashCount);
        Assert.Equal(-1, failedSegmentIndex);
        Assert.Empty(error);

        image[segmentOffset + PageSize - 1] ^= 0xFF;
        ElfHashTableVerifier.Verify(
            image,
            elfInfo,
            hashTable,
            hashInfo,
            out status,
            out _,
            out _,
            out failedSegmentIndex,
            out error);

        Assert.Equal(QcomVerificationStatus.Invalid, status);
        Assert.Equal(0, failedSegmentIndex);
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Verify_PagedSegmentAlignmentOffsetOverflows_ReturnsInvalid()
    {
        var image = new byte[PageSize * 2];
        WriteProgramHeader(
            image,
            ulong.MaxValue - 2047,
            0x1800,
            PageSize + 2048);
        byte[] hashTable = SHA256.HashData(ReadOnlySpan<byte>.Empty);

        ElfHashTableVerifier.Verify(
            image,
            CreateElfInfo(),
            hashTable,
            CreateHashInfo(),
            out QcomVerificationStatus status,
            out _,
            out _,
            out int failedSegmentIndex,
            out string error);

        Assert.Equal(QcomVerificationStatus.Invalid, status);
        Assert.Equal(0, failedSegmentIndex);
        Assert.Contains("偏移溢出", error, StringComparison.Ordinal);
    }

    private static ElfImageInfo CreateElfInfo()
    {
        return new ElfImageInfo
        {
            Is64Bit = true,
            HeaderSize = ProgramHeaderOffset,
            ProgramHeaderOffset = ProgramHeaderOffset,
            ProgramHeaderSize = ProgramHeaderSize,
            ProgramHeaderCount = 1
        };
    }

    private static HashSegmentInfo CreateHashInfo()
    {
        return new HashSegmentInfo
        {
            HashOffset = 0,
            HashSize = 32
        };
    }

    private static void WriteProgramHeader(
        Span<byte> image,
        ulong fileOffset,
        ulong virtualAddress,
        ulong fileSize)
    {
        Span<byte> header = image.Slice(ProgramHeaderOffset, ProgramHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header, 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            header.Slice(4),
            ImageConstants.MiPbtElfAmssPagedRoSegment);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(8), fileOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(16), virtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(32), fileSize);
    }
}
