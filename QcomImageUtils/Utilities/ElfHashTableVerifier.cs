using System;
using QcomImageUtils.Constants;
using QcomImageUtils.Types;

namespace QcomImageUtils.Utilities;

internal static class ElfHashTableVerifier
{
    private const ulong PageSize = 4096;
    private const uint ProgramHeaderType = 6;

    public static void Verify(
        ReadOnlySpan<byte> image,
        ElfImageInfo elfInfo,
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo hashInfo,
        out QcomVerificationStatus status,
        out int expectedHashCount,
        out int verifiedHashCount,
        out int failedSegmentIndex,
        out string error)
    {
        status = QcomVerificationStatus.Invalid;
        expectedHashCount = 0;
        verifiedHashCount = 0;
        failedSegmentIndex = -1;
        error = string.Empty;

        if (!TryCountHashes(image, elfInfo, out expectedHashCount, out error))
            return;

        if (!TrySelectAlgorithm(hashInfo, expectedHashCount,
                out ImageHashAlgorithm algorithm, out int digestLength))
        {
            error = $"哈希表长度 {hashInfo.HashSize} 与 {expectedHashCount} 个 ELF 摘要不匹配";
            return;
        }

        if (!BinaryDataReader.IsRangeInside(hashInfo.HashOffset,
                checked((int)hashInfo.HashSize), hashSegment.Length))
        {
            error = "哈希表范围超出 Qualcomm 哈希段";
            return;
        }

        ReadOnlySpan<byte> table = hashSegment.Slice(
            hashInfo.HashOffset,
            checked((int)hashInfo.HashSize));
        int tableIndex = 0;
        Span<byte> actual = stackalloc byte[64];

        for (int segmentIndex = 0; segmentIndex < elfInfo.ProgramHeaderCount; segmentIndex++)
        {
            if (!ElfHashSegmentReader.TryGetProgramHeader(
                    image,
                    elfInfo,
                    segmentIndex,
                    out ElfProgramHeader header))
            {
                error = $"无法读取第 {segmentIndex} 个 ELF 程序头";
                failedSegmentIndex = segmentIndex;
                return;
            }

            uint pageMode = (header.Flags & ImageConstants.MiPbtFlagPageModeMask)
                            >> ImageConstants.MiPbtFlagPageModeShift;
            if (pageMode == ImageConstants.MiPbtPagedSegment)
            {
                if (!VerifyPagedSegment(image, elfInfo, header, segmentIndex, table,
                        algorithm, digestLength, actual, ref tableIndex,
                        ref verifiedHashCount, out error))
                {
                    failedSegmentIndex = segmentIndex;
                    return;
                }
            }
            else if (header.Type != ProgramHeaderType)
            {
                ReadOnlySpan<byte> expected = table.Slice(tableIndex * digestLength, digestLength);
                if (!VerifyNonPagedSegment(image, elfInfo, header, expected,
                        algorithm, actual, out error))
                {
                    failedSegmentIndex = segmentIndex;
                    return;
                }

                tableIndex++;
                verifiedHashCount++;
            }
        }

        if (tableIndex != expectedHashCount)
        {
            error = "ELF 摘要数量与哈希表不一致";
            return;
        }

        status = QcomVerificationStatus.Valid;
    }

    public static bool IsRangeAuthenticated(
        ReadOnlySpan<byte> image,
        ElfImageInfo elfInfo,
        int rangeOffset,
        int rangeLength)
    {
        if (rangeOffset < 0
            || rangeLength < 0
            || !BinaryDataReader.IsRangeInside(rangeOffset, rangeLength, image.Length))
        {
            return false;
        }

        ulong requestedOffset = (uint)rangeOffset;
        ulong requestedLength = (uint)rangeLength;
        for (int index = 0; index < elfInfo.ProgramHeaderCount; index++)
        {
            if (!ElfHashSegmentReader.TryGetProgramHeader(image, elfInfo, index,
                    out ElfProgramHeader header)
                || !ShouldHash(header))
            {
                continue;
            }

            ulong segmentOffset = header.FileOffset;
            ulong segmentLength = header.FileSize;
            uint pageMode = (header.Flags & ImageConstants.MiPbtFlagPageModeMask)
                            >> ImageConstants.MiPbtFlagPageModeShift;
            if (pageMode == ImageConstants.MiPbtPagedSegment)
            {
                ulong misalignment = header.VirtualAddress & (PageSize - 1);
                if (misalignment != 0)
                {
                    ulong skipped = PageSize - misalignment;
                    if (segmentLength < skipped || segmentOffset > ulong.MaxValue - skipped)
                        continue;
                    segmentOffset += skipped;
                    segmentLength -= skipped;
                }
            }

            if (requestedOffset >= segmentOffset
                && requestedLength <= segmentLength
                && requestedOffset - segmentOffset <= segmentLength - requestedLength)
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryCountHashes(
        ReadOnlySpan<byte> image,
        ElfImageInfo elfInfo,
        out int count,
        out string error)
    {
        count = 0;
        error = string.Empty;
        for (int index = 0; index < elfInfo.ProgramHeaderCount; index++)
        {
            if (!ElfHashSegmentReader.TryGetProgramHeader(image, elfInfo, index,
                    out ElfProgramHeader header))
            {
                error = $"无法读取第 {index} 个 ELF 程序头";
                return false;
            }

            uint pageMode = (header.Flags & ImageConstants.MiPbtFlagPageModeMask)
                            >> ImageConstants.MiPbtFlagPageModeShift;
            if (pageMode != ImageConstants.MiPbtPagedSegment)
            {
                if (header.Type != ProgramHeaderType)
                    count = checked(count + 1);
                continue;
            }

            ulong size = header.FileSize;
            ulong misalignment = header.VirtualAddress & (PageSize - 1);
            if (misalignment != 0)
            {
                ulong skipped = PageSize - misalignment;
                if (size < skipped)
                {
                    error = $"第 {index} 个分页 ELF 段小于页首对齐区域";
                    return false;
                }

                size -= skipped;
            }

            if ((size & (PageSize - 1)) != 0)
            {
                error = $"第 {index} 个分页 ELF 段长度未按 4 KiB 对齐";
                return false;
            }

            ulong pageCount = size / PageSize;
            if (pageCount > int.MaxValue - (uint)count)
            {
                error = "ELF 分页摘要数量超出支持范围";
                return false;
            }

            count += checked((int)pageCount);
        }

        return count > 0;
    }

    private static bool TrySelectAlgorithm(
        HashSegmentInfo info,
        int hashCount,
        out ImageHashAlgorithm algorithm,
        out int digestLength)
    {
        if (info.UsesSha384)
        {
            algorithm = ImageHashAlgorithm.Sha384;
            digestLength = 48;
            return (ulong)hashCount * (uint)digestLength == info.HashSize;
        }

        if ((ulong)hashCount * 32 == info.HashSize)
        {
            algorithm = ImageHashAlgorithm.Sha256;
            digestLength = 32;
            return true;
        }

        algorithm = ImageHashAlgorithm.Sha1;
        digestLength = 20;
        return (ulong)hashCount * (uint)digestLength == info.HashSize;
    }

    private static bool VerifyNonPagedSegment(
        ReadOnlySpan<byte> image,
        ElfImageInfo elfInfo,
        ElfProgramHeader header,
        ReadOnlySpan<byte> expected,
        ImageHashAlgorithm algorithm,
        Span<byte> actual,
        out string error)
    {
        if (!ShouldHash(header))
            return VerifyZeroDigest(expected, out error);

        uint segmentType = GetSegmentType(header.Flags);
        if (segmentType == ImageConstants.MiPbtPhdrSegment)
        {
            ulong tableLength = (ulong)elfInfo.ProgramHeaderCount * elfInfo.ProgramHeaderSize;
            if (!BinaryDataReader.IsRangeInside(0, (ulong)elfInfo.HeaderSize, image.Length)
                || !BinaryDataReader.IsRangeInside(
                    elfInfo.ProgramHeaderOffset,
                    tableLength,
                    image.Length))
            {
                error = "ELF 头或程序头表范围无效";
                return false;
            }

            ReadOnlySpan<byte> elfHeader = image.Slice(0, elfInfo.HeaderSize);
            ReadOnlySpan<byte> programHeaders = image.Slice(
                checked((int)elfInfo.ProgramHeaderOffset),
                checked((int)tableLength));
            CryptographicHash.Compute(algorithm, elfHeader, programHeaders, actual);
        }
        else
        {
            if (!BinaryDataReader.IsRangeInside(header.FileOffset, header.FileSize, image.Length))
            {
                error = "ELF 段范围超出镜像";
                return false;
            }

            CryptographicHash.Compute(
                algorithm,
                image.Slice(checked((int)header.FileOffset), checked((int)header.FileSize)),
                actual);
        }

        if (!FixedTimeEquals(expected, actual.Slice(0, expected.Length)))
        {
            error = "ELF 段摘要与哈希表不一致";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool VerifyPagedSegment(
        ReadOnlySpan<byte> image,
        ElfImageInfo elfInfo,
        ElfProgramHeader header,
        int segmentIndex,
        ReadOnlySpan<byte> table,
        ImageHashAlgorithm algorithm,
        int digestLength,
        Span<byte> actual,
        ref int tableIndex,
        ref int verifiedHashCount,
        out string error)
    {
        ulong segmentOffset = header.FileOffset;
        ulong segmentSize = header.FileSize;
        ulong misalignment = header.VirtualAddress & (PageSize - 1);
        if (misalignment != 0)
        {
            ulong skipped = PageSize - misalignment;
            if (segmentSize < skipped || segmentOffset > ulong.MaxValue - skipped)
            {
                error = $"第 {segmentIndex} 个分页 ELF 段偏移溢出";
                return false;
            }

            segmentOffset += skipped;
            segmentSize -= skipped;
        }

        if (!BinaryDataReader.IsRangeInside(segmentOffset, segmentSize, image.Length))
        {
            error = $"第 {segmentIndex} 个分页 ELF 段范围超出镜像";
            return false;
        }

        while (segmentSize > 0)
        {
            int hashLength = checked((int)Math.Min(segmentSize, PageSize));
            ReadOnlySpan<byte> expected = table.Slice(tableIndex * digestLength, digestLength);
            if (!ShouldHash(header))
            {
                if (!VerifyZeroDigest(expected, out error))
                    return false;
            }
            else
            {
                CryptographicHash.Compute(
                    algorithm,
                    image.Slice(checked((int)segmentOffset), hashLength),
                    actual);
                if (!FixedTimeEquals(expected, actual.Slice(0, digestLength)))
                {
                    error = $"第 {segmentIndex} 个分页 ELF 段摘要与哈希表不一致";
                    return false;
                }
            }

            tableIndex++;
            verifiedHashCount++;
            segmentOffset += (uint)hashLength;
            segmentSize -= (uint)hashLength;
        }

        error = string.Empty;
        return true;
    }

    private static bool ShouldHash(ElfProgramHeader header)
    {
        if (header.FileSize == 0 || GetSegmentType(header.Flags) == ImageConstants.MiPbtHashSegment)
            return false;

        uint accessType = (header.Flags & ImageConstants.MiPbtFlagAccessTypeMask)
                          >> ImageConstants.MiPbtFlagAccessTypeShift;
        return accessType is not (ImageConstants.MiPbtNotusedSegment or ImageConstants.MiPbtSharedSegment);
    }

    private static uint GetSegmentType(uint flags)
    {
        return (flags & ImageConstants.MiPbtFlagSegmentTypeMask)
               >> ImageConstants.MiPbtFlagSegmentTypeShift;
    }

    private static bool VerifyZeroDigest(ReadOnlySpan<byte> expected, out string error)
    {
        for (int index = 0; index < expected.Length; index++)
        {
            if (expected[index] == 0)
                continue;

            error = "无需加载的 ELF 段摘要不是零值";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
            return false;

        int difference = 0;
        for (int index = 0; index < left.Length; index++)
            difference |= left[index] ^ right[index];
        return difference == 0;
    }
}
