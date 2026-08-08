using QcomImageUtils.Types;

namespace QcomImageUtils.Utilities;

internal static class BootMemoryAnalyzer
{
    private const ulong LiteMinimumMemorySize = 16 * 1024;
    private const ulong DdrMinimumMemorySize = 1024 * 1024;
    private const uint ReadWriteFlags = 4 | 2;

    private static ReadOnlySpan<byte> Ddr4Marker => "DRAM Vref DQ CDC perbit"u8;
    private static ReadOnlySpan<byte> Ddr5Marker => "DRAM_LP5"u8;

    public static void Analyze(
        ReadOnlySpan<byte> image,
        int? elfImageOffset,
        out BootMemoryType bootMemoryType,
        out DramGeneration dramGeneration)
    {
        bootMemoryType = BootMemoryType.Unknown;

        bool hasDdr4Marker;
        bool hasDdr5Marker;
        if (elfImageOffset.HasValue
            && ArmExecutableImageReader.TryReadElf(
                image,
                elfImageOffset.Value,
                out ArmExecutableImage executableImage))
        {
            bootMemoryType = ClassifyBootMemory(executableImage.MemoryOnlySegments);
            hasDdr4Marker = ContainsMarker(image, executableImage.Segments, Ddr4Marker);
            hasDdr5Marker = ContainsMarker(image, executableImage.Segments, Ddr5Marker);
        }
        else
        {
            hasDdr4Marker = image.IndexOf(Ddr4Marker) >= 0;
            hasDdr5Marker = image.IndexOf(Ddr5Marker) >= 0;
        }

        dramGeneration = (hasDdr4Marker, hasDdr5Marker) switch
        {
            (true, false) => DramGeneration.Ddr4,
            (false, true) => DramGeneration.Ddr5,
            (true, true) => DramGeneration.Combo,
            _ => DramGeneration.Unknown
        };
    }

    private static BootMemoryType ClassifyBootMemory(
        IReadOnlyList<ArmExecutableSegment> segments)
    {
        BootMemoryType result = BootMemoryType.Unknown;
        for (int index = 0; index < segments.Count; index++)
        {
            ArmExecutableSegment segment = segments[index];
            if (segment.Flags != ReadWriteFlags)
                continue;
            if (segment.MemorySize > DdrMinimumMemorySize)
                return BootMemoryType.Ddr;
            if (segment.MemorySize > LiteMinimumMemorySize
                && segment.MemorySize < DdrMinimumMemorySize)
            {
                result = BootMemoryType.Lite;
            }
        }

        return result;
    }

    private static bool ContainsMarker(
        ReadOnlySpan<byte> image,
        IReadOnlyList<ArmExecutableSegment> segments,
        ReadOnlySpan<byte> marker)
    {
        for (int index = 0; index < segments.Count; index++)
        {
            ArmExecutableSegment segment = segments[index];
            ReadOnlySpan<byte> data = image.Slice(
                checked((int)segment.FileOffset),
                checked((int)segment.FileSize));
            if (data.IndexOf(marker) >= 0)
                return true;
        }

        return false;
    }
}
