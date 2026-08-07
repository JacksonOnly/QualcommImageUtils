using System;
using System.Globalization;
using System.Text;
using QcomImageUtils.Models;

namespace QcomImageUtils.Utilities;

internal static partial class ImageMetadataExtractor
{
    private const string QcVersionKey = "QC_IMAGE_VERSION_STRING=";
    private const string OemVersionKey = "OEM_IMAGE_VERSION_STRING=";
    private const string ImageVariantKey = "IMAGE_VARIANT_STRING=";
    private const string BuildDateFormat = "Binary build date: %s @ %s";
    private const ushort ArmMachine = ArmExecutableImageReader.ArmMachine;
    private const ushort Arm64Machine = ArmExecutableImageReader.Arm64Machine;

    private static readonly byte[] QcVersionPrefix = Encoding.ASCII.GetBytes(QcVersionKey);
    private static readonly byte[] OemVersionPrefix = Encoding.ASCII.GetBytes(OemVersionKey);
    private static readonly byte[] ImageVariantPrefix = Encoding.ASCII.GetBytes(ImageVariantKey);
    private static readonly byte[] BuildDatePrefix = Encoding.ASCII.GetBytes(BuildDateFormat + "\0");
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
    private static readonly string[] BuildTimeFormats =
    {
        "MMM dd yyyy HH:mm:ss",
        "MMM d yyyy HH:mm:ss",
        "MMM dd yyyy",
        "MMM d yyyy"
    };

    public static void Extract(
        ReadOnlySpan<byte> image,
        int maximumStringLength,
        QcomImageParseResult result,
        int? preferredElfOffset = null)
    {
        VersionMetadataValues versionValues = ExtractReferencedVersionValues(
            image,
            maximumStringLength,
            preferredElfOffset,
            out bool hasAnalyzableCode);
        result.QcVersion = !string.IsNullOrEmpty(versionValues.QcVersion)
            ? versionValues.QcVersion
            : hasAnalyzableCode
                ? string.Empty
                : ExtractValue(image, QcVersionPrefix, maximumStringLength);
        result.OemVersion = !string.IsNullOrEmpty(versionValues.OemVersion)
            ? versionValues.OemVersion
            : hasAnalyzableCode
                ? string.Empty
                : ExtractValue(image, OemVersionPrefix, maximumStringLength);
        result.ImageVariant = !string.IsNullOrEmpty(versionValues.ImageVariant)
            ? versionValues.ImageVariant
            : hasAnalyzableCode
                ? string.Empty
                : ExtractValue(image, ImageVariantPrefix, maximumStringLength);

        if (!string.IsNullOrEmpty(versionValues.BuildTime))
        {
            result.BuildTime = versionValues.BuildTime;
            return;
        }

        if (hasAnalyzableCode)
        {
            result.BuildTimeDebug = versionValues.BuildTimeDebug;
            return;
        }

        int patternOffset = image.IndexOf(BuildDatePrefix);
        if (patternOffset < 0)
            return;

        int dateOffset = patternOffset + BuildDatePrefix.Length;
        if (!TryExtractNullTerminated(image, dateOffset, maximumStringLength, out string date, out int dateLength))
        {
            result.BuildTimeDebug = "构建日期为空、过长或编码无效";
            return;
        }

        int timeOffset = dateOffset + dateLength + 1;
        string? time = TryExtractNullTerminated(image, timeOffset, maximumStringLength, out string parsedTime, out _)
            ? parsedTime
            : string.Empty;
        if (time is not null && time.Length > 9)
        {
            time = null;
        }
        string value = CombineBuildTimeParts(date, time);
        if (TryNormalizeBuildTime(value, out string buildTime))
        {
            result.BuildTime = buildTime;
            return;
        }

        result.BuildTimeDebug = $"无法解析构建时间: {value}";
    }

    private static string CombineBuildTimeParts(string date, string? time)
    {
        string normalizedTime = time?.Trim() ?? string.Empty;
        return normalizedTime.Length is > 0 and <= 9
            ? date + " " + normalizedTime
            : date;
    }

    private static bool TryNormalizeBuildTime(string value, out string buildTime)
    {
        if (DateTime.TryParseExact(
                value,
                BuildTimeFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces,
                out DateTime parsedBuildTime))
        {
            buildTime = parsedBuildTime.ToString(
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture);
            return true;
        }

        buildTime = string.Empty;
        return false;
    }

    private static string ExtractValue(
        ReadOnlySpan<byte> image,
        ReadOnlySpan<byte> prefix,
        int maximumStringLength)
    {
        int prefixOffset = image.IndexOf(prefix);
        if (prefixOffset < 0)
            return string.Empty;

        int valueOffset = prefixOffset + prefix.Length;
        return TryExtractNullTerminated(image, valueOffset, maximumStringLength, out string value, out _)
            ? value
            : string.Empty;
    }

    private static bool TryExtractNullTerminated(
        ReadOnlySpan<byte> image,
        int offset,
        int maximumStringLength,
        out string value,
        out int byteLength)
    {
        value = string.Empty;
        byteLength = 0;
        if ((uint)offset >= (uint)image.Length)
            return false;

        ReadOnlySpan<byte> remaining = image.Slice(offset);
        int searchLength = Math.Min(remaining.Length, maximumStringLength + 1);
        int terminator = remaining.Slice(0, searchLength).IndexOf((byte)0);
        if (terminator <= 0 || terminator > maximumStringLength)
            return false;

        try
        {
#if NET5_0_OR_GREATER
            value = StrictUtf8.GetString(remaining.Slice(0, terminator));
#else
            value = StrictUtf8.GetString(remaining.Slice(0, terminator).ToArray());
#endif
            byteLength = terminator;
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
