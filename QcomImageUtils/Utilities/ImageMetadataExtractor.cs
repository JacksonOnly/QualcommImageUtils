using System;
using System.Globalization;
using System.Text;
using QcomImageUtils.Models;

namespace QcomImageUtils.Utilities;

internal static class ImageMetadataExtractor
{
    private static readonly byte[] QcVersionPrefix = Encoding.ASCII.GetBytes("QC_IMAGE_VERSION_STRING=");
    private static readonly byte[] OemVersionPrefix = Encoding.ASCII.GetBytes("OEM_IMAGE_VERSION_STRING=");
    private static readonly byte[] ImageVariantPrefix = Encoding.ASCII.GetBytes("IMAGE_VARIANT_STRING=");
    private static readonly byte[] BuildDatePrefix = Encoding.ASCII.GetBytes("Binary build date: %s @ %s\0");
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
        QcomImageParseResult result)
    {
        result.QcVersion = ExtractValue(image, QcVersionPrefix, maximumStringLength);
        result.OemVersion = ExtractValue(image, OemVersionPrefix, maximumStringLength);
        result.ImageVariant = ExtractValue(image, ImageVariantPrefix, maximumStringLength);

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
        string time = TryExtractNullTerminated(image, timeOffset, maximumStringLength, out string parsedTime, out _)
            ? parsedTime
            : string.Empty;
        string value = string.IsNullOrEmpty(time) ? date : date + " " + time;

        if (DateTime.TryParseExact(
                value,
                BuildTimeFormats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces,
                out DateTime buildTime))
        {
            result.BuildTime = buildTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            return;
        }

        result.BuildTimeDebug = $"无法解析构建时间: {value}";
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
