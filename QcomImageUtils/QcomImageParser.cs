using System;
using System.Collections.Generic;
using System.Globalization;
using QcomImageUtils.Constants;
using QcomImageUtils.Models;
using QcomImageUtils.Types;
using QcomImageUtils.Utilities;

namespace QcomImageUtils;

/// <summary>
/// 以低分配 Span 路径解析 Qualcomm ELF、常规 MBN 与 SBL MBN 镜像。
/// </summary>
public sealed class QcomImageParser : IQcomImageParser
{
    private static readonly byte[] ElfMagic = { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
    private const uint SblCodeword = ArmExecutableImageReader.SblCodeword;
    private const uint SblMagic = ArmExecutableImageReader.SblMagic;
    private const int SblHeaderSize = ArmExecutableImageReader.SblHeaderSize;
    private const uint ProgrammerSoftwareId = 3;
    private const uint ProgrammerImageId = 5;

    private readonly bool _calculateFileSha256;
    private readonly bool _exportCertificatePem;
    private readonly int _maximumImageSize;
    private readonly int _maximumCertificateChainSize;
    private readonly int _maximumCertificateCount;
    private readonly int _maximumMetadataStringLength;
    private readonly FirehoseCommandAnalyzer? _firehoseCommandAnalyzer;

    public QcomImageParser(QcomImageParserOptions? options = null)
    {
        options ??= new QcomImageParserOptions();
        if (options.MaximumImageSize < 1)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumImageSize));
        if (options.MaximumCertificateChainSize is < 1 or > 64 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumCertificateChainSize));
        if (options.MaximumCertificateCount is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumCertificateCount));
        if (options.MaximumMetadataStringLength is < 32 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumMetadataStringLength));

        _calculateFileSha256 = options.CalculateFileSha256;
        _exportCertificatePem = options.ExportCertificatePem;
        _maximumImageSize = options.MaximumImageSize;
        _maximumCertificateChainSize = options.MaximumCertificateChainSize;
        _maximumCertificateCount = options.MaximumCertificateCount;
        _maximumMetadataStringLength = options.MaximumMetadataStringLength;
        if (options.AnalyzeFirehoseCommands)
        {
            _firehoseCommandAnalyzer = new FirehoseCommandAnalyzer(new FirehoseCommandAnalyzerOptions
            {
                MaximumImageSize = options.MaximumImageSize
            });
        }
    }

    public bool TryParse(string filePath, out QcomImageParseResult result)
    {
        result = new QcomImageParseResult();
        if (!ImageFileReader.TryRead(
                filePath,
                _maximumImageSize,
                out byte[] image,
                out string fullPath,
                out string fileName,
                out string error))
        {
            result.OriginalFilePath = fullPath;
            result.OriginalFileName = fileName;
            return Complete(result, false, error);
        }

        bool success = TryParse(image, out result);
        result.OriginalFilePath = fullPath;
        result.OriginalFileName = fileName;
        return success;
    }

    public bool TryParse(ReadOnlySpan<byte> image, out QcomImageParseResult result)
    {
        result = new QcomImageParseResult();
        if (image.IsEmpty)
            return Complete(result, false, "镜像数据为空");
        if (image.Length > _maximumImageSize)
            return Complete(result, false, $"镜像数据超过配置的 {_maximumImageSize} 字节上限");

        try
        {
            string fileSha256 = string.Empty;
            if (_calculateFileSha256)
                fileSha256 = HashUtility.ComputeSha256Hex(image);
            int selectedElfOffset = -1;

            if (!TryAnalyzeSblMbn(image, out QcomImageParseResult sblResult))
            {
                if (!TryAnalyzeElf(
                        image,
                        out QcomImageParseResult elfResult,
                        out selectedElfOffset))
                {
                    if (!TryAnalyzeRegularMbn(image, out QcomImageParseResult mbnResult))
                    {
                        result = mbnResult;
                        result.FileSha256 = fileSha256;
                        string error = mbnResult.ErrorMessage
                                       ?? elfResult.ErrorMessage
                                       ?? sblResult.ErrorMessage
                                       ?? "未识别到受支持的 Qualcomm ELF 或 MBN 镜像";
                        return Complete(result, false, error);
                    }

                    result = mbnResult;
                }
                else
                {
                    result = elfResult;
                }
            }
            else
            {
                result = sblResult;
            }

            result.FileSha256 = fileSha256;
            FinalizeResult(result);
            ImageMetadataExtractor.Extract(
                image,
                _maximumMetadataStringLength,
                result,
                selectedElfOffset >= 0 ? selectedElfOffset : null);
            if (result.IsProgrammer
                && _firehoseCommandAnalyzer is not null
                && _firehoseCommandAnalyzer.TryAnalyze(
                    image,
                    out FirehoseCommandAnalysisResult commandAnalysis))
            {
                result.SupportedCommands = commandAnalysis.Commands;
            }
            return Complete(result, true, string.Empty);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return Complete(result, false, $"解析 Qualcomm 镜像失败: {exception.Message}");
        }
    }

    private bool TryAnalyzeElf(
        ReadOnlySpan<byte> image,
        out QcomImageParseResult result,
        out int selectedElfOffset)
    {
        result = new QcomImageParseResult();
        selectedElfOffset = -1;
        int searchOffset = 0;
        string? lastError = null;
        while (searchOffset <= image.Length - ElfMagic.Length)
        {
            int relativeOffset = image.Slice(searchOffset).IndexOf(ElfMagic);
            if (relativeOffset < 0)
                break;

            int elfOffset = searchOffset + relativeOffset;
            ReadOnlySpan<byte> elfImage = image.Slice(elfOffset);
            if (ElfHashSegmentReader.TryGetHashSegment(elfImage, out ReadOnlySpan<byte> hashSegment))
            {
                var candidate = new QcomImageParseResult();
                if (!HashSegmentReader.TryRead(hashSegment, out HashSegmentInfo info, out string error))
                {
                    lastError = error;
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                bool supportedHashSize = info.HashSize > 0
                                         && (info.UsesSha384
                                             ? info.HashSize % 48 == 0
                                             : info.Version == 3
                                               ? info.HashSize % 20 == 0 || info.HashSize % 32 == 0
                                               : info.HashSize % 32 == 0);
                if (!supportedHashSize)
                {
                    lastError = "Qualcomm 哈希表长度与摘要算法不匹配";
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                if (info.Version == 7 && info.HashTableAlgorithm != 3)
                {
                    lastError = "MBN v7 哈希表算法不受支持";
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                candidate.ImageFormat = "ELF";
                if (TryApplyHashSegment(hashSegment, info, candidate))
                {
                    result = candidate;
                    selectedElfOffset = elfOffset;
                    return true;
                }

                lastError = candidate.ErrorMessage;
            }

            searchOffset = elfOffset + ElfMagic.Length;
        }

        result.ErrorMessage = lastError;
        return false;
    }

    private bool TryAnalyzeRegularMbn(
        ReadOnlySpan<byte> image,
        out QcomImageParseResult result)
    {
        result = new QcomImageParseResult();
        if (!HashSegmentReader.TryGetVersion(image, out _))
            return false;

        if (!HashSegmentReader.TryRead(image, out HashSegmentInfo info, out string error))
        {
            result.ErrorMessage = error;
            return false;
        }

        bool invalidHashSize = info.HashSize == 0
                               || info.UsesSha384 && info.HashSize % 48 != 0
                               || !info.UsesSha384
                               && info.HashSize % 20 != 0
                               && info.HashSize % 32 != 0;
        if (invalidHashSize)
        {
            result.ErrorMessage = "MBN 哈希表长度与支持的摘要算法不匹配";
            return false;
        }

        if (info.Version == 7 && info.HashTableAlgorithm != 3)
        {
            result.ErrorMessage = "MBN v7 哈希表算法不受支持";
            return false;
        }

        result.ImageFormat = "MBN";
        return TryApplyHashSegment(image, info, result);
    }

    private bool TryAnalyzeSblMbn(
        ReadOnlySpan<byte> image,
        out QcomImageParseResult result)
    {
        result = new QcomImageParseResult();
        if (!BinaryDataReader.TryReadUInt32LittleEndian(image, 0, out uint codeword)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 4, out uint magic)
            || codeword != SblCodeword
            || magic != SblMagic)
        {
            return false;
        }

        if (image.Length < SblHeaderSize
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 8, out uint imageId)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 20, out uint imageSource)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 28, out uint imageSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 32, out uint codeSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 40, out uint signatureSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 48, out uint certificateSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 60, out uint bootConfiguration))
        {
            result.ErrorMessage = "SBL MBN 头不完整";
            return false;
        }

        ulong payloadSize = (ulong)codeSize + signatureSize + certificateSize;
        if (imageSize < payloadSize)
        {
            result.ErrorMessage = "SBL MBN 声明的镜像长度无效";
            return false;
        }

        if (!BinaryDataReader.IsRangeInside(imageSource, imageSize, image.Length))
        {
            result.ErrorMessage = "SBL MBN 声明的完整载荷范围超出镜像";
            return false;
        }

        ulong certificateOffset = (ulong)imageSource + codeSize + signatureSize;
        if (!BinaryDataReader.IsRangeInside(certificateOffset, certificateSize, image.Length))
        {
            result.ErrorMessage = "SBL MBN 证书链范围超出镜像";
            return false;
        }

        result.ImageFormat = "MBN";
        result.IsSbl = true;
        result.ImageId = imageId;
        result.ImageType = (QcomImageType)imageId;
        result.SblType = ArmExecutableImageReader.TryDecodeSblArchitecture(
            bootConfiguration,
            out bool isArm64)
            ? isArm64 ? SblType.SblAarch64 : SblType.SblAarch32
            : Types.SblType.Unknown;

        if (certificateSize == 0)
            return true;

        BinaryDataReader.TryReadUInt32LittleEndian(image, 52, out uint rootSelection);
        BinaryDataReader.TryReadUInt32LittleEndian(image, 56, out uint rootCount);
        uint? selectedRootSlot = rootCount > 0 && rootSelection > 0
            ? rootSelection - 1
            : null;
        result.OemRootCertificateSlot = selectedRootSlot;

        ReadOnlySpan<byte> certificateData = image.Slice(
            checked((int)certificateOffset),
            checked((int)certificateSize));
        if (!TryLoadChain(certificateData, CertificateChainType.Oem, false,
                selectedRootSlot, result,
                new List<ImageCertItem>(), out List<ImageCertItem> certificates, out string error))
        {
            result.ErrorMessage = error;
            return false;
        }

        result.CertChains = certificates;
        return true;
    }

    private bool TryApplyHashSegment(
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo info,
        QcomImageParseResult result)
    {
        result.HeaderVersion = info.Version;
        if (info.HasImageId)
        {
            result.ImageId = info.ImageId;
            result.ImageType = (QcomImageType)info.ImageId;
        }

        result.SocHwVersion = info.SocHwVersion;
        result.HasOemId = info.HasOemId;
        result.OemId = info.OemId;
        result.ModelId = info.ModelId;
        result.AntiRollbackVersion = info.AntiRollbackVersion;
        result.QualcommRootCertificateSlot = info.HasQualcommRootCertificateSlot
            ? info.QualcommRootCertificateSlot
            : null;
        result.OemRootCertificateSlot = info.HasOemRootCertificateSlot
            ? info.OemRootCertificateSlot
            : null;
        result.SwId = info.SoftwareId;
        result.HwId = info.HardwareId;
        result.RootCaHash = info.MetadataRootCertificateHash;

        var certificates = new List<ImageCertItem>();
        if (info.QualcommCertificateLength > 0)
        {
            ReadOnlySpan<byte> qtiData = hashSegment.Slice(
                info.QualcommCertificateOffset,
                info.QualcommCertificateLength);
            uint? rootSlot = info.HasQualcommRootCertificateSlot
                ? info.QualcommRootCertificateSlot
                : null;
            if (!TryLoadChain(qtiData, CertificateChainType.Qualcomm, info.UsesSha384,
                    rootSlot,
                    result, certificates, out certificates, out string error))
            {
                result.ErrorMessage = error;
                return false;
            }
        }

        if (info.OemCertificateLength > 0)
        {
            ReadOnlySpan<byte> oemData = hashSegment.Slice(
                info.OemCertificateOffset,
                info.OemCertificateLength);
            uint? rootSlot = info.HasOemRootCertificateSlot
                ? info.OemRootCertificateSlot
                : null;
            if (!TryLoadChain(oemData, CertificateChainType.Oem, info.UsesSha384,
                    rootSlot,
                    result, certificates, out certificates, out string error))
            {
                result.ErrorMessage = error;
                return false;
            }
        }

        result.CertChains = certificates;
        return true;
    }

    private bool TryLoadChain(
        ReadOnlySpan<byte> data,
        CertificateChainType chainType,
        bool useSha384,
        uint? selectedRootSlot,
        QcomImageParseResult result,
        List<ImageCertItem> existingCertificates,
        out List<ImageCertItem> allCertificates,
        out string error)
    {
        allCertificates = existingCertificates;
        if (data.Length > _maximumCertificateChainSize)
        {
            error = $"证书链超过配置的 {_maximumCertificateChainSize} 字节上限";
            return false;
        }

        if (!CertificateChainLoader.TryLoad(
                data,
                chainType,
                _exportCertificatePem,
                _maximumCertificateCount,
                selectedRootSlot,
                out List<ImageCertItem> certificates,
                out CertificateChainSummary summary,
                out error))
        {
            return false;
        }

        existingCertificates.AddRange(certificates);
        ApplyCertificateAttributes(summary.Attributes, result, chainType == CertificateChainType.Oem);
        result.RootCaSubject = summary.RootSubject;
        result.RootCaHash = useSha384 ? summary.RootSha384 : summary.RootSha256;
        return true;
    }

    private static void ApplyCertificateAttributes(
        IReadOnlyDictionary<string, string> attributes,
        QcomImageParseResult result,
        bool overwrite)
    {
        if ((overwrite || result.ModelId == 0) && TryReadHex(attributes, "MODEL_ID", out ulong modelId)
                                                   && modelId <= uint.MaxValue)
            result.ModelId = (uint)modelId;
        if ((overwrite || !result.HasOemId) && TryReadHex(attributes, "OEM_ID", out ulong oemId)
                                               && oemId <= uint.MaxValue)
        {
            result.OemId = (uint)oemId;
            result.HasOemId = true;
        }
        if ((overwrite || result.SwId == 0) && TryReadHex(attributes, "SW_ID", out ulong softwareId))
            result.SwId = softwareId;
        if ((overwrite || result.SwSize == 0) && TryReadHex(attributes, "SW_SIZE", out ulong softwareSize)
                                                && softwareSize <= uint.MaxValue)
            result.SwSize = (uint)softwareSize;
        if ((overwrite || result.HwId == 0) && TryReadHex(attributes, "HW_ID", out ulong hardwareId))
        {
            result.HwId = hardwareId;
            result.HasOemId = true;
        }
    }

    private static bool TryReadHex(
        IReadOnlyDictionary<string, string> attributes,
        string key,
        out ulong value)
    {
        value = 0;
        return attributes.TryGetValue(key, out string? text)
               && ulong.TryParse(text, NumberStyles.AllowHexSpecifier,
                   CultureInfo.InvariantCulture, out value);
    }

    private static void FinalizeResult(QcomImageParseResult result)
    {
        if (result.HeaderVersion < 6)
        {
            if (result.HwId != 0)
            {
                result.MsmId = (uint)(result.HwId >> 32);
                result.HasOemId = true;
                if (result.OemId == 0)
                    result.OemId = (uint)((result.HwId >> 16) & 0xFFFF);
                if (result.ModelId == 0)
                    result.ModelId = (uint)(result.HwId & 0xFFFF);
            }
            else if (result.OemId != 0 || result.ModelId != 0)
            {
                result.HwId = ((ulong)result.OemId << 16) | result.ModelId;
            }
        }

        result.IsProgrammer = result.SwId == ProgrammerSoftwareId
                              || result.SwId == 0 && result.ImageId == ProgrammerImageId;
        result.OemType = QualcommMapping.GetOemType(
            result.HasOemId ? result.OemId : null);
        result.SocType = QualcommMapping.GetSocType(result.SocHwVersion, result.MsmId);
    }

    private static bool Complete(
        QcomImageParseResult result,
        bool success,
        string error)
    {
        result.IsSuccess = success;
        result.ErrorMessage = success ? null : error;
        return success;
    }
}
