using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using QcomImageUtils.Models;
using QcomImageUtils.Types;
using QcomImageUtils.Utilities;

namespace QcomImageUtils;

/// <summary>
/// 验证 Qualcomm ELF/MBN 镜像的段摘要、镜像签名、内置证书链和可选可信根。
/// </summary>
public sealed class QcomImageVerifier : IQcomImageVerifier
{
    private static readonly byte[] ElfMagic = { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
    private const uint SblCodeword = 0x844BDCD1;
    private const uint SblMagic = 0x73D71034;
    private const int SblHeaderSize = 80;
    private const int MinimumAuthenticatedNestedElfLength = 64;

    private readonly int _maximumImageSize;
    private readonly int _maximumCertificateChainSize;
    private readonly int _maximumCertificateCount;
    private readonly int _maximumElfComponentCount;
    private readonly HashSet<string> _trustedRootHashes;
    private readonly QcomImageParser _parser;

    public QcomImageVerifier(QcomImageVerifierOptions? options = null)
    {
        options ??= new QcomImageVerifierOptions();
        if (options.MaximumImageSize < 1)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumImageSize));
        if (options.MaximumCertificateChainSize is < 1 or > 64 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumCertificateChainSize));
        if (options.MaximumCertificateCount is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumCertificateCount));
        if (options.MaximumElfComponentCount is < 1 or > 4096)
            throw new ArgumentOutOfRangeException(nameof(options.MaximumElfComponentCount));

        _maximumImageSize = options.MaximumImageSize;
        _maximumCertificateChainSize = options.MaximumCertificateChainSize;
        _maximumCertificateCount = options.MaximumCertificateCount;
        _maximumElfComponentCount = options.MaximumElfComponentCount;
        _trustedRootHashes = NormalizeTrustedRootHashes(
            options.TrustedRootCertificateHashes
            ?? throw new ArgumentNullException(nameof(options.TrustedRootCertificateHashes)));
        _parser = new QcomImageParser(new QcomImageParserOptions
        {
            CalculateFileSha256 = options.CalculateFileSha256,
            ExportCertificatePem = options.ExportCertificatePem,
            AnalyzeFirehoseCommands = false,
            MaximumImageSize = options.MaximumImageSize,
            MaximumCertificateChainSize = options.MaximumCertificateChainSize,
            MaximumCertificateCount = options.MaximumCertificateCount
        });
    }

    public bool TryVerify(string filePath, out QcomImageVerificationResult result)
    {
        result = new QcomImageVerificationResult();
        if (!ImageFileReader.TryRead(
                filePath,
                _maximumImageSize,
                out byte[] image,
                out string fullPath,
                out string fileName,
                out string error))
        {
            result.Image.OriginalFilePath = fullPath;
            result.Image.OriginalFileName = fileName;
            return CompleteFailure(result, error);
        }

        bool completed = TryVerify(image, out result);
        result.Image.OriginalFilePath = fullPath;
        result.Image.OriginalFileName = fileName;
        return completed;
    }

    public bool TryVerify(ReadOnlySpan<byte> image, out QcomImageVerificationResult result)
    {
        result = new QcomImageVerificationResult();
        if (image.IsEmpty)
            return CompleteFailure(result, "镜像数据为空");
        if (image.Length > _maximumImageSize)
            return CompleteFailure(result, $"镜像数据超过配置的 {_maximumImageSize} 字节上限");

        try
        {
            _parser.TryParse(image, out QcomImageParseResult parseResult);
            result.Image = parseResult;
            if (TryVerifySbl(image, result))
                return true;
            if (TryVerifyElf(image, result))
                return true;
            if (TryVerifyFlatHashSegment(image, result))
                return true;
            return CompleteFailure(
                result,
                parseResult.ErrorMessage ?? "未识别到可验证的 Qualcomm ELF 或 MBN 镜像");
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return CompleteFailure(result, $"验证 Qualcomm 镜像失败: {exception.Message}");
        }
    }

    private bool TryVerifyElf(ReadOnlySpan<byte> image, QcomImageVerificationResult result)
    {
        int searchOffset = 0;
        string lastError = string.Empty;
        var components = new List<QcomImageComponentVerificationResult>();
        var authenticatedComponents = new List<AuthenticatedElfComponent>();
        while (searchOffset <= image.Length - ElfMagic.Length)
        {
            int relativeOffset = image.Slice(searchOffset).IndexOf(ElfMagic);
            if (relativeOffset < 0)
                break;

            int elfOffset = searchOffset + relativeOffset;
            if (components.Count >= _maximumElfComponentCount)
            {
                AddRejectedElfComponent(
                    components,
                    elfOffset,
                    QcomVerificationStatus.Invalid,
                    $"ELF 组件数量超过配置的 {_maximumElfComponentCount} 个上限");
                break;
            }

            ReadOnlySpan<byte> elfImage = image.Slice(elfOffset);
            if (ElfHashSegmentReader.TryGetHashSegment(
                    elfImage,
                    out ReadOnlySpan<byte> hashSegment,
                    out ElfImageInfo elfInfo,
                    out ElfHashSegmentReadStatus readStatus))
            {
                if (!HashSegmentReader.TryRead(
                        hashSegment,
                        out HashSegmentInfo hashInfo,
                        out lastError))
                {
                    if (IsAuthenticatedNestedElf(image, elfOffset, authenticatedComponents))
                    {
                        searchOffset = elfOffset + ElfMagic.Length;
                        continue;
                    }

                    AddRejectedElfComponent(
                        components,
                        elfOffset,
                        QcomVerificationStatus.Invalid,
                        lastError);
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                var component = new QcomImageVerificationResult();
                VerifyElfHashTable(elfImage, elfInfo, hashSegment, hashInfo, component);
                VerifyHashSegmentAuthentication(hashSegment, hashInfo, component);
                FinalizeVerification(component);

                components.Add(CreateComponentResult(component, components.Count, elfOffset));
                if (component.HashTableStatus == QcomVerificationStatus.Valid)
                    authenticatedComponents.Add(new AuthenticatedElfComponent(elfOffset, elfInfo));
                searchOffset = elfOffset + ElfMagic.Length;
                continue;
            }

            if (readStatus == ElfHashSegmentReadStatus.InvalidElf)
            {
                if (IsAuthenticatedNestedElf(image, elfOffset, authenticatedComponents))
                {
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                lastError = "ELF 组件头或程序头结构无效";
                AddRejectedElfComponent(
                    components,
                    elfOffset,
                    QcomVerificationStatus.Invalid,
                    lastError);
            }
            else if (readStatus == ElfHashSegmentReadStatus.HashSegmentNotFound && elfOffset != 0)
            {
                if (IsAuthenticatedNestedElf(image, elfOffset, authenticatedComponents))
                {
                    searchOffset = elfOffset + ElfMagic.Length;
                    continue;
                }

                lastError = "ELF 组件中没有 Qualcomm 哈希段";
                AddRejectedElfComponent(
                    components,
                    elfOffset,
                    QcomVerificationStatus.NotPresent,
                    lastError);
            }

            searchOffset = elfOffset + ElfMagic.Length;
        }

        if (components.Count > 0)
        {
            FinalizeElfContainer(result, components);
            return true;
        }

        if (!string.IsNullOrEmpty(lastError))
            result.ErrorMessage = lastError;
        return false;
    }

    private static bool IsAuthenticatedNestedElf(
        ReadOnlySpan<byte> image,
        int elfOffset,
        IReadOnlyList<AuthenticatedElfComponent> authenticatedComponents)
    {
        for (int index = 0; index < authenticatedComponents.Count; index++)
        {
            AuthenticatedElfComponent component = authenticatedComponents[index];
            int relativeOffset = elfOffset - component.ImageOffset;
            if (relativeOffset <= 0)
                continue;
            if (ElfHashTableVerifier.IsRangeAuthenticated(
                    image.Slice(component.ImageOffset),
                    component.Info,
                    relativeOffset,
                    MinimumAuthenticatedNestedElfLength))
            {
                return true;
            }
        }

        return false;
    }

    private static void AddRejectedElfComponent(
        ICollection<QcomImageComponentVerificationResult> components,
        int imageOffset,
        QcomVerificationStatus hashTableStatus,
        string issue)
    {
        var rejected = new QcomImageVerificationResult
        {
            HashTableStatus = hashTableStatus
        };
        AddIssue(rejected, issue);
        FinalizeVerification(rejected);
        components.Add(CreateComponentResult(rejected, components.Count, imageOffset));
    }

    private void VerifyElfHashTable(
        ReadOnlySpan<byte> elfImage,
        ElfImageInfo elfInfo,
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo hashInfo,
        QcomImageVerificationResult result)
    {
        var issues = new List<string>();
        if (hashInfo.Version == 7 && hashInfo.HashTableAlgorithm != 3)
        {
            result.HashTableStatus = QcomVerificationStatus.Unsupported;
            issues.Add($"MBN v7 哈希表算法 {hashInfo.HashTableAlgorithm} 不受支持");
        }
        else
        {
            ElfHashTableVerifier.Verify(
                elfImage,
                elfInfo,
                hashSegment,
                hashInfo,
                out QcomVerificationStatus status,
                out int expectedHashCount,
                out int verifiedHashCount,
                out int failedSegmentIndex,
                out string error);
            result.HashTableStatus = status;
            result.ExpectedHashCount = expectedHashCount;
            result.VerifiedHashCount = verifiedHashCount;
            result.FailedSegmentIndex = failedSegmentIndex;
            if (!string.IsNullOrEmpty(error))
                issues.Add(error);
        }

        result.Issues = issues.ToArray();
    }

    private bool TryVerifyFlatHashSegment(
        ReadOnlySpan<byte> image,
        QcomImageVerificationResult result)
    {
        if (!HashSegmentReader.TryGetVersion(image, out _)
            || !HashSegmentReader.TryRead(image, out HashSegmentInfo info, out _))
        {
            return false;
        }

        result.HashTableStatus = QcomVerificationStatus.NotChecked;
        AddIssue(result, "独立 MBN 哈希段缺少关联 ELF，无法重算段摘要");
        VerifyHashSegmentAuthentication(image, info, result);
        FinalizeVerification(result);
        return true;
    }

    private bool TryVerifySbl(ReadOnlySpan<byte> image, QcomImageVerificationResult result)
    {
        if (!BinaryDataReader.TryReadUInt32LittleEndian(image, 0, out uint codeword)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 4, out uint magic)
            || codeword != SblCodeword
            || magic != SblMagic)
        {
            return false;
        }

        if (image.Length < SblHeaderSize
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 20, out uint imageSource)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 32, out uint codeSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 40, out uint signatureSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 48, out uint certificateSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 52, out uint rootSelection)
            || !BinaryDataReader.TryReadUInt32LittleEndian(image, 56, out uint rootCount))
        {
            return CompleteFailure(result, "SBL MBN 头不完整");
        }

        ulong signatureOffset = (ulong)imageSource + codeSize;
        ulong certificateOffset = signatureOffset + signatureSize;
        if (!BinaryDataReader.IsRangeInside(imageSource, codeSize, image.Length)
            || !BinaryDataReader.IsRangeInside(signatureOffset, signatureSize, image.Length)
            || !BinaryDataReader.IsRangeInside(certificateOffset, certificateSize, image.Length))
        {
            return CompleteFailure(result, "SBL MBN 的代码、签名或证书链范围无效");
        }

        result.HashTableStatus = QcomVerificationStatus.NotPresent;
        var authority = new AuthorityVerificationData(result.OemSignature);
        if (certificateSize == 0)
        {
            authority.Result.CertificateChainStatus = QcomVerificationStatus.NotPresent;
        }
        else
        {
            ReadOnlySpan<byte> certificateData = image.Slice(
                checked((int)certificateOffset),
                checked((int)certificateSize));
            int? selectedRootSlot = null;
            if (rootCount > 0)
            {
                if (rootSelection == 0 || rootSelection > rootCount)
                {
                    authority.Result.CertificateChainStatus = QcomVerificationStatus.Invalid;
                    AddAuthorityIssue(result, authority,
                        $"SBL Root 选择 {rootSelection} 超出 1-{rootCount} 范围");
                }
                else
                {
                    selectedRootSlot = checked((int)(rootSelection - 1));
                }
            }

            if (authority.Result.CertificateChainStatus != QcomVerificationStatus.Invalid)
                VerifyCertificateChain(certificateData, selectedRootSlot, authority, result);
        }
        if (signatureSize == 0)
        {
            authority.Result.SignatureStatus = QcomVerificationStatus.NotPresent;
        }
        else if (authority.Certificates.Count == 0)
        {
            authority.Result.SignatureStatus = QcomVerificationStatus.Invalid;
            AddAuthorityIssue(result, authority, "SBL MBN 有签名但没有可用的叶证书");
        }
        else
        {
            ReadOnlySpan<byte> signature = image.Slice(
                checked((int)signatureOffset),
                checked((int)signatureSize));
            int signedLength = checked((int)((ulong)imageSource + codeSize));
            VerifyImageSignature(
                authority,
                mbnVersion: 3,
                image.Slice(0, signedLength),
                default,
                signature,
                ImageHashAlgorithm.Sha256,
                result);
        }

        SetAggregateStatuses(result);
        result.IsIntegrityValid = result.SignatureStatus == QcomVerificationStatus.Valid;
        FinalizeTrust(result, authority, null);
        result.MetadataRootHashStatus = QcomVerificationStatus.NotPresent;
        CompleteResult(result);
        return true;
    }

    private void VerifyHashSegmentAuthentication(
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo info,
        QcomImageVerificationResult result)
    {
        var qti = new AuthorityVerificationData(result.QualcommSignature);
        var oem = new AuthorityVerificationData(result.OemSignature);
        VerifyAuthority(hashSegment, info, CertificateChainType.Qualcomm, qti, result);
        VerifyAuthority(hashSegment, info, CertificateChainType.Oem, oem, result);
        SetAggregateStatuses(result);
        VerifyMetadataRootHash(hashSegment, info, oem, result);
        FinalizeTrust(result, qti, oem);
    }

    private void VerifyAuthority(
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo info,
        CertificateChainType chainType,
        AuthorityVerificationData authority,
        QcomImageVerificationResult result)
    {
        int certificateOffset = chainType == CertificateChainType.Qualcomm
            ? info.QualcommCertificateOffset
            : info.OemCertificateOffset;
        int certificateLength = chainType == CertificateChainType.Qualcomm
            ? info.QualcommCertificateLength
            : info.OemCertificateLength;
        int signatureOffset = chainType == CertificateChainType.Qualcomm
            ? info.QualcommSignatureOffset
            : info.OemSignatureOffset;
        int signatureLength = chainType == CertificateChainType.Qualcomm
            ? info.QualcommSignatureLength
            : info.OemSignatureLength;

        if (certificateLength == 0)
        {
            authority.Result.CertificateChainStatus = QcomVerificationStatus.NotPresent;
        }
        else if (certificateLength > _maximumCertificateChainSize)
        {
            authority.Result.CertificateChainStatus = QcomVerificationStatus.Invalid;
            AddAuthorityIssue(result, authority,
                $"证书链超过配置的 {_maximumCertificateChainSize} 字节上限");
        }
        else
        {
            if (!TryGetRootCertificateSlot(info, chainType, out int? rootSlot, out string slotError))
            {
                authority.Result.CertificateChainStatus = QcomVerificationStatus.Invalid;
                AddAuthorityIssue(result, authority, slotError);
            }
            else
            {
                VerifyCertificateChain(
                    hashSegment.Slice(certificateOffset, certificateLength),
                    rootSlot,
                    authority,
                    result);
            }
        }

        if (signatureLength == 0)
        {
            authority.Result.SignatureStatus = QcomVerificationStatus.NotPresent;
            return;
        }

        if (authority.Certificates.Count == 0)
        {
            authority.Result.SignatureStatus = QcomVerificationStatus.Invalid;
            AddAuthorityIssue(result, authority, "镜像有签名但没有可用的叶证书");
            return;
        }

        int signedLength = checked(info.HashOffset + (int)info.HashSize);
        ReadOnlySpan<byte> signedData = hashSegment.Slice(0, signedLength);
        ReadOnlySpan<byte> signature = hashSegment.Slice(signatureOffset, signatureLength);
        ImageHashAlgorithm preferred = info.UsesSha384
            ? ImageHashAlgorithm.Sha384
            : ImageHashAlgorithm.Sha256;
        Span<HashMask> masks = stackalloc HashMask[3];
        int maskCount = GetOppositeAuthorityMasks(info, chainType, masks);
        VerifyImageSignature(
            authority,
            info.Version,
            signedData,
            masks.Slice(0, maskCount),
            signature,
            preferred,
            result);
        if (authority.Result.SignatureStatus != QcomVerificationStatus.Valid && maskCount > 0)
        {
            VerifyImageSignature(
                authority,
                info.Version,
                signedData,
                default,
                signature,
                preferred,
                result,
                replaceIssue: true);
        }
    }

    private void VerifyCertificateChain(
        ReadOnlySpan<byte> certificateData,
        int? selectedRootSlot,
        AuthorityVerificationData authority,
        QcomImageVerificationResult result)
    {
        bool valid = CertificateChainVerifier.TryVerify(
            certificateData,
            _maximumCertificateCount,
            selectedRootSlot,
            out CertificatePackageVerification verification,
            out string error);
        authority.Certificates = verification.Certificates;
        authority.Result.CertificateCount = verification.Certificates.Count;
        var roots = new List<byte[]>(verification.ValidRootIndices.Count);
        var sha256Hashes = new string[verification.ValidRootIndices.Count];
        var sha384Hashes = new string[verification.ValidRootIndices.Count];
        for (int index = 0; index < verification.ValidRootIndices.Count; index++)
        {
            byte[] root = verification.Certificates[verification.ValidRootIndices[index]];
            roots.Add(root);
            sha256Hashes[index] = HashUtility.ComputeSha256Hex(root);
            sha384Hashes[index] = HashUtility.ComputeSha384Hex(root);
        }

        authority.RootCertificates = roots;
        authority.Result.ValidRootCertificateSha256Hashes = sha256Hashes;
        authority.Result.ValidRootCertificateSha384Hashes = sha384Hashes;
        if (verification.SelectedRootIndex is int selectedRootIndex)
        {
            byte[] root = verification.Certificates[selectedRootIndex];
            authority.Result.RootCertificateSha256 = HashUtility.ComputeSha256Hex(root);
            authority.Result.RootCertificateSha384 = HashUtility.ComputeSha384Hex(root);
        }

        authority.Result.CertificateChainStatus = valid
            ? QcomVerificationStatus.Valid
            : QcomVerificationStatus.Invalid;
        if (!valid)
            AddAuthorityIssue(result, authority, error);
    }

    private static bool TryGetRootCertificateSlot(
        HashSegmentInfo info,
        CertificateChainType chainType,
        out int? rootSlot,
        out string error)
    {
        bool hasSlot = chainType == CertificateChainType.Qualcomm
            ? info.HasQualcommRootCertificateSlot
            : info.HasOemRootCertificateSlot;
        uint slot = chainType == CertificateChainType.Qualcomm
            ? info.QualcommRootCertificateSlot
            : info.OemRootCertificateSlot;
        if (!hasSlot)
        {
            rootSlot = null;
            error = string.Empty;
            return true;
        }

        if (slot > int.MaxValue)
        {
            rootSlot = null;
            error = $"MRC Root 槽位 {slot} 超出支持范围";
            return false;
        }

        rootSlot = (int)slot;
        error = string.Empty;
        return true;
    }

    private static void VerifyImageSignature(
        AuthorityVerificationData authority,
        uint mbnVersion,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<HashMask> masks,
        ReadOnlySpan<byte> signature,
        ImageHashAlgorithm preferredHash,
        QcomImageVerificationResult result,
        bool replaceIssue = false)
    {
        bool valid = ImageSignatureVerifier.TryVerify(
            authority.Certificates[0],
            mbnVersion,
            signedData,
            masks,
            signature,
            preferredHash,
            out string algorithm,
            out bool unsupported,
            out string error);
        authority.Result.Algorithm = algorithm;
        authority.Result.SignatureStatus = valid
            ? QcomVerificationStatus.Valid
            : unsupported
                ? QcomVerificationStatus.Unsupported
                : QcomVerificationStatus.Invalid;
        if (valid)
        {
            if (authority.Result.CertificateChainStatus == QcomVerificationStatus.Valid)
                authority.Result.ErrorMessage = null;
            if (replaceIssue)
                RemoveAuthoritySignatureIssue(result, authority.Result.ChainType);
            return;
        }

        if (replaceIssue)
            RemoveAuthoritySignatureIssue(result, authority.Result.ChainType);
        AddAuthorityIssue(result, authority, error, signatureIssue: true);
    }

    private static int GetOppositeAuthorityMasks(
        HashSegmentInfo info,
        CertificateChainType authority,
        Span<HashMask> masks)
    {
        if (info.Version == 3)
            return 0;

        int count = 0;
        if (authority == CertificateChainType.Qualcomm)
        {
            int signatureSizeOffset = info.Version == 7 ? 32 : 28;
            int certificateSizeOffset = info.Version == 7 ? 36 : 36;
            masks[count++] = new HashMask(signatureSizeOffset, sizeof(uint));
            masks[count++] = new HashMask(certificateSizeOffset, sizeof(uint));
            if (info.OemMetadataLength > 0)
                masks[count++] = new HashMask(info.OemMetadataOffset, info.OemMetadataLength);
        }
        else
        {
            int signatureSizeOffset = info.Version == 7 ? 24 : 8;
            int certificateSizeOffset = info.Version == 7 ? 28 : 12;
            masks[count++] = new HashMask(signatureSizeOffset, sizeof(uint));
            masks[count++] = new HashMask(certificateSizeOffset, sizeof(uint));
            if (info.QualcommMetadataLength > 0)
                masks[count++] = new HashMask(
                    info.QualcommMetadataOffset,
                    info.QualcommMetadataLength);
        }

        return count;
    }

    private static void VerifyMetadataRootHash(
        ReadOnlySpan<byte> hashSegment,
        HashSegmentInfo info,
        AuthorityVerificationData oem,
        QcomImageVerificationResult result)
    {
        if (info.MetadataRootCertificateHashLength == 0)
        {
            result.MetadataRootHashStatus = QcomVerificationStatus.NotPresent;
            return;
        }

        if (oem.RootCertificates.Count == 0)
        {
            result.MetadataRootHashStatus = QcomVerificationStatus.Invalid;
            AddIssue(result, "OEM 元数据声明了 Root CA 哈希，但镜像没有可用的 OEM 根证书");
            return;
        }

        ReadOnlySpan<byte> slot = hashSegment.Slice(
            info.MetadataRootCertificateHashOffset,
            info.MetadataRootCertificateHashLength);
        QcomVerificationStatus status = VerifyMetadataRootHash(
            slot,
            info.MetadataRootCertificateHashAlgorithm,
            oem.RootCertificates);
        result.MetadataRootHashStatus = status;
        if (status == QcomVerificationStatus.Unsupported)
        {
            AddIssue(result,
                $"OEM 元数据 Root CA 哈希算法 {info.MetadataRootCertificateHashAlgorithm} 不受支持");
            return;
        }

        if (status == QcomVerificationStatus.Invalid)
        {
            AddIssue(result,
                $"OEM 元数据 Root CA 哈希不匹配，算法标识为 {info.MetadataRootCertificateHashAlgorithm}");
        }
    }

    internal static QcomVerificationStatus VerifyMetadataRootHash(
        ReadOnlySpan<byte> slot,
        uint algorithmIdentifier,
        IReadOnlyList<byte[]> rootCertificates)
    {
        ImageHashAlgorithm algorithm;
        switch (algorithmIdentifier)
        {
            case 1:
                algorithm = ImageHashAlgorithm.Sha1;
                break;
            case 2:
                algorithm = ImageHashAlgorithm.Sha256;
                break;
            case 3:
                algorithm = ImageHashAlgorithm.Sha384;
                break;
            case 4:
                algorithm = ImageHashAlgorithm.Sha512;
                break;
            default:
                return QcomVerificationStatus.Unsupported;
        }

        int digestLength = CryptographicHash.GetDigestLength(algorithm);
        if (slot.Length < digestLength)
            return QcomVerificationStatus.Invalid;

        Span<byte> digest = stackalloc byte[64];
        for (int index = 0; index < rootCertificates.Count; index++)
        {
            CryptographicHash.Compute(algorithm, rootCertificates[index], digest);
            if (MatchesPaddedHash(slot, digest.Slice(0, digestLength)))
                return QcomVerificationStatus.Valid;
        }

        return QcomVerificationStatus.Invalid;
    }

    private void FinalizeTrust(
        QcomImageVerificationResult result,
        AuthorityVerificationData? qti,
        AuthorityVerificationData? oem)
    {
        if (_trustedRootHashes.Count == 0)
        {
            result.TrustedRootStatus = QcomVerificationStatus.NotChecked;
            result.IsTrusted = null;
            return;
        }

        bool hasRoot = false;
        bool trusted = IsTrusted(qti, ref hasRoot) || IsTrusted(oem, ref hasRoot);
        result.TrustedRootStatus = trusted
            ? QcomVerificationStatus.Valid
            : hasRoot
                ? QcomVerificationStatus.Invalid
                : QcomVerificationStatus.NotPresent;
        result.IsTrusted = trusted;
        if (!trusted)
        {
            AddIssue(result, hasRoot
                ? "镜像内置 Root CA 与配置的可信哈希不匹配"
                : "镜像中没有可用于可信根匹配的证书链");
        }
    }

    private bool IsTrusted(AuthorityVerificationData? authority, ref bool hasRoot)
    {
        if (authority is null
            || authority.Result.CertificateChainStatus != QcomVerificationStatus.Valid
            || authority.Result.ValidRootCertificateSha256Hashes.Count == 0)
        {
            return false;
        }

        hasRoot = true;
        for (int index = 0;
             index < authority.Result.ValidRootCertificateSha256Hashes.Count;
             index++)
        {
            if (_trustedRootHashes.Contains(
                    authority.Result.ValidRootCertificateSha256Hashes[index])
                || _trustedRootHashes.Contains(
                    authority.Result.ValidRootCertificateSha384Hashes[index]))
            {
                return true;
            }
        }

        return false;
    }

    private static void SetAggregateStatuses(QcomImageVerificationResult result)
    {
        result.SignatureStatus = Combine(
            result.QualcommSignature.SignatureStatus,
            result.OemSignature.SignatureStatus);
        result.CertificateChainStatus = Combine(
            result.QualcommSignature.CertificateChainStatus,
            result.OemSignature.CertificateChainStatus);
    }

    private static QcomVerificationStatus Combine(
        QcomVerificationStatus first,
        QcomVerificationStatus second)
    {
        if (first == QcomVerificationStatus.Invalid || second == QcomVerificationStatus.Invalid)
            return QcomVerificationStatus.Invalid;
        if (first == QcomVerificationStatus.Unsupported || second == QcomVerificationStatus.Unsupported)
            return QcomVerificationStatus.Unsupported;
        if (first == QcomVerificationStatus.Valid || second == QcomVerificationStatus.Valid)
            return QcomVerificationStatus.Valid;
        if (first == QcomVerificationStatus.NotPresent || second == QcomVerificationStatus.NotPresent)
            return QcomVerificationStatus.NotPresent;
        return QcomVerificationStatus.NotChecked;
    }

    private static void FinalizeVerification(QcomImageVerificationResult result)
    {
        result.IsIntegrityValid = result.HashTableStatus == QcomVerificationStatus.Valid;
        CompleteResult(result);
    }

    private static QcomImageComponentVerificationResult CreateComponentResult(
        QcomImageVerificationResult result,
        int componentIndex,
        int imageOffset)
    {
        return new QcomImageComponentVerificationResult
        {
            ComponentIndex = componentIndex,
            ImageOffset = imageOffset,
            VerificationCompleted = result.VerificationCompleted,
            IsVerified = result.IsVerified,
            IsIntegrityValid = result.IsIntegrityValid,
            IsAuthentic = result.IsAuthentic,
            IsTrusted = result.IsTrusted,
            HashTableStatus = result.HashTableStatus,
            SignatureStatus = result.SignatureStatus,
            CertificateChainStatus = result.CertificateChainStatus,
            MetadataRootHashStatus = result.MetadataRootHashStatus,
            TrustedRootStatus = result.TrustedRootStatus,
            ExpectedHashCount = result.ExpectedHashCount,
            VerifiedHashCount = result.VerifiedHashCount,
            FailedSegmentIndex = result.FailedSegmentIndex,
            QualcommSignature = result.QualcommSignature,
            OemSignature = result.OemSignature,
            Issues = result.Issues,
            ErrorMessage = result.ErrorMessage
        };
    }

    private static void FinalizeElfContainer(
        QcomImageVerificationResult result,
        IReadOnlyList<QcomImageComponentVerificationResult> components)
    {
        result.Components = components;
        if (components.Count == 1)
        {
            CopyComponentToResult(result, components[0]);
            return;
        }

        result.HashTableStatus = CombineComponentStatuses(components, component => component.HashTableStatus);
        result.SignatureStatus = CombineComponentStatuses(components, component => component.SignatureStatus);
        result.CertificateChainStatus = CombineComponentStatuses(
            components,
            component => component.CertificateChainStatus);
        result.MetadataRootHashStatus = CombineComponentStatuses(
            components,
            component => component.MetadataRootHashStatus);
        result.TrustedRootStatus = CombineComponentStatuses(
            components,
            component => component.TrustedRootStatus);
        result.ExpectedHashCount = SumComponentCount(components, component => component.ExpectedHashCount);
        result.VerifiedHashCount = SumComponentCount(components, component => component.VerifiedHashCount);
        result.FailedSegmentIndex = -1;

        for (int index = 0; index < components.Count; index++)
        {
            if (components[index].FailedSegmentIndex >= 0)
            {
                result.FailedSegmentIndex = components[index].FailedSegmentIndex;
                break;
            }
        }

        result.QualcommSignature = AggregateSignature(components, CertificateChainType.Qualcomm);
        result.OemSignature = AggregateSignature(components, CertificateChainType.Oem);

        var issues = new List<string>();
        bool allCompleted = true;
        bool allIntegrityValid = true;
        bool allAuthentic = true;
        bool allVerified = true;
        bool hasUntrusted = false;
        bool hasUnknownTrust = false;
        string? firstError = null;
        for (int index = 0; index < components.Count; index++)
        {
            QcomImageComponentVerificationResult component = components[index];
            allCompleted &= component.VerificationCompleted;
            allIntegrityValid &= component.IsIntegrityValid;
            allAuthentic &= component.IsAuthentic;
            allVerified &= component.IsVerified;
            if (component.IsTrusted is false)
                hasUntrusted = true;
            else if (component.IsTrusted is null)
                hasUnknownTrust = true;

            if (firstError is null && !string.IsNullOrEmpty(component.ErrorMessage))
                firstError = component.ErrorMessage;
            for (int issueIndex = 0; issueIndex < component.Issues.Count; issueIndex++)
            {
                issues.Add(
                    $"ELF 组件 {component.ComponentIndex} (偏移 0x{component.ImageOffset:X}): "
                    + component.Issues[issueIndex]);
            }
        }

        if (hasUntrusted)
            result.IsTrusted = false;
        else if (hasUnknownTrust)
            result.IsTrusted = null;
        else
            result.IsTrusted = true;

        result.IsIntegrityValid = allIntegrityValid;
        result.IsAuthentic = allAuthentic;
        result.IsVerified = allVerified;
        result.VerificationCompleted = allCompleted;
        result.Issues = issues.ToArray();
        result.ErrorMessage = firstError;
    }

    private static void CopyComponentToResult(
        QcomImageVerificationResult result,
        QcomImageComponentVerificationResult component)
    {
        result.IsVerified = component.IsVerified;
        result.IsIntegrityValid = component.IsIntegrityValid;
        result.IsAuthentic = component.IsAuthentic;
        result.IsTrusted = component.IsTrusted;
        result.HashTableStatus = component.HashTableStatus;
        result.SignatureStatus = component.SignatureStatus;
        result.CertificateChainStatus = component.CertificateChainStatus;
        result.MetadataRootHashStatus = component.MetadataRootHashStatus;
        result.TrustedRootStatus = component.TrustedRootStatus;
        result.ExpectedHashCount = component.ExpectedHashCount;
        result.VerifiedHashCount = component.VerifiedHashCount;
        result.FailedSegmentIndex = component.FailedSegmentIndex;
        result.QualcommSignature = component.QualcommSignature;
        result.OemSignature = component.OemSignature;
        result.Issues = component.Issues;
        result.ErrorMessage = component.ErrorMessage;
        result.VerificationCompleted = component.VerificationCompleted;
    }

    private static QcomSignatureVerificationResult AggregateSignature(
        IReadOnlyList<QcomImageComponentVerificationResult> components,
        CertificateChainType chainType)
    {
        var aggregate = new QcomSignatureVerificationResult
        {
            ChainType = chainType
        };
        bool hasAlgorithm = false;
        bool sameAlgorithm = true;
        string algorithm = string.Empty;
        bool hasRootSha256 = false;
        bool sameRootSha256 = true;
        string rootSha256 = string.Empty;
        bool hasRootSha384 = false;
        bool sameRootSha384 = true;
        string rootSha384 = string.Empty;
        var validRootSha256 = new List<string>();
        var validRootSha384 = new List<string>();
        var seenRootSha256 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenRootSha384 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? firstError = null;

        for (int index = 0; index < components.Count; index++)
        {
            QcomSignatureVerificationResult current = chainType == CertificateChainType.Qualcomm
                ? components[index].QualcommSignature
                : components[index].OemSignature;
            aggregate.SignatureStatus = index == 0
                ? current.SignatureStatus
                : CombineComponentStatuses(aggregate.SignatureStatus, current.SignatureStatus);
            aggregate.CertificateChainStatus = index == 0
                ? current.CertificateChainStatus
                : CombineComponentStatuses(
                    aggregate.CertificateChainStatus,
                    current.CertificateChainStatus);
            aggregate.CertificateCount = AddComponentCount(
                aggregate.CertificateCount,
                current.CertificateCount);

            if (!string.IsNullOrEmpty(current.Algorithm))
            {
                if (!hasAlgorithm)
                {
                    algorithm = current.Algorithm;
                    hasAlgorithm = true;
                }
                else if (!string.Equals(algorithm, current.Algorithm, StringComparison.Ordinal))
                {
                    sameAlgorithm = false;
                }
            }

            if (!string.IsNullOrEmpty(current.RootCertificateSha256))
            {
                if (!hasRootSha256)
                {
                    rootSha256 = current.RootCertificateSha256;
                    hasRootSha256 = true;
                }
                else if (!string.Equals(rootSha256, current.RootCertificateSha256, StringComparison.OrdinalIgnoreCase))
                {
                    sameRootSha256 = false;
                }
            }
            else
            {
                sameRootSha256 = false;
            }

            if (!string.IsNullOrEmpty(current.RootCertificateSha384))
            {
                if (!hasRootSha384)
                {
                    rootSha384 = current.RootCertificateSha384;
                    hasRootSha384 = true;
                }
                else if (!string.Equals(rootSha384, current.RootCertificateSha384, StringComparison.OrdinalIgnoreCase))
                {
                    sameRootSha384 = false;
                }
            }
            else
            {
                sameRootSha384 = false;
            }

            AddUniqueHashes(
                current.ValidRootCertificateSha256Hashes,
                validRootSha256,
                seenRootSha256);
            AddUniqueHashes(
                current.ValidRootCertificateSha384Hashes,
                validRootSha384,
                seenRootSha384);

            if (firstError is null && !string.IsNullOrEmpty(current.ErrorMessage))
                firstError = current.ErrorMessage;
        }

        aggregate.Algorithm = hasAlgorithm
            ? sameAlgorithm ? algorithm : "Multiple"
            : string.Empty;
        aggregate.RootCertificateSha256 = hasRootSha256 && sameRootSha256
            ? rootSha256
            : string.Empty;
        aggregate.RootCertificateSha384 = hasRootSha384 && sameRootSha384
            ? rootSha384
            : string.Empty;
        aggregate.ValidRootCertificateSha256Hashes = validRootSha256.ToArray();
        aggregate.ValidRootCertificateSha384Hashes = validRootSha384.ToArray();
        aggregate.ErrorMessage = firstError;
        return aggregate;
    }

    private static void AddUniqueHashes(
        IReadOnlyList<string> source,
        List<string> destination,
        HashSet<string> seen)
    {
        for (int index = 0; index < source.Count; index++)
        {
            if (seen.Add(source[index]))
                destination.Add(source[index]);
        }
    }

    private static QcomVerificationStatus CombineComponentStatuses(
        IReadOnlyList<QcomImageComponentVerificationResult> components,
        Func<QcomImageComponentVerificationResult, QcomVerificationStatus> selector)
    {
        QcomVerificationStatus status = QcomVerificationStatus.Valid;
        for (int index = 0; index < components.Count; index++)
        {
            status = index == 0
                ? selector(components[index])
                : CombineComponentStatuses(status, selector(components[index]));
        }

        return status;
    }

    private static QcomVerificationStatus CombineComponentStatuses(
        QcomVerificationStatus first,
        QcomVerificationStatus second)
    {
        if (first == QcomVerificationStatus.Invalid || second == QcomVerificationStatus.Invalid)
            return QcomVerificationStatus.Invalid;
        if (first == QcomVerificationStatus.Unsupported || second == QcomVerificationStatus.Unsupported)
            return QcomVerificationStatus.Unsupported;
        if (first == QcomVerificationStatus.NotPresent || second == QcomVerificationStatus.NotPresent)
            return QcomVerificationStatus.NotPresent;
        if (first == QcomVerificationStatus.NotChecked || second == QcomVerificationStatus.NotChecked)
            return QcomVerificationStatus.NotChecked;
        return QcomVerificationStatus.Valid;
    }

    private static int SumComponentCount(
        IReadOnlyList<QcomImageComponentVerificationResult> components,
        Func<QcomImageComponentVerificationResult, int> selector)
    {
        int total = 0;
        for (int index = 0; index < components.Count; index++)
            total = AddComponentCount(total, selector(components[index]));
        return total;
    }

    private static int AddComponentCount(int left, int right)
    {
        if (right <= 0 || left == int.MaxValue)
            return left;
        return right > int.MaxValue - left
            ? int.MaxValue
            : left + right;
    }

    private static void CompleteResult(QcomImageVerificationResult result)
    {
        bool metadataValid = result.MetadataRootHashStatus is
            QcomVerificationStatus.Valid or QcomVerificationStatus.NotPresent;
        result.IsAuthentic = result.IsIntegrityValid
                             && result.SignatureStatus == QcomVerificationStatus.Valid
                             && result.CertificateChainStatus == QcomVerificationStatus.Valid
                             && metadataValid;
        bool trustValid = result.TrustedRootStatus is
            QcomVerificationStatus.Valid or QcomVerificationStatus.NotChecked;
        result.IsVerified = result.IsAuthentic && trustValid;
        result.VerificationCompleted = true;
        result.ErrorMessage = null;
    }

    private static bool CompleteFailure(QcomImageVerificationResult result, string error)
    {
        result.VerificationCompleted = false;
        result.IsVerified = false;
        result.ErrorMessage = error;
        return false;
    }

    private static HashSet<string> NormalizeTrustedRootHashes(
        IReadOnlyCollection<string> hashes)
    {
        var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string hash in hashes)
        {
            string value = NormalizeHash(hash);
            if (value.Length is not (64 or 96))
            {
                throw new ArgumentException(
                    "可信 Root CA 哈希必须是 SHA-256 或 SHA-384 十六进制值",
                    nameof(hashes));
            }

            normalized.Add(value);
        }

        return normalized;
    }

    private static string NormalizeHash(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
            throw new ArgumentException("可信 Root CA 哈希不能为空", nameof(hash));

        ReadOnlySpan<char> source = hash.AsSpan().Trim();
        if (source.StartsWith("0x".AsSpan(), StringComparison.OrdinalIgnoreCase))
            source = source.Slice(2);
        var characters = new char[source.Length];
        int length = 0;
        for (int index = 0; index < source.Length; index++)
        {
            char character = source[index];
            if (character is ':' or '-' || char.IsWhiteSpace(character))
                continue;
            if (!Uri.IsHexDigit(character))
                throw new ArgumentException("可信 Root CA 哈希包含非十六进制字符", nameof(hash));
            characters[length++] = char.ToUpperInvariant(character);
        }

        return new string(characters, 0, length);
    }

    private static bool MatchesPaddedHash(
        ReadOnlySpan<byte> slot,
        ReadOnlySpan<byte> digest)
    {
        if (slot.Length < digest.Length
            || !FixedTimeEquals(slot.Slice(0, digest.Length), digest))
        {
            return false;
        }

        for (int index = digest.Length; index < slot.Length; index++)
        {
            if (slot[index] != 0)
                return false;
        }

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

    private static void AddAuthorityIssue(
        QcomImageVerificationResult result,
        AuthorityVerificationData authority,
        string message,
        bool signatureIssue = false)
    {
        authority.Result.ErrorMessage = message;
        AddIssue(result,
            $"{authority.Result.ChainType}: {(signatureIssue ? "签名" : "证书链")} {message}");
    }

    private static void RemoveAuthoritySignatureIssue(
        QcomImageVerificationResult result,
        CertificateChainType chainType)
    {
        string prefix = $"{chainType}: 签名 ";
        var issues = new List<string>(result.Issues.Count);
        for (int index = 0; index < result.Issues.Count; index++)
        {
            string issue = result.Issues[index];
            if (!issue.StartsWith(prefix, StringComparison.Ordinal))
                issues.Add(issue);
        }

        result.Issues = issues.ToArray();
    }

    private static void AddIssue(QcomImageVerificationResult result, string issue)
    {
        var issues = new string[result.Issues.Count + 1];
        for (int index = 0; index < result.Issues.Count; index++)
            issues[index] = result.Issues[index];
        issues[issues.Length - 1] = issue;
        result.Issues = issues;
    }

    private sealed class AuthorityVerificationData
    {
        public AuthorityVerificationData(QcomSignatureVerificationResult result)
        {
            Result = result;
        }

        public QcomSignatureVerificationResult Result { get; }
        public List<byte[]> Certificates { get; set; } = new();
        public List<byte[]> RootCertificates { get; set; } = new();
    }

    private readonly struct AuthenticatedElfComponent
    {
        public AuthenticatedElfComponent(int imageOffset, ElfImageInfo info)
        {
            ImageOffset = imageOffset;
            Info = info;
        }

        public int ImageOffset { get; }
        public ElfImageInfo Info { get; }
    }
}
