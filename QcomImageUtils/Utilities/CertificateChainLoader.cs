using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using QcomImageUtils.Models;
using QcomImageUtils.Types;

namespace QcomImageUtils.Utilities;

internal sealed class CertificateChainSummary
{
    public Dictionary<string, string> Attributes { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string RootSubject { get; set; } = string.Empty;
    public string RootSha256 { get; set; } = string.Empty;
    public string RootSha384 { get; set; } = string.Empty;
}

/// <summary>
/// 解析连续 DER 编码的 Qualcomm 证书链并验证尾部填充。
/// </summary>
internal static class CertificateChainLoader
{
    private const string OrganizationalUnitOid = "2.5.4.11";

    public static bool TryLoad(
        ReadOnlySpan<byte> data,
        CertificateChainType chainType,
        bool exportPem,
        int maximumCertificateCount,
        uint? selectedRootSlot,
        out List<ImageCertItem> certificates,
        out CertificateChainSummary summary,
        out string error)
    {
        certificates = new List<ImageCertItem>(Math.Min(maximumCertificateCount, 4));
        summary = new CertificateChainSummary();
        if (!TryReadEncodedCertificates(data, maximumCertificateCount,
                out List<byte[]> encodedCertificates, out error))
            return false;

        var rootIndices = new List<int>();
        var rootHashes = new HashSet<string>(StringComparer.Ordinal);
        for (int index = 0; index < encodedCertificates.Count; index++)
        {
            byte[] encodedCertificate = encodedCertificates[index];
            try
            {
#if NET9_0_OR_GREATER
                using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(encodedCertificate);
#else
                using var certificate = new X509Certificate2(encodedCertificate);
#endif
                if (index == 0)
                    ReadAttributes(certificate.SubjectName.RawData, summary.Attributes);

                string sha256 = HashUtility.ComputeSha256Hex(encodedCertificate);
                bool isRoot = CertificateChainVerifier.IsSelfSignedCertificate(
                    encodedCertificate,
                    certificate);
                if (isRoot)
                {
                    rootIndices.Add(index);
                    rootHashes.Add(sha256);
                }

                certificates.Add(new ImageCertItem
                {
                    ChainType = chainType,
                    Index = index,
                    IsRoot = isRoot,
                    Subject = certificate.Subject,
                    Issuer = certificate.Issuer,
                    SerialNumber = certificate.SerialNumber,
                    Sha256 = sha256,
                    CertPem = exportPem ? ExportPem(encodedCertificate) : string.Empty
                });
            }
            catch (CryptographicException exception)
            {
                error = $"证书链中的第 {index} 张 X.509 证书无效: {exception.Message}";
                return false;
            }
        }

        int? selectedRootIndex = null;
        if (selectedRootSlot is uint rootSlot)
        {
            if (rootSlot >= (uint)rootIndices.Count)
            {
                error = $"MRC Root 槽位 {rootSlot} 超出证书包的 {rootIndices.Count} 个 Root 槽位";
                return false;
            }

            selectedRootIndex = rootIndices[checked((int)rootSlot)];
        }
        else if (rootHashes.Count == 1 && rootIndices.Count > 0)
        {
            selectedRootIndex = rootIndices[0];
        }

        if (selectedRootIndex is int rootIndex)
        {
            ImageCertItem root = certificates[rootIndex];
            summary.RootSubject = root.Subject;
            summary.RootSha256 = root.Sha256;
            summary.RootSha384 = HashUtility.ComputeSha384Hex(encodedCertificates[rootIndex]);
        }

        return true;
    }

    public static bool TryReadEncodedCertificates(
        ReadOnlySpan<byte> data,
        int maximumCertificateCount,
        out List<byte[]> certificates,
        out string error)
    {
        certificates = new List<byte[]>(Math.Min(maximumCertificateCount, 4));
        error = string.Empty;
        int offset = 0;

        while (offset < data.Length)
        {
            ReadOnlySpan<byte> remaining = data.Slice(offset);
            if (remaining[0] is 0x00 or 0xFF)
            {
                if (certificates.Count == 0 || !IsPadding(remaining))
                {
                    error = $"证书链在偏移 {offset} 处包含无效填充";
                    return false;
                }

                break;
            }

            if (remaining[0] != 0x30)
            {
                error = $"证书链在偏移 {offset} 处缺少 DER SEQUENCE 标记";
                return false;
            }

            if (certificates.Count >= maximumCertificateCount)
            {
                error = $"证书数量超过上限 {maximumCertificateCount}";
                return false;
            }

            int bytesConsumed;
            try
            {
                AsnDecoder.ReadEncodedValue(
                    remaining,
                    AsnEncodingRules.DER,
                    out _,
                    out _,
                    out bytesConsumed);
            }
            catch (AsnContentException exception)
            {
                error = $"证书链在偏移 {offset} 处的 DER 数据无效: {exception.Message}";
                return false;
            }

            certificates.Add(remaining.Slice(0, bytesConsumed).ToArray());
            offset += bytesConsumed;
        }

        if (certificates.Count == 0)
        {
            error = "证书链中没有 X.509 证书";
            return false;
        }

        return true;
    }

    private static void ReadAttributes(byte[] encodedSubject, Dictionary<string, string> attributes)
    {
        IReadOnlyList<string> values = X500NameReader.GetValues(encodedSubject, OrganizationalUnitOid);
        for (int index = 0; index < values.Count; index++)
        {
            string[] parts = values[index].Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 3)
                attributes[parts[2]] = parts[1];
        }
    }

    private static bool IsPadding(ReadOnlySpan<byte> data)
    {
        for (int index = 0; index < data.Length; index++)
        {
            if (data[index] is not (0x00 or 0xFF))
                return false;
        }

        return true;
    }

    private static string ExportPem(byte[] encodedCertificate)
    {
        string body = Convert.ToBase64String(
            encodedCertificate,
            Base64FormattingOptions.InsertLineBreaks).Replace("\r\n", "\n");
        return $"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----";
    }
}
