using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QcomImageUtils.Utilities;

internal static class ImageSignatureVerifier
{
    private const string OrganizationalUnitOid = "2.5.4.11";
    private const ulong InnerPad = 0x3636363636363636;
    private const ulong OuterPad = 0x5C5C5C5C5C5C5C5C;

    public static bool TryVerify(
        byte[] leafCertificate,
        uint mbnVersion,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<HashMask> masks,
        ReadOnlySpan<byte> signature,
        ImageHashAlgorithm preferredHash,
        out string algorithm,
        out bool unsupported,
        out string error)
    {
        algorithm = string.Empty;
        unsupported = false;
        error = string.Empty;

        try
        {
            using X509Certificate2 certificate =
                CertificateChainVerifier.LoadCertificate(leafCertificate);
            Span<byte> digest = stackalloc byte[64];
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa is not null)
            {
                if (!TryNormalizeRsaSignature(signature, rsa.KeySize, out byte[] normalized))
                {
                    error = "RSA 签名长度与证书公钥不匹配";
                    return false;
                }

                if (mbnVersion is 3 or 5
                    && TryVerifyQualcommHmac(certificate, rsa, signedData, masks, normalized))
                {
                    algorithm = "RSA-QCOM-HMAC-SHA256";
                    return true;
                }

                IReadOnlyList<ImageHashAlgorithm> candidates =
                    GetHashCandidates(certificate, preferredHash);
                for (int index = 0; index < candidates.Count; index++)
                {
                    ImageHashAlgorithm hashAlgorithm = candidates[index];
                    CryptographicHash.Compute(hashAlgorithm, signedData, masks, digest);
                    ReadOnlySpan<byte> hash = digest.Slice(
                        0,
                        CryptographicHash.GetDigestLength(hashAlgorithm));
                    if (VerifyRsaHash(rsa, hash, normalized,
                            hashAlgorithm, RSASignaturePadding.Pss))
                    {
                        algorithm = $"RSA-PSS-{CryptographicHash.GetDisplayName(hashAlgorithm)}";
                        return true;
                    }

                    if (VerifyRsaHash(rsa, hash, normalized,
                            hashAlgorithm, RSASignaturePadding.Pkcs1))
                    {
                        algorithm = $"RSA-PKCS1-{CryptographicHash.GetDisplayName(hashAlgorithm)}";
                        return true;
                    }
                }

                error = "RSA 镜像签名不匹配";
                return false;
            }

            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is null)
            {
                unsupported = true;
                error = "签名证书的公钥算法不受支持";
                return false;
            }

            if (!TryTrimDerSignature(signature, out byte[] derSignature)
                || !CertificateChainVerifier.TryConvertDerEcdsaSignature(
                    derSignature,
                    checked((ecdsa.KeySize + 7) / 8),
                    out byte[] p1363Signature))
            {
                error = "ECDSA 镜像签名编码无效";
                return false;
            }

            IReadOnlyList<ImageHashAlgorithm> ecdsaCandidates =
                GetHashCandidates(certificate, preferredHash);
            for (int index = 0; index < ecdsaCandidates.Count; index++)
            {
                ImageHashAlgorithm hashAlgorithm = ecdsaCandidates[index];
                CryptographicHash.Compute(hashAlgorithm, signedData, masks, digest);
                int digestLength = CryptographicHash.GetDigestLength(hashAlgorithm);
                if (!VerifyEcdsaHash(
                        ecdsa,
                        digest.Slice(0, digestLength),
                        p1363Signature))
                {
                    continue;
                }

                algorithm = $"ECDSA-{CryptographicHash.GetDisplayName(hashAlgorithm)}";
                return true;
            }

            error = "ECDSA 镜像签名不匹配";
            return false;
        }
        catch (CryptographicException exception)
        {
            error = $"镜像签名验证失败: {exception.Message}";
            return false;
        }
    }

    private static bool TryVerifyQualcommHmac(
        X509Certificate2 certificate,
        RSA rsa,
        ReadOnlySpan<byte> signedData,
        ReadOnlySpan<HashMask> masks,
        ReadOnlySpan<byte> signature)
    {
        if (!TryReadSigningIdentifiers(certificate, out ulong softwareId, out ulong hardwareId))
            return false;

        Span<byte> first = stackalloc byte[32];
        Span<byte> second = stackalloc byte[32];
        Span<byte> third = stackalloc byte[32];
        Span<byte> identifier = stackalloc byte[8];
        CryptographicHash.Compute(ImageHashAlgorithm.Sha256, signedData, masks, first);
        BinaryPrimitives.WriteUInt64BigEndian(identifier, softwareId ^ InnerPad);
        CryptographicHash.Compute(ImageHashAlgorithm.Sha256, identifier, first, second);
        BinaryPrimitives.WriteUInt64BigEndian(identifier, hardwareId ^ OuterPad);
        CryptographicHash.Compute(ImageHashAlgorithm.Sha256, identifier, second, third);
        return VerifyRawPkcs1Digest(rsa, signature, third);
    }

    private static bool VerifyRawPkcs1Digest(
        RSA rsa,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> digest)
    {
        RSAParameters parameters = rsa.ExportParameters(false);
        if (parameters.Modulus is null || parameters.Exponent is null)
            return false;

        BigInteger modulus = FromBigEndianUnsigned(parameters.Modulus);
        BigInteger exponent = FromBigEndianUnsigned(parameters.Exponent);
        BigInteger signatureValue = FromBigEndianUnsigned(signature);
        if (signatureValue.Sign < 0 || signatureValue >= modulus)
            return false;

        BigInteger encodedValue = BigInteger.ModPow(signatureValue, exponent, modulus);
        byte[] encoded = ToBigEndianUnsigned(encodedValue, parameters.Modulus.Length);
        if (encoded.Length < digest.Length + 11
            || encoded[0] != 0
            || encoded[1] != 1)
        {
            return false;
        }

        int separator = encoded.Length - digest.Length - 1;
        if (separator < 10 || encoded[separator] != 0)
            return false;
        for (int index = 2; index < separator; index++)
        {
            if (encoded[index] != 0xFF)
                return false;
        }

        return FixedTimeEquals(encoded.AsSpan(separator + 1), digest);
    }

    private static bool TryReadSigningIdentifiers(
        X509Certificate2 certificate,
        out ulong softwareId,
        out ulong hardwareId)
    {
        softwareId = 0;
        hardwareId = 0;
        bool hasSoftwareId = false;
        bool hasHardwareId = false;
        IReadOnlyList<string> values = X500NameReader.GetValues(
            certificate.SubjectName.RawData,
            OrganizationalUnitOid);
        for (int index = 0; index < values.Count; index++)
        {
            string[] parts = values[index].Split(
                new[] { ' ' },
                StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3
                || !ulong.TryParse(parts[1], NumberStyles.AllowHexSpecifier,
                    CultureInfo.InvariantCulture, out ulong value))
            {
                continue;
            }

            if (string.Equals(parts[2], "SW_ID", StringComparison.OrdinalIgnoreCase))
            {
                softwareId = value;
                hasSoftwareId = true;
            }
            else if (string.Equals(parts[2], "HW_ID", StringComparison.OrdinalIgnoreCase))
            {
                hardwareId = value;
                hasHardwareId = true;
            }
        }

        return hasSoftwareId && hasHardwareId;
    }

    private static IReadOnlyList<ImageHashAlgorithm> GetHashCandidates(
        X509Certificate2 certificate,
        ImageHashAlgorithm preferred)
    {
        var candidates = new List<ImageHashAlgorithm>(5);
        if (TryReadCertificateHashAlgorithm(certificate, out ImageHashAlgorithm certificateHash))
            candidates.Add(certificateHash);
        AddUnique(candidates, preferred);
        AddUnique(candidates, ImageHashAlgorithm.Sha256);
        AddUnique(candidates, ImageHashAlgorithm.Sha384);
        AddUnique(candidates, ImageHashAlgorithm.Sha512);
        AddUnique(candidates, ImageHashAlgorithm.Sha1);
        return candidates;
    }

    private static bool TryReadCertificateHashAlgorithm(
        X509Certificate2 certificate,
        out ImageHashAlgorithm algorithm)
    {
        IReadOnlyList<string> values = X500NameReader.GetValues(
            certificate.SubjectName.RawData,
            OrganizationalUnitOid);
        for (int index = 0; index < values.Count; index++)
        {
            string value = values[index];
            if (value.IndexOf("SHA384", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                algorithm = ImageHashAlgorithm.Sha384;
                return true;
            }

            if (value.IndexOf("SHA512", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                algorithm = ImageHashAlgorithm.Sha512;
                return true;
            }

            if (value.IndexOf("SHA256", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                algorithm = ImageHashAlgorithm.Sha256;
                return true;
            }

            if (value.IndexOf("SHA1", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                algorithm = ImageHashAlgorithm.Sha1;
                return true;
            }
        }

        algorithm = default;
        return false;
    }

    private static void AddUnique(List<ImageHashAlgorithm> values, ImageHashAlgorithm value)
    {
        if (!values.Contains(value))
            values.Add(value);
    }

    private static bool TryNormalizeRsaSignature(
        ReadOnlySpan<byte> signature,
        int keySize,
        out byte[] normalized)
    {
        normalized = Array.Empty<byte>();
        int length = checked((keySize + 7) / 8);
        if (signature.Length == length)
        {
            normalized = signature.ToArray();
            return true;
        }

        if (signature.Length < length)
            return false;

        ReadOnlySpan<byte> trailing = signature.Slice(length);
        if (IsPadding(trailing))
        {
            normalized = signature.Slice(0, length).ToArray();
            return true;
        }

        ReadOnlySpan<byte> leading = signature.Slice(0, signature.Length - length);
        if (!IsPadding(leading))
            return false;
        normalized = signature.Slice(signature.Length - length).ToArray();
        return true;
    }

    private static bool TryTrimDerSignature(
        ReadOnlySpan<byte> signature,
        out byte[] derSignature)
    {
        derSignature = Array.Empty<byte>();
        if (signature.IsEmpty || signature[0] != 0x30)
            return false;

        try
        {
            AsnDecoder.ReadEncodedValue(
                signature,
                AsnEncodingRules.DER,
                out _,
                out _,
                out int consumed);
            if (!IsPadding(signature.Slice(consumed)))
                return false;
            derSignature = signature.Slice(0, consumed).ToArray();
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool VerifyRsaHash(
        RSA rsa,
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature,
        ImageHashAlgorithm algorithm,
        RSASignaturePadding padding)
    {
        try
        {
#if NET8_0_OR_GREATER
            if (rsa.VerifyHash(hash, signature, CryptographicHash.GetName(algorithm), padding))
                return true;
            Span<byte> reversed = signature.Length <= 1024
                ? stackalloc byte[signature.Length]
                : new byte[signature.Length];
            signature.CopyTo(reversed);
            reversed.Reverse();
            return rsa.VerifyHash(hash, reversed, CryptographicHash.GetName(algorithm), padding);
#else
            byte[] hashBytes = hash.ToArray();
            byte[] signatureBytes = signature.ToArray();
            if (rsa.VerifyHash(hashBytes, signatureBytes, CryptographicHash.GetName(algorithm), padding))
                return true;
            Array.Reverse(signatureBytes);
            return rsa.VerifyHash(hashBytes, signatureBytes, CryptographicHash.GetName(algorithm), padding);
#endif
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool VerifyEcdsaHash(
        ECDsa ecdsa,
        ReadOnlySpan<byte> hash,
        ReadOnlySpan<byte> signature)
    {
#if NET8_0_OR_GREATER
        return ecdsa.VerifyHash(hash, signature);
#else
        return ecdsa.VerifyHash(hash.ToArray(), signature.ToArray());
#endif
    }

    private static BigInteger FromBigEndianUnsigned(ReadOnlySpan<byte> value)
    {
        byte[] littleEndian = new byte[value.Length + 1];
        for (int index = 0; index < value.Length; index++)
            littleEndian[index] = value[value.Length - index - 1];
        return new BigInteger(littleEndian);
    }

    private static byte[] ToBigEndianUnsigned(BigInteger value, int length)
    {
        byte[] littleEndian = value.ToByteArray();
        int valueLength = littleEndian.Length;
        while (valueLength > 1 && littleEndian[valueLength - 1] == 0)
            valueLength--;
        if (valueLength > length)
            return Array.Empty<byte>();

        var result = new byte[length];
        for (int index = 0; index < valueLength; index++)
            result[length - index - 1] = littleEndian[index];
        return result;
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
