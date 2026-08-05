using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QcomImageUtils.Utilities;

internal sealed class CertificatePackageVerification
{
    public List<byte[]> Certificates { get; } = new();
    public List<int> ValidRootIndices { get; } = new();
    public int? SelectedRootIndex { get; set; }
}

internal static class CertificateChainVerifier
{
    private const string RsaSha1Oid = "1.2.840.113549.1.1.5";
    private const string RsaPssOid = "1.2.840.113549.1.1.10";
    private const string RsaSha256Oid = "1.2.840.113549.1.1.11";
    private const string RsaSha384Oid = "1.2.840.113549.1.1.12";
    private const string RsaSha512Oid = "1.2.840.113549.1.1.13";
    private const string Mgf1Oid = "1.2.840.113549.1.1.8";
    private const string EcdsaSha256Oid = "1.2.840.10045.4.3.2";
    private const string EcdsaSha384Oid = "1.2.840.10045.4.3.3";
    private const string EcdsaSha512Oid = "1.2.840.10045.4.3.4";
    private const string Sha1Oid = "1.3.14.3.2.26";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";

    public static bool TryVerify(
        ReadOnlySpan<byte> chainData,
        int maximumCertificateCount,
        out List<byte[]> encodedCertificates,
        out string rootSha256,
        out string rootSha384,
        out string error)
    {
        bool valid = TryVerify(
            chainData,
            maximumCertificateCount,
            selectedRootSlot: null,
            out CertificatePackageVerification verification,
            out error);
        encodedCertificates = verification.Certificates;
        rootSha256 = string.Empty;
        rootSha384 = string.Empty;
        if (valid && verification.SelectedRootIndex is int rootIndex)
        {
            byte[] encodedRoot = encodedCertificates[rootIndex];
            rootSha256 = HashUtility.ComputeSha256Hex(encodedRoot);
            rootSha384 = HashUtility.ComputeSha384Hex(encodedRoot);
        }

        return valid;
    }

    public static bool TryVerify(
        ReadOnlySpan<byte> chainData,
        int maximumCertificateCount,
        int? selectedRootSlot,
        out CertificatePackageVerification verification,
        out string error)
    {
        verification = new CertificatePackageVerification();
        if (!CertificateChainLoader.TryReadEncodedCertificates(
                chainData,
                maximumCertificateCount,
                out List<byte[]> encodedCertificates,
                out error))
        {
            return false;
        }

        verification.Certificates.AddRange(encodedCertificates);
        var certificates = new List<X509Certificate2>(encodedCertificates.Count);
        try
        {
            for (int index = 0; index < encodedCertificates.Count; index++)
                certificates.Add(LoadCertificate(encodedCertificates[index]));

            var edgeStates = new sbyte[certificates.Count, certificates.Count];
            var authorityPolicies = new CertificateAuthorityPolicy[certificates.Count];
            var authorityPolicyStates = new sbyte[certificates.Count];
            var rootIndices = new List<int>();
            for (int index = 0; index < certificates.Count; index++)
            {
                if (IsSelfSignedCertificate(
                        encodedCertificates[index],
                        certificates[index],
                        edgeStates,
                        index))
                {
                    rootIndices.Add(index);
                }
            }

            if (rootIndices.Count == 0)
            {
                error = "证书包中没有自颁发 Root 证书";
                return false;
            }

            if (selectedRootSlot is int slot
                && (slot < 0 || slot >= rootIndices.Count))
            {
                error = $"MRC Root 槽位 {slot} 超出证书包的 {rootIndices.Count} 个 Root 槽位";
                return false;
            }

            var uniqueRoots = new HashSet<string>(StringComparer.Ordinal);
            int firstTarget = selectedRootSlot is int selectedSlot
                ? selectedSlot
                : 0;
            int targetCount = selectedRootSlot.HasValue
                ? 1
                : rootIndices.Count;
            for (int targetOffset = 0; targetOffset < targetCount; targetOffset++)
            {
                int rootIndex = rootIndices[firstTarget + targetOffset];
                if (!TryGetCertificateEdgeState(
                        rootIndex,
                        rootIndex,
                        encodedCertificates,
                        certificates,
                        edgeStates))
                {
                    continue;
                }

                var visiting = new bool[certificates.Count];
                if (!HasPathToRoot(
                        0,
                        rootIndex,
                        encodedCertificates,
                        certificates,
                        edgeStates,
                        authorityPolicies,
                        authorityPolicyStates,
                        nonSelfIssuedCaBelow: 0,
                        visiting))
                {
                    continue;
                }

                string rootHash = HashUtility.ComputeSha256Hex(encodedCertificates[rootIndex]);
                if (uniqueRoots.Add(rootHash))
                    verification.ValidRootIndices.Add(rootIndex);
            }

            if (verification.ValidRootIndices.Count == 0)
            {
                error = selectedRootSlot.HasValue
                    ? "MRC 选择的 Root 无法建立有效的叶证书签名路径"
                    : "证书包无法从叶证书建立到有效自签 Root 的路径";
                return false;
            }

            if (selectedRootSlot.HasValue || verification.ValidRootIndices.Count == 1)
                verification.SelectedRootIndex = verification.ValidRootIndices[0];
            error = string.Empty;
            return true;
        }
        catch (CryptographicException exception)
        {
            error = $"无法读取证书公钥: {exception.Message}";
            return false;
        }
        finally
        {
            for (int index = 0; index < certificates.Count; index++)
                certificates[index].Dispose();
        }
    }

    private static bool HasPathToRoot(
        int certificateIndex,
        int rootIndex,
        IReadOnlyList<byte[]> encodedCertificates,
        IReadOnlyList<X509Certificate2> certificates,
        sbyte[,] edgeStates,
        CertificateAuthorityPolicy[] authorityPolicies,
        sbyte[] authorityPolicyStates,
        int nonSelfIssuedCaBelow,
        bool[] visiting)
    {
        if (certificateIndex == rootIndex)
            return true;

        visiting[certificateIndex] = true;
        X509Certificate2 certificate = certificates[certificateIndex];
        for (int issuerIndex = 0; issuerIndex < certificates.Count; issuerIndex++)
        {
            X509Certificate2 issuer = certificates[issuerIndex];
            if (issuerIndex == certificateIndex
                || visiting[issuerIndex]
                || !NamesMatch(certificate.IssuerName, issuer.SubjectName)
                || issuerIndex != rootIndex
                && (!TryGetCertificateAuthorityPolicy(
                        issuerIndex,
                        certificates,
                        authorityPolicies,
                        authorityPolicyStates,
                        out CertificateAuthorityPolicy policy)
                    || policy.HasPathLengthConstraint
                    && nonSelfIssuedCaBelow > policy.PathLengthConstraint)
                || !TryGetCertificateEdgeState(
                    certificateIndex,
                    issuerIndex,
                    encodedCertificates,
                    certificates,
                    edgeStates))
            {
                continue;
            }

            int nextCaCount = nonSelfIssuedCaBelow;
            if (issuerIndex != rootIndex
                && !NamesMatch(issuer.SubjectName, issuer.IssuerName))
            {
                nextCaCount++;
            }

            if (HasPathToRoot(
                    issuerIndex,
                    rootIndex,
                    encodedCertificates,
                    certificates,
                    edgeStates,
                    authorityPolicies,
                    authorityPolicyStates,
                    nextCaCount,
                    visiting))
            {
                visiting[certificateIndex] = false;
                return true;
            }
        }

        visiting[certificateIndex] = false;
        return false;
    }

    private static bool TryGetCertificateAuthorityPolicy(
        int certificateIndex,
        IReadOnlyList<X509Certificate2> certificates,
        CertificateAuthorityPolicy[] policies,
        sbyte[] states,
        out CertificateAuthorityPolicy policy)
    {
        sbyte state = states[certificateIndex];
        if (state != 0)
        {
            policy = policies[certificateIndex];
            return state > 0;
        }

        bool hasBasicConstraints = false;
        bool hasKeyUsage = false;
        bool certificateAuthority = false;
        bool hasPathLengthConstraint = false;
        int pathLengthConstraint = 0;
        X509KeyUsageFlags keyUsages = 0;
        try
        {
            X509ExtensionCollection extensions = certificates[certificateIndex].Extensions;
            for (int index = 0; index < extensions.Count; index++)
            {
                X509Extension extension = extensions[index];
                switch (extension.Oid?.Value)
                {
                    case "2.5.29.19":
                        if (hasBasicConstraints)
                        {
                            policy = default;
                            states[certificateIndex] = -1;
                            return false;
                        }

                        var basicConstraints = extension as X509BasicConstraintsExtension
                                               ?? new X509BasicConstraintsExtension();
                        if (!ReferenceEquals(basicConstraints, extension))
                            basicConstraints.CopyFrom(extension);
                        hasBasicConstraints = true;
                        certificateAuthority = basicConstraints.CertificateAuthority;
                        hasPathLengthConstraint = basicConstraints.HasPathLengthConstraint;
                        pathLengthConstraint = basicConstraints.PathLengthConstraint;
                        break;
                    case "2.5.29.15":
                        if (hasKeyUsage)
                        {
                            policy = default;
                            states[certificateIndex] = -1;
                            return false;
                        }

                        var keyUsage = extension as X509KeyUsageExtension
                                       ?? new X509KeyUsageExtension();
                        if (!ReferenceEquals(keyUsage, extension))
                            keyUsage.CopyFrom(extension);
                        hasKeyUsage = true;
                        keyUsages = keyUsage.KeyUsages;
                        break;
                }
            }
        }
        catch (CryptographicException)
        {
            policy = default;
            states[certificateIndex] = -1;
            return false;
        }

        policy = new CertificateAuthorityPolicy(
            hasPathLengthConstraint,
            pathLengthConstraint);
        policies[certificateIndex] = policy;
        bool valid = hasBasicConstraints
                     && certificateAuthority
                     && (!hasKeyUsage
                         || (keyUsages & X509KeyUsageFlags.KeyCertSign) != 0);
        states[certificateIndex] = valid ? (sbyte)1 : (sbyte)-1;
        return valid;
    }

    private static bool TryGetCertificateEdgeState(
        int certificateIndex,
        int issuerIndex,
        IReadOnlyList<byte[]> encodedCertificates,
        IReadOnlyList<X509Certificate2> certificates,
        sbyte[,] edgeStates)
    {
        sbyte state = edgeStates[certificateIndex, issuerIndex];
        if (state != 0)
            return state > 0;

        bool valid = TryVerifyCertificateSignature(
            encodedCertificates[certificateIndex],
            certificates[issuerIndex],
            out _);
        edgeStates[certificateIndex, issuerIndex] = valid ? (sbyte)1 : (sbyte)-1;
        return valid;
    }

    public static X509Certificate2 LoadCertificate(byte[] encodedCertificate)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(encodedCertificate);
#else
        return new X509Certificate2(encodedCertificate);
#endif
    }

    internal static bool IsSelfSignedCertificate(
        byte[] encodedCertificate,
        X509Certificate2 certificate)
    {
        return NamesMatch(certificate.IssuerName, certificate.SubjectName)
               && TryVerifyCertificateSignature(encodedCertificate, certificate, out _);
    }

    private static bool IsSelfSignedCertificate(
        byte[] encodedCertificate,
        X509Certificate2 certificate,
        sbyte[,] edgeStates,
        int index)
    {
        if (!NamesMatch(certificate.IssuerName, certificate.SubjectName))
            return false;

        bool valid = TryVerifyCertificateSignature(encodedCertificate, certificate, out _);
        edgeStates[index, index] = valid ? (sbyte)1 : (sbyte)-1;
        return valid;
    }

    public static bool TryConvertDerEcdsaSignature(
        ReadOnlySpan<byte> signature,
        int fieldLength,
        out byte[] p1363Signature)
    {
        p1363Signature = Array.Empty<byte>();
        try
        {
            var reader = new AsnReader(signature.ToArray(), AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            ReadOnlySpan<byte> r = sequence.ReadIntegerBytes().Span;
            ReadOnlySpan<byte> s = sequence.ReadIntegerBytes().Span;
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            r = TrimPositiveInteger(r);
            s = TrimPositiveInteger(s);
            if (r.IsEmpty || s.IsEmpty || r.Length > fieldLength || s.Length > fieldLength)
                return false;

            p1363Signature = new byte[fieldLength * 2];
            r.CopyTo(p1363Signature.AsSpan(fieldLength - r.Length, r.Length));
            s.CopyTo(p1363Signature.AsSpan(fieldLength * 2 - s.Length, s.Length));
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool TryVerifyCertificateSignature(
        byte[] encodedCertificate,
        X509Certificate2 issuer,
        out string error)
    {
        if (!TryReadCertificateSignature(encodedCertificate,
                out byte[] signedData, out string oid, out ReadOnlyMemory<byte> parameters,
                out byte[] signature, out error))
            return false;

        if (TryGetRsaHashAlgorithm(oid, parameters, out ImageHashAlgorithm rsaHash))
        {
            using RSA? rsa = issuer.GetRSAPublicKey();
            if (rsa is null)
            {
                error = "颁发者证书没有 RSA 公钥";
                return false;
            }

            RSASignaturePadding padding = oid == RsaPssOid
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
            bool valid = rsa.VerifyData(signedData, signature,
                CryptographicHash.GetName(rsaHash), padding);
            error = valid ? string.Empty : "RSA 证书签名不匹配";
            return valid;
        }

        if (TryGetEcdsaHashAlgorithm(oid, out ImageHashAlgorithm ecdsaHash))
        {
            using ECDsa? ecdsa = issuer.GetECDsaPublicKey();
            if (ecdsa is null)
            {
                error = "颁发者证书没有 ECDSA 公钥";
                return false;
            }

            int fieldLength = checked((ecdsa.KeySize + 7) / 8);
            if (!TryConvertDerEcdsaSignature(signature, fieldLength, out byte[] p1363))
            {
                error = "ECDSA 证书签名编码无效";
                return false;
            }

            bool valid = ecdsa.VerifyData(
                signedData,
                p1363,
                CryptographicHash.GetName(ecdsaHash));
            error = valid ? string.Empty : "ECDSA 证书签名不匹配";
            return valid;
        }

        error = $"不支持证书签名算法 {oid}";
        return false;
    }

    private static bool TryReadCertificateSignature(
        byte[] encodedCertificate,
        out byte[] signedData,
        out string oid,
        out ReadOnlyMemory<byte> parameters,
        out byte[] signature,
        out string error)
    {
        signedData = Array.Empty<byte>();
        oid = string.Empty;
        parameters = ReadOnlyMemory<byte>.Empty;
        signature = Array.Empty<byte>();
        error = string.Empty;
        try
        {
            var reader = new AsnReader(encodedCertificate, AsnEncodingRules.DER);
            AsnReader certificate = reader.ReadSequence();
            signedData = certificate.ReadEncodedValue().ToArray();
            ReadOnlyMemory<byte> encodedAlgorithm = certificate.ReadEncodedValue();
            var algorithmReader = new AsnReader(encodedAlgorithm, AsnEncodingRules.DER);
            AsnReader algorithm = algorithmReader.ReadSequence();
            oid = algorithm.ReadObjectIdentifier();
            if (algorithm.HasData)
                parameters = algorithm.ReadEncodedValue();
            algorithm.ThrowIfNotEmpty();
            algorithmReader.ThrowIfNotEmpty();
            if (!TryReadTbsSignatureAlgorithm(signedData, out ReadOnlyMemory<byte> tbsAlgorithm)
                || !encodedAlgorithm.Span.SequenceEqual(tbsAlgorithm.Span))
            {
                error = "证书内外层签名算法声明不一致";
                return false;
            }

            signature = certificate.ReadBitString(out int unusedBitCount);
            if (unusedBitCount != 0)
            {
                error = "证书签名包含未使用位";
                return false;
            }

            certificate.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return true;
        }
        catch (AsnContentException exception)
        {
            error = $"证书 ASN.1 结构无效: {exception.Message}";
            return false;
        }
    }

    private static bool TryReadTbsSignatureAlgorithm(
        ReadOnlyMemory<byte> signedData,
        out ReadOnlyMemory<byte> algorithm)
    {
        algorithm = ReadOnlyMemory<byte>.Empty;
        var reader = new AsnReader(signedData, AsnEncodingRules.DER);
        AsnReader certificate = reader.ReadSequence();
        var versionTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        if (certificate.HasData && certificate.PeekTag().HasSameClassAndValue(versionTag))
            certificate.ReadEncodedValue();
        certificate.ReadIntegerBytes();
        algorithm = certificate.ReadEncodedValue();
        var algorithmReader = new AsnReader(algorithm, AsnEncodingRules.DER);
        AsnReader sequence = algorithmReader.ReadSequence();
        sequence.ReadObjectIdentifier();
        if (sequence.HasData)
            sequence.ReadEncodedValue();
        sequence.ThrowIfNotEmpty();
        algorithmReader.ThrowIfNotEmpty();
        return true;
    }

    private static bool TryGetRsaHashAlgorithm(
        string oid,
        ReadOnlyMemory<byte> parameters,
        out ImageHashAlgorithm algorithm)
    {
        switch (oid)
        {
            case RsaSha1Oid:
                algorithm = ImageHashAlgorithm.Sha1;
                return true;
            case RsaSha256Oid:
                algorithm = ImageHashAlgorithm.Sha256;
                return true;
            case RsaSha384Oid:
                algorithm = ImageHashAlgorithm.Sha384;
                return true;
            case RsaSha512Oid:
                algorithm = ImageHashAlgorithm.Sha512;
                return true;
            case RsaPssOid:
                return TryReadPssHashAlgorithm(parameters, out algorithm);
            default:
                algorithm = default;
                return false;
        }
    }

    private static bool TryReadPssHashAlgorithm(
        ReadOnlyMemory<byte> parameters,
        out ImageHashAlgorithm algorithm)
    {
        algorithm = ImageHashAlgorithm.Sha1;
        try
        {
            if (parameters.IsEmpty)
                return false;

            var reader = new AsnReader(parameters, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            var hashTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            var maskTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
            var saltTag = new Asn1Tag(TagClass.ContextSpecific, 2, true);
            var trailerTag = new Asn1Tag(TagClass.ContextSpecific, 3, true);
            ImageHashAlgorithm hashAlgorithm = ImageHashAlgorithm.Sha1;
            ImageHashAlgorithm maskHashAlgorithm = ImageHashAlgorithm.Sha1;
            int saltLength = 20;
            int trailerField = 1;

            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(hashTag))
            {
                AsnReader explicitHash = sequence.ReadSequence(hashTag);
                if (!TryReadHashAlgorithmIdentifier(explicitHash, out hashAlgorithm))
                    return false;
                explicitHash.ThrowIfNotEmpty();
            }

            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(maskTag))
            {
                AsnReader explicitMask = sequence.ReadSequence(maskTag);
                AsnReader maskIdentifier = explicitMask.ReadSequence();
                if (!string.Equals(maskIdentifier.ReadObjectIdentifier(), Mgf1Oid,
                        StringComparison.Ordinal)
                    || !TryReadHashAlgorithmIdentifier(
                        maskIdentifier,
                        out maskHashAlgorithm))
                {
                    return false;
                }

                maskIdentifier.ThrowIfNotEmpty();
                explicitMask.ThrowIfNotEmpty();
            }

            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(saltTag))
            {
                AsnReader explicitSalt = sequence.ReadSequence(saltTag);
                BigInteger value = explicitSalt.ReadInteger();
                if (value < 0 || value > int.MaxValue)
                    return false;
                saltLength = (int)value;
                explicitSalt.ThrowIfNotEmpty();
            }

            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(trailerTag))
            {
                AsnReader explicitTrailer = sequence.ReadSequence(trailerTag);
                BigInteger value = explicitTrailer.ReadInteger();
                if (value < 0 || value > int.MaxValue)
                    return false;
                trailerField = (int)value;
                explicitTrailer.ThrowIfNotEmpty();
            }

            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            if (maskHashAlgorithm != hashAlgorithm
                || saltLength != CryptographicHash.GetDigestLength(hashAlgorithm)
                || trailerField != 1)
            {
                return false;
            }

            algorithm = hashAlgorithm;
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static bool TryReadHashAlgorithmIdentifier(
        AsnReader reader,
        out ImageHashAlgorithm algorithm)
    {
        AsnReader identifier = reader.ReadSequence();
        string hashOid = identifier.ReadObjectIdentifier();
        if (identifier.HasData)
            identifier.ReadNull();
        identifier.ThrowIfNotEmpty();
        return TryMapHashOid(hashOid, out algorithm);
    }

    private static bool TryGetEcdsaHashAlgorithm(string oid, out ImageHashAlgorithm algorithm)
    {
        switch (oid)
        {
            case EcdsaSha256Oid:
                algorithm = ImageHashAlgorithm.Sha256;
                return true;
            case EcdsaSha384Oid:
                algorithm = ImageHashAlgorithm.Sha384;
                return true;
            case EcdsaSha512Oid:
                algorithm = ImageHashAlgorithm.Sha512;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    private static bool TryMapHashOid(string oid, out ImageHashAlgorithm algorithm)
    {
        switch (oid)
        {
            case Sha1Oid:
                algorithm = ImageHashAlgorithm.Sha1;
                return true;
            case Sha256Oid:
                algorithm = ImageHashAlgorithm.Sha256;
                return true;
            case Sha384Oid:
                algorithm = ImageHashAlgorithm.Sha384;
                return true;
            case Sha512Oid:
                algorithm = ImageHashAlgorithm.Sha512;
                return true;
            default:
                algorithm = default;
                return false;
        }
    }

    private static bool NamesMatch(X500DistinguishedName left, X500DistinguishedName right)
    {
        ReadOnlySpan<byte> leftRaw = left.RawData;
        ReadOnlySpan<byte> rightRaw = right.RawData;
        if (leftRaw.SequenceEqual(rightRaw))
            return true;

        return string.Equals(
            left.Decode(X500DistinguishedNameFlags.UseUTF8Encoding),
            right.Decode(X500DistinguishedNameFlags.UseUTF8Encoding),
            StringComparison.OrdinalIgnoreCase);
    }

    private static ReadOnlySpan<byte> TrimPositiveInteger(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty || (value[0] & 0x80) != 0)
            return ReadOnlySpan<byte>.Empty;
        while (value.Length > 1 && value[0] == 0)
            value = value.Slice(1);
        return value;
    }

    private readonly struct CertificateAuthorityPolicy(
        bool hasPathLengthConstraint,
        int pathLengthConstraint)
    {
        public bool HasPathLengthConstraint { get; } = hasPathLengthConstraint;
        public int PathLengthConstraint { get; } = pathLengthConstraint;
    }
}
