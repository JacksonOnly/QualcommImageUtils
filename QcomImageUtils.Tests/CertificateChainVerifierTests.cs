using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class CertificateChainVerifierTests
{
    private const int MaximumCertificateCount = 8;
    private const string RootDistinguishedName = "CN=Qcom MRC Test Root";

    [Fact]
    public void TryVerify_MrcSlotZero_SelectsFirstValidRoot()
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.ValidRoot,
            graph.UnrelatedRoot);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: 0,
            out CertificatePackageVerification verification,
            out string error);

        Assert.True(valid, error);
        Assert.Equal(2, verification.SelectedRootIndex);
        Assert.Equal([2], verification.ValidRootIndices);
    }

    [Fact]
    public void TryVerify_MrcSlotZero_RejectsUnrelatedRootAndSlotOneSelectsValidRoot()
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.UnrelatedRoot,
            graph.ValidRoot);

        bool wrongRootValid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: 0,
            out CertificatePackageVerification wrongRootVerification,
            out string wrongRootError);
        bool validRootValid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: 1,
            out CertificatePackageVerification validRootVerification,
            out string validRootError);

        Assert.False(wrongRootValid);
        Assert.Null(wrongRootVerification.SelectedRootIndex);
        Assert.Empty(wrongRootVerification.ValidRootIndices);
        Assert.NotEmpty(wrongRootError);
        Assert.True(validRootValid, validRootError);
        Assert.Equal(3, validRootVerification.SelectedRootIndex);
        Assert.Equal([3], validRootVerification.ValidRootIndices);
    }

    [Fact]
    public void TryVerify_WithoutMrc_SelectsRootFromSignaturePath()
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.UnrelatedRoot,
            graph.ValidRoot);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: null,
            out CertificatePackageVerification verification,
            out string error);

        Assert.True(valid, error);
        Assert.Equal(3, verification.SelectedRootIndex);
        Assert.Equal([3], verification.ValidRootIndices);
    }

    [Fact]
    public void TryVerify_DuplicateRoot_DeduplicatesValidEndpoints()
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.ValidRoot,
            graph.ValidRoot);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: null,
            out CertificatePackageVerification verification,
            out string error);

        Assert.True(valid, error);
        Assert.Equal(4, verification.Certificates.Count);
        Assert.Equal(2, verification.SelectedRootIndex);
        Assert.Equal([2], verification.ValidRootIndices);
    }

    [Fact]
    public void TryVerify_AdditionalUnrelatedRoot_DoesNotBecomeValidEndpoint()
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.ValidRoot,
            graph.UnrelatedRoot);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: null,
            out CertificatePackageVerification verification,
            out string error);

        Assert.True(valid, error);
        Assert.Equal(2, verification.SelectedRootIndex);
        Assert.Equal([2], verification.ValidRootIndices);
        Assert.DoesNotContain(3, verification.ValidRootIndices);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    public void TryVerify_MrcSlotOutsideRootRange_ReturnsFalse(int selectedRootSlot)
    {
        CertificateGraph graph = CreateGraph();
        byte[] package = Combine(
            graph.Leaf,
            graph.Intermediate,
            graph.ValidRoot,
            graph.UnrelatedRoot);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot,
            out CertificatePackageVerification verification,
            out string error);

        Assert.False(valid);
        Assert.Null(verification.SelectedRootIndex);
        Assert.Empty(verification.ValidRootIndices);
        Assert.NotEmpty(error);
    }

    [Fact]
    public void TryVerify_NonCaIntermediate_ReturnsFalse()
    {
        CertificateGraph graph = CreateGraph(intermediateCertificateAuthority: false);

        AssertChainRejected(Combine(graph.Leaf, graph.Intermediate, graph.ValidRoot));
    }

    [Fact]
    public void TryVerify_IntermediateWithoutKeyCertSign_ReturnsFalse()
    {
        CertificateGraph graph = CreateGraph(
            intermediateKeyUsage: X509KeyUsageFlags.DigitalSignature);

        AssertChainRejected(Combine(graph.Leaf, graph.Intermediate, graph.ValidRoot));
    }

    [Fact]
    public void TryVerify_PathLengthConstraintExceeded_ReturnsFalse()
    {
        AssertChainRejected(CreatePathLengthViolationPackage());
    }

    [Fact]
    public void TryVerify_RsaPssWithSupportedParameters_ReturnsTrue()
    {
        byte[] package = CreateDirectPssChain(PssParameterVariant.Supported);

        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: null,
            out _,
            out string error);

        Assert.True(valid, error);
    }

    [Theory]
    [InlineData(PssParameterVariant.MismatchedMaskHash)]
    [InlineData(PssParameterVariant.MismatchedSaltLength)]
    [InlineData(PssParameterVariant.UnsupportedTrailer)]
    public void TryVerify_RsaPssWithUnsupportedParameters_ReturnsFalse(
        PssParameterVariant variant)
    {
        AssertChainRejected(CreateDirectPssChain(variant));
    }

    private static CertificateGraph CreateGraph(
        bool intermediateCertificateAuthority = true,
        X509KeyUsageFlags intermediateKeyUsage =
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)
    {
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(1);
        using RSA validRootKey = RSA.Create(2048);
        using RSA unrelatedRootKey = RSA.Create(2048);
        using RSA intermediateKey = RSA.Create(2048);
        using RSA leafKey = RSA.Create(2048);
        using X509Certificate2 validRoot = CreateRoot(validRootKey, notBefore, notAfter);
        using X509Certificate2 unrelatedRoot = CreateRoot(unrelatedRootKey, notBefore, notAfter);

        var intermediateRequest = new CertificateRequest(
            "CN=Qcom MRC Test Intermediate",
            intermediateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                intermediateCertificateAuthority,
                intermediateCertificateAuthority,
                0,
                true));
        intermediateRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(intermediateKeyUsage, true));
        intermediateRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
        using X509Certificate2 encodedIntermediate = intermediateRequest.Create(
            validRoot,
            notBefore,
            notAfter,
            [0x10, 0x20, 0x30, 0x40]);
        using X509Certificate2 intermediate = encodedIntermediate.CopyWithPrivateKey(intermediateKey);

        var leafRequest = new CertificateRequest(
            "CN=Qcom MRC Test Leaf",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using X509Certificate2 leaf = leafRequest.Create(
            intermediate.SubjectName,
            X509SignatureGenerator.CreateForRSA(
                intermediateKey,
                RSASignaturePadding.Pkcs1),
            notBefore,
            notAfter,
            [0x50, 0x60, 0x70, 0x80]);

        return new CertificateGraph(
            leaf.Export(X509ContentType.Cert),
            intermediate.Export(X509ContentType.Cert),
            validRoot.Export(X509ContentType.Cert),
            unrelatedRoot.Export(X509ContentType.Cert));
    }

    private static byte[] CreatePathLengthViolationPackage()
    {
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(1);
        using RSA rootKey = RSA.Create(2048);
        using RSA upperKey = RSA.Create(2048);
        using RSA lowerKey = RSA.Create(2048);
        using RSA leafKey = RSA.Create(2048);
        using X509Certificate2 root = CreateRoot(rootKey, notBefore, notAfter);
        using X509Certificate2 upper = CreateIssuedCertificate(
            "CN=Qcom Upper Intermediate",
            upperKey,
            root,
            notBefore,
            notAfter,
            certificateAuthority: true,
            pathLengthConstraint: 0,
            [0x11, 0x12, 0x13, 0x14]);
        using X509Certificate2 lower = CreateIssuedCertificate(
            "CN=Qcom Lower Intermediate",
            lowerKey,
            upper,
            notBefore,
            notAfter,
            certificateAuthority: true,
            pathLengthConstraint: 0,
            [0x21, 0x22, 0x23, 0x24]);
        using X509Certificate2 leaf = CreateIssuedCertificate(
            "CN=Qcom Deep Leaf",
            leafKey,
            lower,
            notBefore,
            notAfter,
            certificateAuthority: false,
            pathLengthConstraint: 0,
            [0x31, 0x32, 0x33, 0x34]);
        return Combine(
            leaf.Export(X509ContentType.Cert),
            lower.Export(X509ContentType.Cert),
            upper.Export(X509ContentType.Cert),
            root.Export(X509ContentType.Cert));
    }

    private static X509Certificate2 CreateIssuedCertificate(
        string subject,
        RSA subjectKey,
        X509Certificate2 issuer,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool certificateAuthority,
        int pathLengthConstraint,
        byte[] serialNumber)
    {
        var request = new CertificateRequest(
            subject,
            subjectKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority,
                certificateAuthority,
                pathLengthConstraint,
                true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                certificateAuthority
                    ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                    : X509KeyUsageFlags.DigitalSignature,
                true));
        using X509Certificate2 encoded = request.Create(
            issuer,
            notBefore,
            notAfter,
            serialNumber);
        return encoded.CopyWithPrivateKey(subjectKey);
    }

    private static byte[] CreateDirectPssChain(PssParameterVariant variant)
    {
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(1);
        using RSA rootKey = RSA.Create(2048);
        using RSA leafKey = RSA.Create(2048);
        using X509Certificate2 root = CreateRoot(rootKey, notBefore, notAfter);
        var request = new CertificateRequest(
            "CN=Qcom PSS Leaf",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        byte[] algorithm = variant == PssParameterVariant.Supported
            ? X509SignatureGenerator
                .CreateForRSA(rootKey, RSASignaturePadding.Pss)
                .GetSignatureAlgorithmIdentifier(HashAlgorithmName.SHA256)
            : CreatePssAlgorithmIdentifier(variant);
        var generator = new RsaPssSignatureGenerator(rootKey, algorithm);
        using X509Certificate2 leaf = request.Create(
            root.SubjectName,
            generator,
            notBefore,
            notAfter,
            [0x41, 0x42, 0x43, 0x44]);
        return Combine(
            leaf.Export(X509ContentType.Cert),
            root.Export(X509ContentType.Cert));
    }

    private static byte[] CreatePssAlgorithmIdentifier(PssParameterVariant variant)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.1.10");
        writer.PushSequence();
        WriteExplicitHashAlgorithm(writer, 0, "2.16.840.1.101.3.4.2.1");
        var maskTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
        writer.PushSequence(maskTag);
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.840.113549.1.1.8");
        WriteHashAlgorithm(
            writer,
            variant == PssParameterVariant.MismatchedMaskHash
                ? "2.16.840.1.101.3.4.2.2"
                : "2.16.840.1.101.3.4.2.1");
        writer.PopSequence();
        writer.PopSequence(maskTag);
        var saltTag = new Asn1Tag(TagClass.ContextSpecific, 2, true);
        writer.PushSequence(saltTag);
        writer.WriteInteger(
            variant == PssParameterVariant.MismatchedSaltLength ? 20 : 32);
        writer.PopSequence(saltTag);
        if (variant == PssParameterVariant.UnsupportedTrailer)
        {
            var trailerTag = new Asn1Tag(TagClass.ContextSpecific, 3, true);
            writer.PushSequence(trailerTag);
            writer.WriteInteger(2);
            writer.PopSequence(trailerTag);
        }

        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    private static void WriteExplicitHashAlgorithm(
        AsnWriter writer,
        int tagValue,
        string oid)
    {
        var tag = new Asn1Tag(TagClass.ContextSpecific, tagValue, true);
        writer.PushSequence(tag);
        WriteHashAlgorithm(writer, oid);
        writer.PopSequence(tag);
    }

    private static void WriteHashAlgorithm(AsnWriter writer, string oid)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.PopSequence();
    }

    private static void AssertChainRejected(byte[] package)
    {
        bool valid = CertificateChainVerifier.TryVerify(
            package,
            MaximumCertificateCount,
            selectedRootSlot: null,
            out _,
            out string error);

        Assert.False(valid);
        Assert.NotEmpty(error);
    }

    private static X509Certificate2 CreateRoot(
        RSA key,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(
            RootDistinguishedName,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    private static byte[] Combine(params byte[][] certificates)
    {
        int length = 0;
        for (int index = 0; index < certificates.Length; index++)
            length = checked(length + certificates[index].Length);

        var package = new byte[length];
        int offset = 0;
        for (int index = 0; index < certificates.Length; index++)
        {
            certificates[index].CopyTo(package, offset);
            offset += certificates[index].Length;
        }

        return package;
    }

    private sealed record CertificateGraph(
        byte[] Leaf,
        byte[] Intermediate,
        byte[] ValidRoot,
        byte[] UnrelatedRoot);

    public enum PssParameterVariant
    {
        Supported,
        MismatchedMaskHash,
        MismatchedSaltLength,
        UnsupportedTrailer
    }

    private sealed class RsaPssSignatureGenerator(
        RSA key,
        byte[] algorithmIdentifier) : X509SignatureGenerator
    {
        private readonly X509SignatureGenerator _publicKeyGenerator =
            CreateForRSA(key, RSASignaturePadding.Pkcs1);

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            return [.. algorithmIdentifier];
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            return key.SignData(data, hashAlgorithm, RSASignaturePadding.Pss);
        }

        protected override PublicKey BuildPublicKey()
        {
            return _publicKeyGenerator.PublicKey;
        }
    }
}
