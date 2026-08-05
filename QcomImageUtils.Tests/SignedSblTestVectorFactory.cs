using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QcomImageUtils.Tests;

internal static class SignedSblTestVectorFactory
{
    private const ulong SoftwareId = 3;
    private const ulong HardwareId = 0x1234567800AB00CD;
    private const int HeaderLength = 80;
    private const int CodeLength = 137;
    private const int PreambleLength = 32;
    private const uint Codeword = 0x844BDCD1;
    private const uint Magic = 0x73D71034;
    private const uint ImageId = 5;
    private const uint ImageDestination = 0x80000000;

    private static readonly Lazy<SigningMaterial> Material = new(CreateSigningMaterial);
    private static readonly Lazy<SignedSblTestVector> Signed =
        new(() => CreateSignedCore(HeaderLength, SignatureCoverage.Envelope));
    private static readonly Lazy<SignedSblTestVector> SignedWithPreamble =
        new(() => CreateSignedCore(HeaderLength + PreambleLength, SignatureCoverage.Envelope));
    private static readonly Lazy<SignedSblTestVector> CodeOnlySigned =
        new(() => CreateSignedCore(HeaderLength, SignatureCoverage.Code));
    private static readonly Lazy<SignedSblTestVector> Unsigned = new(CreateUnsignedCore);

    public static SignedSblTestVector CreateSigned()
    {
        return Signed.Value.Copy();
    }

    public static SignedSblTestVector CreateSignedWithPreamble()
    {
        return SignedWithPreamble.Value.Copy();
    }

    public static SignedSblTestVector CreateCodeOnlySigned()
    {
        return CodeOnlySigned.Value.Copy();
    }

    public static SignedSblTestVector CreateUnsigned()
    {
        return Unsigned.Value.Copy();
    }

    private static SignedSblTestVector CreateSignedCore(
        int imageSource,
        SignatureCoverage coverage)
    {
        SigningMaterial material = Material.Value;
        int signatureLength = material.LeafKey.Modulus?.Length
                              ?? throw new CryptographicException("RSA modulus is missing.");
        int imageSize = checked(CodeLength + signatureLength + material.CertificateChain.Length);
        var image = new byte[checked(imageSource + imageSize)];

        WriteHeader(
            image,
            imageSource,
            CodeLength,
            signatureLength,
            material.CertificateChain.Length,
            rootCount: 1);
        FillData(image.AsSpan(HeaderLength, imageSource - HeaderLength), 0x91);
        FillData(image.AsSpan(imageSource, CodeLength), 0x37);

        ReadOnlySpan<byte> signedData = coverage == SignatureCoverage.Envelope
            ? image.AsSpan(0, imageSource + CodeLength)
            : image.AsSpan(imageSource, CodeLength);
        byte[] signature = SignLegacy(material.LeafKey, signedData);
        int signatureOffset = imageSource + CodeLength;
        signature.CopyTo(image, signatureOffset);
        material.CertificateChain.CopyTo(image, signatureOffset + signature.Length);

        return new SignedSblTestVector(
            image,
            material.RootCertificateSha256,
            imageSource,
            CodeLength,
            signature.Length,
            material.CertificateChain.Length);
    }

    private static SignedSblTestVector CreateUnsignedCore()
    {
        var image = new byte[HeaderLength + CodeLength];
        WriteHeader(
            image,
            HeaderLength,
            CodeLength,
            signatureLength: 0,
            certificateChainLength: 0,
            rootCount: 0);
        FillData(image.AsSpan(HeaderLength, CodeLength), 0x37);
        return new SignedSblTestVector(image, string.Empty, HeaderLength, CodeLength, 0, 0);
    }

    private static SigningMaterial CreateSigningMaterial()
    {
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(30);

        using RSA rootKey = RSA.Create(2048);
        using X509Certificate2 root = CreateRoot(rootKey, notBefore, notAfter);
        using RSA leafKey = RSA.Create(2048);
        using X509Certificate2 leaf = CreateLeaf(root, leafKey, notBefore, notAfter);
        byte[] rootDer = root.Export(X509ContentType.Cert);
        byte[] leafDer = leaf.Export(X509ContentType.Cert);
        return new SigningMaterial(
            leafKey.ExportParameters(true),
            CreateCertificateChain(leafDer, rootDer),
            Convert.ToHexString(SHA256.HashData(rootDer)));
    }

    private static X509Certificate2 CreateRoot(
        RSA key,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(
            "CN=Qcom SBL Verification Root",
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

    private static X509Certificate2 CreateLeaf(
        X509Certificate2 issuer,
        RSA key,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(
            CreateLeafSubject(),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        byte[] serialNumber = [0x21, 0x43, 0x65, 0x87, 0x19, 0x3B, 0x5D];
        return request.Create(issuer, notBefore, notAfter, serialNumber);
    }

    private static X500DistinguishedName CreateLeafSubject()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        WriteNameAttribute(
            writer,
            "2.5.4.3",
            "Qcom SBL Verification Leaf",
            UniversalTagNumber.PrintableString);
        WriteNameAttribute(
            writer,
            "2.5.4.11",
            "01 0000000000000003 SW_ID",
            UniversalTagNumber.TeletexString);
        WriteNameAttribute(
            writer,
            "2.5.4.11",
            "02 1234567800AB00CD HW_ID",
            UniversalTagNumber.TeletexString);
        writer.PopSequence();
        return new X500DistinguishedName(writer.Encode());
    }

    private static void WriteNameAttribute(
        AsnWriter writer,
        string oid,
        string value,
        UniversalTagNumber stringType)
    {
        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        writer.WriteCharacterString(stringType, value);
        writer.PopSequence();
        writer.PopSetOf();
    }

    private static byte[] CreateCertificateChain(byte[] leafDer, byte[] rootDer)
    {
        int rawLength = checked(leafDer.Length + rootDer.Length);
        var chain = new byte[Align(rawLength, 16)];
        chain.AsSpan().Fill(0xFF);
        leafDer.CopyTo(chain, 0);
        rootDer.CopyTo(chain, leafDer.Length);
        return chain;
    }

    private static byte[] SignLegacy(RSAParameters key, ReadOnlySpan<byte> data)
    {
        byte[] digest = ComputeLegacyDigest(data);
        byte[] modulusBytes = key.Modulus
                              ?? throw new CryptographicException("RSA modulus is missing.");
        byte[] privateExponentBytes = key.D
                                      ?? throw new CryptographicException("RSA private exponent is missing.");
        var encodedMessage = new byte[modulusBytes.Length];
        encodedMessage[1] = 0x01;
        int delimiterOffset = encodedMessage.Length - digest.Length - 1;
        encodedMessage.AsSpan(2, delimiterOffset - 2).Fill(0xFF);
        digest.CopyTo(encodedMessage, delimiterOffset + 1);

        var modulus = new BigInteger(modulusBytes, true, true);
        var privateExponent = new BigInteger(privateExponentBytes, true, true);
        var message = new BigInteger(encodedMessage, true, true);
        byte[] signature = BigInteger.ModPow(message, privateExponent, modulus)
            .ToByteArray(true, true);
        if (signature.Length == encodedMessage.Length)
            return signature;

        var paddedSignature = new byte[encodedMessage.Length];
        signature.CopyTo(paddedSignature, paddedSignature.Length - signature.Length);
        return paddedSignature;
    }

    private static byte[] ComputeLegacyDigest(ReadOnlySpan<byte> data)
    {
        Span<byte> firstDigest = stackalloc byte[32];
        Span<byte> secondDigest = stackalloc byte[32];
        Span<byte> input = stackalloc byte[40];

        SHA256.HashData(data, firstDigest);
        BinaryPrimitives.WriteUInt64BigEndian(
            input,
            SoftwareId ^ 0x3636363636363636);
        firstDigest.CopyTo(input[8..]);
        SHA256.HashData(input, secondDigest);
        BinaryPrimitives.WriteUInt64BigEndian(
            input,
            HardwareId ^ 0x5C5C5C5C5C5C5C5C);
        secondDigest.CopyTo(input[8..]);
        return SHA256.HashData(input);
    }

    private static void WriteHeader(
        byte[] image,
        int imageSource,
        int codeLength,
        int signatureLength,
        int certificateChainLength,
        uint rootCount)
    {
        int imageSize = checked(codeLength + signatureLength + certificateChainLength);
        uint signatureDestination = checked(ImageDestination + (uint)codeLength);
        uint certificateDestination = checked(signatureDestination + (uint)signatureLength);

        WriteUInt32(image, 0, Codeword);
        WriteUInt32(image, 4, Magic);
        WriteUInt32(image, 8, ImageId);
        WriteUInt32(image, 20, checked((uint)imageSource));
        WriteUInt32(image, 24, ImageDestination);
        WriteUInt32(image, 28, checked((uint)imageSize));
        WriteUInt32(image, 32, checked((uint)codeLength));
        WriteUInt32(image, 36, signatureDestination);
        WriteUInt32(image, 40, checked((uint)signatureLength));
        WriteUInt32(image, 44, certificateDestination);
        WriteUInt32(image, 48, checked((uint)certificateChainLength));
        WriteUInt32(image, 52, rootCount == 0 ? 0u : 1u);
        WriteUInt32(image, 56, rootCount);
        WriteUInt32(image, 60, 0xF);
    }

    private static void FillData(Span<byte> data, byte seed)
    {
        for (int index = 0; index < data.Length; index++)
            data[index] = unchecked((byte)(seed + index * 29));
    }

    private static int Align(int value, int alignment)
    {
        return checked((value + alignment - 1) & -alignment);
    }

    private static void WriteUInt32(byte[] destination, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan(offset, sizeof(uint)), value);
    }

    private enum SignatureCoverage
    {
        Envelope,
        Code
    }

    private sealed class SigningMaterial(
        RSAParameters leafKey,
        byte[] certificateChain,
        string rootCertificateSha256)
    {
        public RSAParameters LeafKey { get; } = leafKey;
        public byte[] CertificateChain { get; } = certificateChain;
        public string RootCertificateSha256 { get; } = rootCertificateSha256;
    }
}
