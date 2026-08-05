using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QcomImageUtils.Tests;

internal static class SignedElfTestVectorFactory
{
    public const ulong LegacySoftwareId = 3;
    public const ulong LegacyHardwareId = 0x1234567800AB00CD;

    private const int ElfHeaderSize = 52;
    private const int ProgramHeaderSize = 32;
    private const int ProgramHeaderCount = 4;
    private const int HashHeaderSize = 40;
    private const int DigestSize = 32;
    private const int FirstContentLength = 97;
    private const int SecondContentLength = 53;
    private const int SegmentAlignment = 0x1000;
    private const uint HashSegmentFlags = 0x02200000;
    private const uint HeaderSegmentFlags = 0x07000000;

    private static readonly Lazy<SignedElfTestVector> SignedV3 =
        new(() => CreateCore(3, true, false));
    private static readonly Lazy<SignedElfTestVector> SignedV5 =
        new(() => CreateCore(5, true, false));
    private static readonly Lazy<SignedElfTestVector> SignedV5Legacy =
        new(() => CreateCore(5, true, false, true));
    private static readonly Lazy<SignedElfTestVector> UnsignedV3 =
        new(() => CreateCore(3, false, false));
    private static readonly Lazy<SignedElfTestVector> UnsignedV5 =
        new(() => CreateCore(5, false, false));
    private static readonly Lazy<SignedElfTestVector> BrokenChainV3 =
        new(() => CreateCore(3, true, true));
    private static readonly Lazy<SignedElfTestVector> BrokenChainV5 =
        new(() => CreateCore(5, true, true));

    public static SignedElfTestVector CreateSigned(int version)
    {
        return version switch
        {
            3 => SignedV3.Value.Copy(),
            5 => SignedV5.Value.Copy(),
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };
    }

    public static SignedElfTestVector CreateUnsigned(int version)
    {
        return version switch
        {
            3 => UnsignedV3.Value.Copy(),
            5 => UnsignedV5.Value.Copy(),
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };
    }

    public static SignedElfTestVector CreateSignedV5Legacy()
    {
        return SignedV5Legacy.Value.Copy();
    }

    public static SignedElfTestVector CreateSignedWithAuthenticatedNestedElf()
    {
        return CreateCore(5, true, false, includeAuthenticatedNestedElf: true);
    }

    public static SignedElfTestVector CreateBrokenCertificateChain(int version)
    {
        return version switch
        {
            3 => BrokenChainV3.Value.Copy(),
            5 => BrokenChainV5.Value.Copy(),
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };
    }

    private static SignedElfTestVector CreateCore(
        int version,
        bool includeSignature,
        bool breakCertificateChain,
        bool useLegacyV5Signature = false,
        bool includeAuthenticatedNestedElf = false)
    {
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(30);

        using RSA signingRootKey = RSA.Create(2048);
        using X509Certificate2 signingRoot = CreateRoot(
            "CN=Qcom Verification Root",
            signingRootKey,
            notBefore,
            notAfter);
        using RSA leafKey = RSA.Create(2048);
        using X509Certificate2 leaf = CreateLeaf(
            signingRoot,
            leafKey,
            notBefore,
            notAfter,
            version);

        byte[] chainRootDer;
        if (breakCertificateChain)
        {
            using RSA unrelatedRootKey = RSA.Create(2048);
            using X509Certificate2 unrelatedRoot = CreateRoot(
                "CN=Qcom Unrelated Root",
                unrelatedRootKey,
                notBefore,
                notAfter);
            chainRootDer = unrelatedRoot.Export(X509ContentType.Cert);
        }
        else
        {
            chainRootDer = signingRoot.Export(X509ContentType.Cert);
        }

        byte[] leafDer = leaf.Export(X509ContentType.Cert);
        byte[] certificateChain = CreateCertificateChain(leafDer, chainRootDer);
        int hashTableLength = ProgramHeaderCount * DigestSize;
        int signatureLength = includeSignature ? leafKey.KeySize / 8 : 0;
        int hashSegmentLength = checked(
            HashHeaderSize + hashTableLength + signatureLength + certificateChain.Length);
        int elfHeaderLength = ElfHeaderSize + ProgramHeaderCount * ProgramHeaderSize;
        int hashSegmentOffset = Align(elfHeaderLength, SegmentAlignment);
        int firstContentOffset = Align(
            hashSegmentOffset + hashSegmentLength,
            SegmentAlignment);
        int secondContentOffset = Align(
            firstContentOffset + FirstContentLength,
            SegmentAlignment);
        var image = new byte[secondContentOffset + SecondContentLength];

        WriteElfHeader(image);
        WriteProgramHeader(
            image,
            0,
            0,
            0,
            0,
            checked((uint)elfHeaderLength),
            0,
            HeaderSegmentFlags,
            0);
        WriteProgramHeader(
            image,
            1,
            0,
            checked((uint)hashSegmentOffset),
            0x90000000,
            checked((uint)hashSegmentLength),
            checked((uint)Align(hashSegmentLength, SegmentAlignment)),
            HashSegmentFlags,
            SegmentAlignment);
        WriteProgramHeader(
            image,
            2,
            1,
            checked((uint)firstContentOffset),
            0x80000000,
            FirstContentLength,
            FirstContentLength,
            0x01200005,
            SegmentAlignment);
        WriteProgramHeader(
            image,
            3,
            1,
            checked((uint)secondContentOffset),
            0x80001000,
            SecondContentLength,
            SecondContentLength,
            0x01000006,
            SegmentAlignment);

        FillContent(image.AsSpan(firstContentOffset, FirstContentLength), 0x31);
        FillContent(image.AsSpan(secondContentOffset, SecondContentLength), 0xA7);
        if (includeAuthenticatedNestedElf)
            WriteInvalidNestedElf(image.AsSpan(firstContentOffset, FirstContentLength));

        var hashTable = new byte[hashTableLength];
        SHA256.HashData(
            image.AsSpan(0, elfHeaderLength),
            hashTable.AsSpan(0, DigestSize));
        SHA256.HashData(
            image.AsSpan(firstContentOffset, FirstContentLength),
            hashTable.AsSpan(DigestSize * 2, DigestSize));
        SHA256.HashData(
            image.AsSpan(secondContentOffset, SecondContentLength),
            hashTable.AsSpan(DigestSize * 3, DigestSize));

        int signatureOffset = hashSegmentOffset + HashHeaderSize + hashTableLength;
        int certificateChainOffset = signatureOffset + signatureLength;

        WriteHashHeader(
            image.AsSpan(hashSegmentOffset, HashHeaderSize),
            version,
            hashTableLength,
            signatureLength,
            certificateChain.Length);
        hashTable.CopyTo(image, hashSegmentOffset + HashHeaderSize);
        ReadOnlySpan<byte> signedData = image.AsSpan(
            hashSegmentOffset,
            HashHeaderSize + hashTableLength);
        byte[] signature = includeSignature
            ? Sign(version, leafKey, signedData, useLegacyV5Signature)
            : [];
        signature.CopyTo(image, signatureOffset);
        certificateChain.CopyTo(image, certificateChainOffset);

        return new SignedElfTestVector(
            image,
            Convert.ToHexString(SHA256.HashData(chainRootDer)),
            leafDer,
            chainRootDer,
            elfHeaderLength,
            hashSegmentOffset,
            HashHeaderSize + hashTableLength,
            hashSegmentOffset + HashHeaderSize,
            hashTableLength,
            signatureOffset,
            signature.Length,
            certificateChainOffset,
            certificateChain.Length,
            firstContentOffset,
            FirstContentLength,
            secondContentOffset,
            SecondContentLength);
    }

    private static X509Certificate2 CreateRoot(
        string subject,
        RSA key,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(
            subject,
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
        DateTimeOffset notAfter,
        int version)
    {
        var request = new CertificateRequest(
            CreateLeafSubject(version),
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        byte[] serialNumber = [0x01, 0x37, 0x51, 0x93, 0xA5, 0xC7, 0xE9];
        return request.Create(issuer, notBefore, notAfter, serialNumber);
    }

    private static X500DistinguishedName CreateLeafSubject(int version)
    {
        if (version != 3)
        {
            return new X500DistinguishedName(
                "CN=Qcom Verification Leaf, OU=01 0000000000000003 SW_ID, OU=02 1234567800AB00CD HW_ID, OU=07 0001 SHA256");
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        WriteNameAttribute(writer, "2.5.4.3", "Qcom Verification Leaf", UniversalTagNumber.PrintableString);
        WriteNameAttribute(writer, "2.5.4.11", "01 0000000000000003 SW_ID", UniversalTagNumber.TeletexString);
        WriteNameAttribute(writer, "2.5.4.11", "02 1234567800AB00CD HW_ID", UniversalTagNumber.TeletexString);
        WriteNameAttribute(writer, "2.5.4.11", "07 0001 SHA256", UniversalTagNumber.TeletexString);
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

    private static byte[] Sign(
        int version,
        RSA key,
        ReadOnlySpan<byte> data,
        bool useLegacyV5Signature)
    {
        if (version == 5 && !useLegacyV5Signature)
        {
            return key.SignData(
                data,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
        }

        byte[] digest = ComputeLegacyDigest(data);
        RSAParameters parameters = key.ExportParameters(true);
        byte[] modulusBytes = parameters.Modulus
                              ?? throw new CryptographicException("RSA modulus is missing.");
        byte[] privateExponentBytes = parameters.D
                                      ?? throw new CryptographicException("RSA private exponent is missing.");
        var encodedMessage = new byte[modulusBytes.Length];
        encodedMessage[1] = 0x01;
        int delimiterOffset = encodedMessage.Length - digest.Length - 1;
        encodedMessage.AsSpan(2, delimiterOffset - 2).Fill(0xFF);
        digest.CopyTo(encodedMessage, delimiterOffset + 1);

        var modulus = new BigInteger(modulusBytes, true, true);
        var privateExponent = new BigInteger(privateExponentBytes, true, true);
        var message = new BigInteger(encodedMessage, true, true);
        BigInteger signatureValue = BigInteger.ModPow(message, privateExponent, modulus);
        byte[] signature = signatureValue.ToByteArray(true, true);
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
            LegacySoftwareId ^ 0x3636363636363636);
        firstDigest.CopyTo(input[8..]);
        SHA256.HashData(input, secondDigest);
        BinaryPrimitives.WriteUInt64BigEndian(
            input,
            LegacyHardwareId ^ 0x5C5C5C5C5C5C5C5C);
        secondDigest.CopyTo(input[8..]);
        return SHA256.HashData(input);
    }

    private static void WriteElfHeader(byte[] image)
    {
        image[0] = 0x7F;
        image[1] = (byte)'E';
        image[2] = (byte)'L';
        image[3] = (byte)'F';
        image[4] = 1;
        image[5] = 1;
        image[6] = 1;
        WriteUInt16(image, 16, 2);
        WriteUInt16(image, 18, 40);
        WriteUInt32(image, 20, 1);
        WriteUInt32(image, 28, ElfHeaderSize);
        WriteUInt16(image, 40, ElfHeaderSize);
        WriteUInt16(image, 42, ProgramHeaderSize);
        WriteUInt16(image, 44, ProgramHeaderCount);
    }

    private static void WriteProgramHeader(
        byte[] image,
        int index,
        uint type,
        uint fileOffset,
        uint physicalAddress,
        uint fileSize,
        uint memorySize,
        uint flags,
        uint alignment)
    {
        int offset = ElfHeaderSize + index * ProgramHeaderSize;
        WriteUInt32(image, offset, type);
        WriteUInt32(image, offset + 4, fileOffset);
        WriteUInt32(image, offset + 8, physicalAddress);
        WriteUInt32(image, offset + 12, physicalAddress);
        WriteUInt32(image, offset + 16, fileSize);
        WriteUInt32(image, offset + 20, memorySize);
        WriteUInt32(image, offset + 24, flags);
        WriteUInt32(image, offset + 28, alignment);
    }

    private static void WriteHashHeader(
        Span<byte> header,
        int version,
        int hashTableLength,
        int signatureLength,
        int certificateChainLength)
    {
        WriteUInt32(header, 0, BinaryImageFactory.ImageId);
        WriteUInt32(header, 4, checked((uint)version));
        if (version == 5)
        {
            WriteUInt32(header, 8, 0);
            WriteUInt32(header, 12, 0);
        }

        WriteUInt32(
            header,
            16,
            checked((uint)(hashTableLength + signatureLength + certificateChainLength)));
        WriteUInt32(header, 20, checked((uint)hashTableLength));
        WriteUInt32(header, 24, version == 3 ? 0x90000028u : uint.MaxValue);
        WriteUInt32(header, 28, checked((uint)signatureLength));
        WriteUInt32(
            header,
            32,
            version == 3
                ? checked((uint)(0x90000028 + hashTableLength + signatureLength))
                : uint.MaxValue);
        WriteUInt32(header, 36, checked((uint)certificateChainLength));
    }

    private static void FillContent(Span<byte> content, byte seed)
    {
        for (int index = 0; index < content.Length; index++)
            content[index] = unchecked((byte)(seed + index * 17));
    }

    private static void WriteInvalidNestedElf(Span<byte> destination)
    {
        destination[0] = 0x7F;
        destination[1] = (byte)'E';
        destination[2] = (byte)'L';
        destination[3] = (byte)'F';
        destination[4] = 1;
        destination[5] = 1;
        destination[6] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(28, 4), ElfHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(40, 2), ElfHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(42, 2), ProgramHeaderSize);
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(44, 2), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(ElfHeaderSize, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(ElfHeaderSize + 4, 4),
            ElfHeaderSize + ProgramHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(ElfHeaderSize + 16, 4), 40);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(ElfHeaderSize + 24, 4),
            HashSegmentFlags);
        BinaryPrimitives.WriteUInt32LittleEndian(
            destination.Slice(ElfHeaderSize + ProgramHeaderSize + 4, 4),
            uint.MaxValue);
    }

    private static int Align(int value, int alignment)
    {
        return checked((value + alignment - 1) & -alignment);
    }

    private static void WriteUInt16(byte[] destination, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(destination.AsSpan(offset, sizeof(ushort)), value);
    }

    private static void WriteUInt32(byte[] destination, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan(offset, sizeof(uint)), value);
    }

    private static void WriteUInt32(Span<byte> destination, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(offset, sizeof(uint)), value);
    }
}
