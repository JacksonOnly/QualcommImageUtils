using System.Buffers.Binary;

namespace QcomImageUtils.Tests;

internal static class BinaryImageFactory
{
    public const uint ImageId = 5;
    public const uint SoftwareId = 3;
    public const uint HardwareId = 0x1234ABCD;
    public const uint OemId = 0xAB;
    public const uint ModelId = 0xCD;
    public const uint SocHardwareVersion = 0x60060001;
    public const uint AntiRollbackVersion = 0x35;

    private const int V3HeaderSize = 40;
    private const int V5HeaderSize = 40;
    private const int V6HeaderSize = 48;
    private const int V7HeaderSize = 40;
    private const int Sha256Size = 32;
    private const int Sha384Size = 48;
    private const uint HashSegmentFlags = 0x02200000;

    public static byte[] CreateHashSegment(int version)
    {
        return version switch
        {
            3 => CreateV3(),
            5 => CreateV5(),
            6 => CreateV6(16, 128),
            7 => CreateV7(32, 12, 240),
            _ => throw new ArgumentOutOfRangeException(nameof(version))
        };
    }

    public static byte[] CreateV3(byte[]? certificateChain = null)
    {
        certificateChain ??= [];
        int payloadSize = checked(Sha256Size + certificateChain.Length);
        var image = new byte[checked(V3HeaderSize + payloadSize)];

        WriteUInt32(image, 0, ImageId);
        WriteUInt32(image, 4, 3);
        WriteUInt32(image, 16, checked((uint)payloadSize));
        WriteUInt32(image, 20, Sha256Size);
        WriteUInt32(image, 36, checked((uint)certificateChain.Length));
        image.AsSpan(V3HeaderSize, Sha256Size).Fill(0x31);
        certificateChain.CopyTo(image, V3HeaderSize + Sha256Size);

        return image;
    }

    public static byte[] CreateV3Sha1()
    {
        const int sha1Size = 20;
        var image = new byte[V3HeaderSize + sha1Size];

        WriteUInt32(image, 0, ImageId);
        WriteUInt32(image, 4, 3);
        WriteUInt32(image, 16, sha1Size);
        WriteUInt32(image, 20, sha1Size);
        image.AsSpan(V3HeaderSize, sha1Size).Fill(0x41);

        return image;
    }

    public static byte[] CreateV5()
    {
        var image = new byte[V5HeaderSize + Sha256Size];

        WriteUInt32(image, 0, ImageId);
        WriteUInt32(image, 4, 5);
        WriteUInt32(image, 16, Sha256Size);
        WriteUInt32(image, 20, Sha256Size);
        image.AsSpan(V5HeaderSize, Sha256Size).Fill(0x52);

        return image;
    }

    public static byte[] CreateV6(int qtiMetadataSize, int oemMetadataSize)
    {
        int metadataSize = checked(qtiMetadataSize + oemMetadataSize);
        int payloadSize = checked(metadataSize + Sha384Size);
        var image = new byte[checked(V6HeaderSize + payloadSize)];

        WriteUInt32(image, 0, ImageId);
        WriteUInt32(image, 4, 6);
        WriteUInt32(image, 16, checked((uint)payloadSize));
        WriteUInt32(image, 20, Sha384Size);
        WriteUInt32(image, 40, checked((uint)qtiMetadataSize));
        WriteUInt32(image, 44, checked((uint)oemMetadataSize));

        int oemOffset = V6HeaderSize + qtiMetadataSize;
        if (oemMetadataSize >= 120)
        {
            WriteUInt32(image, oemOffset, 1);
            WriteUInt32(image, oemOffset + 4, 0);
            WriteUInt32(image, oemOffset + 8, SoftwareId);
            WriteUInt32(image, oemOffset + 12, HardwareId);
            WriteUInt32(image, oemOffset + 16, OemId);
            WriteUInt32(image, oemOffset + 20, ModelId);
            WriteUInt32(image, oemOffset + 32, SocHardwareVersion);
            WriteUInt32(image, oemOffset + 116, AntiRollbackVersion);
        }

        image.AsSpan(V6HeaderSize + metadataSize, Sha384Size).Fill(0x63);
        return image;
    }

    public static byte[] CreateV7(
        int commonMetadataSize,
        int qtiMetadataSize,
        int oemMetadataSize)
    {
        int metadataSize = checked(commonMetadataSize + qtiMetadataSize + oemMetadataSize);
        var image = new byte[checked(V7HeaderSize + metadataSize + Sha384Size)];

        WriteUInt32(image, 4, 7);
        WriteUInt32(image, 8, checked((uint)commonMetadataSize));
        WriteUInt32(image, 12, checked((uint)qtiMetadataSize));
        WriteUInt32(image, 16, checked((uint)oemMetadataSize));
        WriteUInt32(image, 20, Sha384Size);

        if (commonMetadataSize >= 24)
        {
            WriteUInt32(image, V7HeaderSize, 1);
            WriteUInt32(image, V7HeaderSize + 4, 0);
            WriteUInt32(image, V7HeaderSize + 8, SoftwareId);
            WriteUInt32(image, V7HeaderSize + 16, 3);
        }

        int oemOffset = V7HeaderSize + commonMetadataSize + qtiMetadataSize;
        if (oemMetadataSize >= 224)
        {
            WriteUInt32(image, oemOffset, 1);
            WriteUInt32(image, oemOffset + 4, 0);
            WriteUInt32(image, oemOffset + 8, AntiRollbackVersion);
            WriteUInt32(image, oemOffset + 16, SocHardwareVersion);
            WriteUInt32(image, oemOffset + 136, OemId);
            WriteUInt32(image, oemOffset + 140, ModelId);
            WriteUInt32(image, oemOffset + 152, 3);
            for (int index = 0; index < 64; index++)
                image[oemOffset + 156 + index] = checked((byte)(index + 1));
        }

        image.AsSpan(V7HeaderSize + metadataSize, Sha384Size).Fill(0x74);
        return image;
    }

    public static byte[] CreateSbl(byte[]? code = null)
    {
        code ??= [];
        var image = new byte[checked(80 + code.Length)];

        WriteUInt32(image, 0, 0x844BDCD1);
        WriteUInt32(image, 4, 0x73D71034);
        WriteUInt32(image, 8, ImageId);
        WriteUInt32(image, 20, 80);
        WriteUInt32(image, 32, checked((uint)code.Length));
        WriteUInt32(image, 60, 0xF);
        code.CopyTo(image, 80);

        return image;
    }

    public static byte[] CreateElf(byte[] hashSegment, bool is64Bit, int prefixLength = 0)
    {
        int elfHeaderSize = is64Bit ? 64 : 52;
        int programHeaderSize = is64Bit ? 56 : 32;
        int segmentOffset = elfHeaderSize + programHeaderSize;
        var elf = new byte[checked(segmentOffset + hashSegment.Length)];

        elf[0] = 0x7F;
        elf[1] = (byte)'E';
        elf[2] = (byte)'L';
        elf[3] = (byte)'F';
        elf[4] = is64Bit ? (byte)2 : (byte)1;
        elf[5] = 1;
        elf[6] = 1;

        if (is64Bit)
        {
            WriteUInt64(elf, 32, checked((ulong)elfHeaderSize));
            WriteUInt16(elf, 52, checked((ushort)elfHeaderSize));
            WriteUInt16(elf, 54, checked((ushort)programHeaderSize));
            WriteUInt16(elf, 56, 1);
            WriteUInt32(elf, elfHeaderSize, 1);
            WriteUInt32(elf, elfHeaderSize + 4, HashSegmentFlags);
            WriteUInt64(elf, elfHeaderSize + 8, checked((ulong)segmentOffset));
            WriteUInt64(elf, elfHeaderSize + 32, checked((ulong)hashSegment.Length));
        }
        else
        {
            WriteUInt32(elf, 28, checked((uint)elfHeaderSize));
            WriteUInt16(elf, 40, checked((ushort)elfHeaderSize));
            WriteUInt16(elf, 42, checked((ushort)programHeaderSize));
            WriteUInt16(elf, 44, 1);
            WriteUInt32(elf, elfHeaderSize, 1);
            WriteUInt32(elf, elfHeaderSize + 4, checked((uint)segmentOffset));
            WriteUInt32(elf, elfHeaderSize + 16, checked((uint)hashSegment.Length));
            WriteUInt32(elf, elfHeaderSize + 24, HashSegmentFlags);
        }

        hashSegment.CopyTo(elf, segmentOffset);
        if (prefixLength == 0)
            return elf;

        var prefixedImage = new byte[checked(prefixLength + elf.Length)];
        prefixedImage.AsSpan(0, prefixLength).Fill(0xA5);
        elf.CopyTo(prefixedImage, prefixLength);
        return prefixedImage;
    }

    public static byte[] CreateElf64WithOverflowingSegmentOffset()
    {
        byte[] elf = CreateElf(CreateV3(), true);
        WriteUInt64(elf, 64 + 8, ulong.MaxValue);
        return elf;
    }

    public static byte[] CreateV5WithOverflowingLengths()
    {
        var image = new byte[V5HeaderSize];
        WriteUInt32(image, 0, ImageId);
        WriteUInt32(image, 4, 5);
        WriteUInt32(image, 8, uint.MaxValue);
        WriteUInt32(image, 12, uint.MaxValue);
        WriteUInt32(image, 16, uint.MaxValue);
        WriteUInt32(image, 20, uint.MaxValue);
        WriteUInt32(image, 28, uint.MaxValue);
        WriteUInt32(image, 36, uint.MaxValue);
        return image;
    }

    public static byte[] Append(byte[] image, byte[] suffix)
    {
        var combined = new byte[checked(image.Length + suffix.Length)];
        image.CopyTo(combined, 0);
        suffix.CopyTo(combined, image.Length);
        return combined;
    }

    public static string ExpectedV7RootHash()
    {
        Span<byte> hash = stackalloc byte[64];
        for (int index = 0; index < hash.Length; index++)
            hash[index] = checked((byte)(index + 1));
        return Convert.ToHexString(hash);
    }

    private static void WriteUInt16(byte[] destination, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(destination.AsSpan(offset, sizeof(ushort)), value);
    }

    private static void WriteUInt32(byte[] destination, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan(offset, sizeof(uint)), value);
    }

    private static void WriteUInt64(byte[] destination, int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination.AsSpan(offset, sizeof(ulong)), value);
    }
}
