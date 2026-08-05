namespace QcomImageUtils.Utilities;

internal struct HashSegmentInfo
{
    public bool HasImageId;
    public uint ImageId;
    public uint Version;
    public int HeaderLength;
    public int HashOffset;
    public uint HashSize;
    public uint HashTableAlgorithm;
    public int QualcommMetadataOffset;
    public int QualcommMetadataLength;
    public int OemMetadataOffset;
    public int OemMetadataLength;
    public int QualcommSignatureOffset;
    public int QualcommSignatureLength;
    public bool HasQualcommRootCertificateSlot;
    public uint QualcommRootCertificateSlot;
    public uint SocHwVersion;
    public bool HasOemId;
    public uint OemId;
    public uint ModelId;
    public uint AntiRollbackVersion;
    public ulong SoftwareId;
    public ulong HardwareId;
    public int QualcommCertificateOffset;
    public int QualcommCertificateLength;
    public int OemSignatureOffset;
    public int OemSignatureLength;
    public bool HasOemRootCertificateSlot;
    public uint OemRootCertificateSlot;
    public int OemCertificateOffset;
    public int OemCertificateLength;
    public int MetadataRootCertificateHashOffset;
    public int MetadataRootCertificateHashLength;
    public uint MetadataRootCertificateHashAlgorithm;
    public bool UsesSha384;
    public string MetadataRootCertificateHash;
}

/// <summary>
/// 按 Qualcomm MBN v3、v5、v6 和 v7 声明长度解析哈希段。
/// </summary>
internal static class HashSegmentReader
{
    private const int V3HeaderSize = 40;
    private const int V5HeaderSize = 40;
    private const int V6HeaderSize = 48;
    private const int V7HeaderSize = 40;
    private const int V6OemMetadataSize = 120;
    private const int V7CommonMetadataSize = 24;
    private const int V7OemMetadataSize = 224;

    public static bool TryGetVersion(ReadOnlySpan<byte> data, out uint version)
    {
        return BinaryDataReader.TryReadUInt32LittleEndian(data, sizeof(uint), out version)
               && version is 3 or 5 or 6 or 7;
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out HashSegmentInfo info, out string error)
    {
        info = default;
        info.MetadataRootCertificateHash = string.Empty;
        error = string.Empty;

        if (!TryGetVersion(data, out uint version))
        {
            error = "MBN 头版本不受支持";
            return false;
        }

        info.Version = version;
        return version switch
        {
            3 => TryReadV3(data, ref info, out error),
            5 => TryReadV5(data, ref info, out error),
            6 => TryReadV6(data, ref info, out error),
            7 => TryReadV7(data, ref info, out error),
            _ => false
        };
    }

    private static bool TryReadV3(ReadOnlySpan<byte> data, ref HashSegmentInfo info, out string error)
    {
        if (!TryReadCommonFields(data, out uint imageId, out uint totalSize, out uint hashSize,
                out uint signatureSize, out uint certificateSize))
        {
            error = "MBN v3 头不完整";
            return false;
        }

        ulong requiredSize = (ulong)hashSize + signatureSize + certificateSize;
        if (!TryValidateLayout(data, V3HeaderSize, totalSize, requiredSize, 0, out error))
            return false;

        info.HasImageId = true;
        info.ImageId = imageId;
        info.HeaderLength = V3HeaderSize;
        info.HashOffset = V3HeaderSize;
        info.HashSize = hashSize;
        info.HashTableAlgorithm = 2;
        info.OemSignatureOffset = checked(V3HeaderSize + (int)hashSize);
        info.OemSignatureLength = checked((int)signatureSize);
        info.OemCertificateOffset = checked(info.OemSignatureOffset + info.OemSignatureLength);
        info.OemCertificateLength = checked((int)certificateSize);
        return true;
    }

    private static bool TryReadV5(ReadOnlySpan<byte> data, ref HashSegmentInfo info, out string error)
    {
        if (!TryReadCommonFields(data, out uint imageId, out uint totalSize, out uint hashSize,
                out uint signatureSize, out uint certificateSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 8, out uint signatureSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 12, out uint certificateSizeQti))
        {
            error = "MBN v5 头不完整";
            return false;
        }

        ulong requiredSize = (ulong)hashSize + signatureSizeQti + certificateSizeQti
                             + signatureSize + certificateSize;
        if (!TryValidateLayout(data, V5HeaderSize, totalSize, requiredSize, 0, out error))
            return false;

        ulong qtiSignatureOffset = (ulong)V5HeaderSize + hashSize;
        ulong qtiCertificateOffset = qtiSignatureOffset + signatureSizeQti;
        ulong oemSignatureOffset = qtiCertificateOffset + certificateSizeQti;
        ulong oemCertificateOffset = qtiCertificateOffset + certificateSizeQti + signatureSize;
        if (!TrySetAuthenticationRanges(data,
                qtiSignatureOffset, signatureSizeQti, qtiCertificateOffset, certificateSizeQti,
                oemSignatureOffset, signatureSize, oemCertificateOffset, certificateSize,
                ref info, out error))
            return false;

        info.HasImageId = true;
        info.ImageId = imageId;
        info.HeaderLength = V5HeaderSize;
        info.HashOffset = V5HeaderSize;
        info.HashSize = hashSize;
        info.HashTableAlgorithm = 2;
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> data, ref HashSegmentInfo info, out string error)
    {
        if (!TryReadCommonFields(data, out uint imageId, out uint totalSize, out uint hashSize,
                out uint signatureSize, out uint certificateSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 8, out uint signatureSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 12, out uint certificateSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 40, out uint metadataSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 44, out uint metadataSizeOem))
        {
            error = "MBN v6 头不完整";
            return false;
        }

        ulong metadataSize = (ulong)metadataSizeQti + metadataSizeOem;
        ulong requiredSize = metadataSize + hashSize + signatureSizeQti + certificateSizeQti
                             + signatureSize + certificateSize;
        if (!TryValidateLayout(data, V6HeaderSize, totalSize, requiredSize, metadataSize, out error))
            return false;

        ulong hashOffset = (ulong)V6HeaderSize + metadataSize;
        ulong qtiSignatureOffset = hashOffset + hashSize;
        ulong qtiCertificateOffset = qtiSignatureOffset + signatureSizeQti;
        ulong oemSignatureOffset = qtiCertificateOffset + certificateSizeQti;
        ulong oemCertificateOffset = qtiCertificateOffset + certificateSizeQti + signatureSize;
        if (!TrySetAuthenticationRanges(data,
                qtiSignatureOffset, signatureSizeQti, qtiCertificateOffset, certificateSizeQti,
                oemSignatureOffset, signatureSize, oemCertificateOffset, certificateSize,
                ref info, out error))
            return false;

        info.HasImageId = true;
        info.ImageId = imageId;
        info.HeaderLength = V6HeaderSize;
        info.QualcommMetadataOffset = V6HeaderSize;
        info.QualcommMetadataLength = checked((int)metadataSizeQti);
        info.OemMetadataOffset = checked(V6HeaderSize + (int)metadataSizeQti);
        info.OemMetadataLength = checked((int)metadataSizeOem);
        info.HashOffset = checked((int)hashOffset);
        info.HashSize = hashSize;
        info.HashTableAlgorithm = 3;
        info.UsesSha384 = true;

        if (metadataSizeQti >= V6OemMetadataSize)
        {
            int offset = V6HeaderSize;
            BinaryDataReader.TryReadUInt32LittleEndian(
                data,
                offset + 112,
                out info.QualcommRootCertificateSlot);
            info.HasQualcommRootCertificateSlot = true;
        }

        ulong oemMetadataOffset = (ulong)V6HeaderSize + metadataSizeQti;
        if (metadataSizeOem >= V6OemMetadataSize
            && BinaryDataReader.IsRangeInside(oemMetadataOffset, V6OemMetadataSize, data.Length))
        {
            info.HasOemId = true;
            int offset = checked((int)oemMetadataOffset);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 8, out uint softwareId);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 12, out uint hardwareId);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 16, out info.OemId);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 20, out info.ModelId);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 32, out info.SocHwVersion);
            BinaryDataReader.TryReadUInt32LittleEndian(
                data,
                offset + 112,
                out info.OemRootCertificateSlot);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 116, out info.AntiRollbackVersion);
            info.HasOemRootCertificateSlot = true;
            info.SoftwareId = softwareId;
            info.HardwareId = hardwareId;
        }

        return true;
    }

    private static bool TryReadV7(ReadOnlySpan<byte> data, ref HashSegmentInfo info, out string error)
    {
        if (data.Length < V7HeaderSize
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 8, out uint commonMetadataSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 12, out uint metadataSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 16, out uint metadataSizeOem)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 20, out uint hashSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 24, out uint signatureSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 28, out uint certificateSizeQti)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 32, out uint signatureSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 36, out uint certificateSize))
        {
            error = "MBN v7 头不完整";
            return false;
        }

        if (commonMetadataSize < V7CommonMetadataSize)
        {
            error = "MBN v7 公共元数据长度无效";
            return false;
        }

        ulong metadataSize = (ulong)commonMetadataSize + metadataSizeQti + metadataSizeOem;
        ulong requiredSize = metadataSize + hashSize + signatureSizeQti + certificateSizeQti
                             + signatureSize + certificateSize;
        if (!BinaryDataReader.IsRangeInside(V7HeaderSize, requiredSize, data.Length))
        {
            error = "MBN v7 数据范围超出镜像";
            return false;
        }

        ulong hashOffset = (ulong)V7HeaderSize + metadataSize;
        ulong qtiSignatureOffset = hashOffset + hashSize;
        ulong qtiCertificateOffset = qtiSignatureOffset + signatureSizeQti;
        ulong oemSignatureOffset = qtiCertificateOffset + certificateSizeQti;
        ulong oemCertificateOffset = qtiCertificateOffset + certificateSizeQti + signatureSize;
        if (!TrySetAuthenticationRanges(data,
                qtiSignatureOffset, signatureSizeQti, qtiCertificateOffset, certificateSizeQti,
                oemSignatureOffset, signatureSize, oemCertificateOffset, certificateSize,
                ref info, out error))
            return false;

        info.UsesSha384 = true;
        info.HeaderLength = V7HeaderSize;
        info.QualcommMetadataOffset = checked(V7HeaderSize + (int)commonMetadataSize);
        info.QualcommMetadataLength = checked((int)metadataSizeQti);
        info.OemMetadataOffset = checked(info.QualcommMetadataOffset + info.QualcommMetadataLength);
        info.OemMetadataLength = checked((int)metadataSizeOem);
        info.HashOffset = checked((int)hashOffset);
        info.HashSize = hashSize;
        BinaryDataReader.TryReadUInt32LittleEndian(data, V7HeaderSize + 8, out uint softwareId);
        BinaryDataReader.TryReadUInt32LittleEndian(data, V7HeaderSize + 16, out info.HashTableAlgorithm);
        info.SoftwareId = softwareId;

        if (metadataSizeQti >= 16)
        {
            BinaryDataReader.TryReadUInt32LittleEndian(
                data,
                info.QualcommMetadataOffset + 12,
                out info.QualcommRootCertificateSlot);
            info.HasQualcommRootCertificateSlot = true;
        }

        ulong oemMetadataOffset = (ulong)V7HeaderSize + commonMetadataSize + metadataSizeQti;
        if (metadataSizeOem >= V7OemMetadataSize
            && BinaryDataReader.IsRangeInside(oemMetadataOffset, V7OemMetadataSize, data.Length))
        {
            info.HasOemId = true;
            int offset = checked((int)oemMetadataOffset);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 8, out info.AntiRollbackVersion);
            BinaryDataReader.TryReadUInt32LittleEndian(
                data,
                offset + 12,
                out info.OemRootCertificateSlot);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 16, out info.SocHwVersion);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 136, out info.OemId);
            BinaryDataReader.TryReadUInt32LittleEndian(data, offset + 140, out info.ModelId);
            BinaryDataReader.TryReadUInt32LittleEndian(
                data,
                offset + 152,
                out info.MetadataRootCertificateHashAlgorithm);
            ReadOnlySpan<byte> rootHash = data.Slice(offset + 156, 64);
            if (!IsAllZero(rootHash))
            {
                info.MetadataRootCertificateHashOffset = offset + 156;
                info.MetadataRootCertificateHashLength = rootHash.Length;
                info.MetadataRootCertificateHash = HexEncoding.ToHexString(rootHash);
            }

            info.HasOemRootCertificateSlot = true;
        }

        return true;
    }

    private static bool TryReadCommonFields(
        ReadOnlySpan<byte> data,
        out uint imageId,
        out uint totalSize,
        out uint hashSize,
        out uint signatureSize,
        out uint certificateSize)
    {
        imageId = 0;
        totalSize = 0;
        hashSize = 0;
        signatureSize = 0;
        certificateSize = 0;
        if (!BinaryDataReader.TryReadUInt32LittleEndian(data, 0, out imageId)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 16, out totalSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 20, out hashSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 28, out signatureSize)
            || !BinaryDataReader.TryReadUInt32LittleEndian(data, 36, out certificateSize))
        {
            return false;
        }

        return true;
    }

    private static bool TryValidateLayout(
        ReadOnlySpan<byte> data,
        int headerSize,
        uint totalSize,
        ulong requiredSize,
        ulong metadataSize,
        out string error)
    {
        ulong minimumDeclaredSize = requiredSize - metadataSize;
        if (requiredSize > 0 && totalSize == 0)
        {
            error = "MBN 头声明的总长度为零";
            return false;
        }

        if (totalSize < minimumDeclaredSize)
        {
            error = "MBN 头声明的总长度小于各数据段之和";
            return false;
        }

        ulong declaredSize = totalSize switch
        {
            _ when totalSize < requiredSize => metadataSize + totalSize,
            _ => totalSize
        };
        if (!BinaryDataReader.IsRangeInside((ulong)headerSize, declaredSize, data.Length)
            || !BinaryDataReader.IsRangeInside((ulong)headerSize, requiredSize, data.Length))
        {
            error = "MBN 数据范围超出镜像";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool TrySetAuthenticationRanges(
        ReadOnlySpan<byte> data,
        ulong qtiSignatureOffset,
        uint qtiSignatureLength,
        ulong qtiOffset,
        uint qtiLength,
        ulong oemSignatureOffset,
        uint oemSignatureLength,
        ulong oemOffset,
        uint oemLength,
        ref HashSegmentInfo info,
        out string error)
    {
        if (!BinaryDataReader.IsRangeInside(qtiSignatureOffset, qtiSignatureLength, data.Length)
            || !BinaryDataReader.IsRangeInside(qtiOffset, qtiLength, data.Length)
            || !BinaryDataReader.IsRangeInside(oemSignatureOffset, oemSignatureLength, data.Length)
            || !BinaryDataReader.IsRangeInside(oemOffset, oemLength, data.Length))
        {
            error = "MBN 签名或证书链范围超出镜像";
            return false;
        }

        info.QualcommSignatureOffset = checked((int)qtiSignatureOffset);
        info.QualcommSignatureLength = checked((int)qtiSignatureLength);
        info.QualcommCertificateOffset = checked((int)qtiOffset);
        info.QualcommCertificateLength = checked((int)qtiLength);
        info.OemSignatureOffset = checked((int)oemSignatureOffset);
        info.OemSignatureLength = checked((int)oemSignatureLength);
        info.OemCertificateOffset = checked((int)oemOffset);
        info.OemCertificateLength = checked((int)oemLength);
        error = string.Empty;
        return true;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        for (int index = 0; index < data.Length; index++)
        {
            if (data[index] != 0)
                return false;
        }

        return true;
    }
}
