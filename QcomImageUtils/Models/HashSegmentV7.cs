namespace QcomImageUtils.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct HashSegmentV7
{
    public uint ImageId;
    public uint Version;
    public uint CommonMetadataSize;
    public uint MetadataSizeQcom;
    public uint MetadataSize;
    public uint HashSize;
    public uint SignatureSizeQcom;
    public uint CertChainSizeQcom;
    public uint SignatureSize;
    public uint CertChainSize;
    public uint CommonMetadataMajorVersion;
    public uint CommonMetadataMinorVersion;
    public uint SoftwareId;
    public uint SecondarySoftwareId;
    public uint HashTableAlgorithm;
    public uint MeasurementRegisterTarget;
    public uint MajorVersion;
    public uint MinorVersion;
    public uint AntiRollbackVersion;
    public uint MrcIndex;
    public uint SocHwVer0;
    public uint SocHwVer1;
    public uint SocHwVer2;
    public uint SocHwVer3;
    public uint SocHwVer4;
    public uint SocHwVer5;
    public uint SocHwVer6;
    public uint SocHwVer7;
    public uint SocHwVer8;
    public uint SocHwVer9;
    public uint SocHwVer10;
    public uint SocHwVer11;
    public int SocFeatureId;
    public int JtagId;
    public ulong SerialNumber0;
    public ulong SerialNumber1;
    public ulong SerialNumber2;
    public ulong SerialNumber3;
    public ulong SerialNumber4;
    public ulong SerialNumber5;
    public ulong SerialNumber6;
    public ulong SerialNumber7;
    public uint OemId;
    public uint OemProductId;
    public uint SocLifecycleState;
    public uint OemLifecycleState;
    public uint OemRootCertificateHashAlgorithm;
    public fixed byte OemRootCertificateHash[64];
    public uint Flags;
}