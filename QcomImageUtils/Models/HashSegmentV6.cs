namespace QcomImageUtils.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HashSegmentV6
{
    public uint ImageId;
    public uint Version;
    public uint SignatureSizeQcom;
    public uint CertChainSizeQcom;
    public uint TotalSize;
    public uint HashSize;
    public uint SignatureAddr;
    public uint SignatureSize;
    public uint CertChainAddr;
    public uint CertChainSize;
    public uint MetadataSizeQcom;
    public uint MetadataSize;
    public uint MajorVersion;
    public uint MinorVersion;
    public uint SoftwareId;
    public uint HardwareId;
    public uint OemId;
    public uint ModelId;
    public uint AppId;
    public uint Flags;
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
    public ulong SerialNumber0;
    public ulong SerialNumber1;
    public ulong SerialNumber2;
    public ulong SerialNumber3;
    public uint MrcIndex;
    public uint AntiRollbackVersion;
}