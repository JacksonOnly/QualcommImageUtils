namespace QcomImageUtils.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HashSegmentV3
{
    public uint ImageId;
    public uint Version;
    public uint FlashAddr;
    public uint DestAddr;
    public uint TotalSize;
    public uint HashSize;
    public uint SignatureAddr;
    public uint SignatureSize;
    public uint CertChainAddr;
    public uint CertChainSize;
}
