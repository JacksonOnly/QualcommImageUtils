namespace QcomImageUtils.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HashSegmentV5
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
}