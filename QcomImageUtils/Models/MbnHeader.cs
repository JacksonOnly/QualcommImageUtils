namespace QcomImageUtils.Models;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct MbnHeader
{
    public uint Codeword;
    public uint Magic;
    public uint ImageId;
    public uint Reserved1;
    public uint Reserved2;
    public uint ImageSrc;
    public uint ImageDestAddr;
    public uint ImageSize;
    public uint CodeSize;
    public uint SignatureAddr;
    public uint SignatureSize;
    public uint CertChainAddr;
    public uint CertChainSize;
    public uint OemRootCertSel;
    public uint OemNumRootCerts;
    public uint BootingImageConfig;
    public uint Reserved6;
    public uint Reserved7;
    public uint Reserved8;
    public uint Reserved9;
}