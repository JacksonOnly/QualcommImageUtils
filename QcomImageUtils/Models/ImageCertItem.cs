namespace QcomImageUtils.Models;

public sealed class ImageCertItem
{
    public Types.CertificateChainType ChainType { get; internal set; }
    public int Index { get; internal set; }
    public bool IsRoot { get; internal set; }
    public string Subject { get; internal set; } = string.Empty;
    public string Issuer { get; internal set; } = string.Empty;
    public string SerialNumber { get; internal set; } = string.Empty;
    public string Sha256 { get; internal set; } = string.Empty;
    public string CertPem { get; internal set; } = string.Empty;
}
