using System;
using System.Collections.Generic;
using QcomImageUtils.Types;

namespace QcomImageUtils.Models;

public sealed class QcomSignatureVerificationResult
{
    public CertificateChainType ChainType { get; internal set; }
    public QcomVerificationStatus SignatureStatus { get; internal set; }
    public QcomVerificationStatus CertificateChainStatus { get; internal set; }
    public string Algorithm { get; internal set; } = string.Empty;
    public int CertificateCount { get; internal set; }
    public string RootCertificateSha256 { get; internal set; } = string.Empty;
    public string RootCertificateSha384 { get; internal set; } = string.Empty;
    public IReadOnlyList<string> ValidRootCertificateSha256Hashes { get; internal set; } =
        Array.Empty<string>();
    public IReadOnlyList<string> ValidRootCertificateSha384Hashes { get; internal set; } =
        Array.Empty<string>();
    public string? ErrorMessage { get; internal set; }
}
