using System;
using System.Collections.Generic;
using QcomImageUtils.Types;

namespace QcomImageUtils.Models;

/// <summary>
/// 表示 Qualcomm 镜像的内容摘要、签名、证书链和可信根验证结果。
/// </summary>
public sealed class QcomImageVerificationResult
{
    public bool VerificationCompleted { get; internal set; }
    public bool IsVerified { get; internal set; }
    public bool IsIntegrityValid { get; internal set; }
    public bool IsAuthentic { get; internal set; }
    public bool? IsTrusted { get; internal set; }
    public QcomImageParseResult Image { get; internal set; } = new();
    public QcomVerificationStatus HashTableStatus { get; internal set; }
    public QcomVerificationStatus SignatureStatus { get; internal set; }
    public QcomVerificationStatus CertificateChainStatus { get; internal set; }
    public QcomVerificationStatus MetadataRootHashStatus { get; internal set; }
    public QcomVerificationStatus TrustedRootStatus { get; internal set; }
    public int ExpectedHashCount { get; internal set; }
    public int VerifiedHashCount { get; internal set; }
    public int FailedSegmentIndex { get; internal set; } = -1;
    public QcomSignatureVerificationResult QualcommSignature { get; internal set; } = new()
    {
        ChainType = CertificateChainType.Qualcomm
    };
    public QcomSignatureVerificationResult OemSignature { get; internal set; } = new()
    {
        ChainType = CertificateChainType.Oem
    };
    public IReadOnlyList<QcomImageComponentVerificationResult> Components { get; internal set; }
        = Array.Empty<QcomImageComponentVerificationResult>();
    public IReadOnlyList<string> Issues { get; internal set; } = Array.Empty<string>();
    public string? ErrorMessage { get; internal set; }
}
