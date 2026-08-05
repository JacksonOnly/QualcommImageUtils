using System;
using System.Collections.Generic;
using QcomImageUtils.Types;

namespace QcomImageUtils.Models;

/// <summary>
/// 表示多 ELF 容器中单个 Qualcomm ELF 组件的密码学验证结果，组件索引从零开始，偏移相对于输入镜像起点。
/// </summary>
public sealed class QcomImageComponentVerificationResult
{
    public int ComponentIndex { get; internal set; }
    public int ImageOffset { get; internal set; }
    public bool VerificationCompleted { get; internal set; }
    public bool IsVerified { get; internal set; }
    public bool IsIntegrityValid { get; internal set; }
    public bool IsAuthentic { get; internal set; }
    public bool? IsTrusted { get; internal set; }
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
    public IReadOnlyList<string> Issues { get; internal set; } = Array.Empty<string>();
    public string? ErrorMessage { get; internal set; }
}
