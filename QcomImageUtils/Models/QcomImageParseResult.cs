using System;
using System.Collections.Generic;
using QcomImageUtils.Types;

namespace QcomImageUtils.Models;

public sealed class QcomImageParseResult
{
    public bool IsSuccess { get; internal set; }
    public string OriginalFilePath { get; internal set; } = string.Empty;
    public string OriginalFileName { get; internal set; } = string.Empty;
    public string ImageFormat { get; internal set; } = string.Empty;
    public string FileSha256 { get; internal set; } = string.Empty;
    public uint? ImageId { get; internal set; }
    public QcomImageType? ImageType { get; internal set; }
    public uint HeaderVersion { get; internal set; }
    public bool IsProgrammer { get; internal set; }
    public BootMemoryType BootMemoryType { get; internal set; }
    public DramGeneration DramGeneration { get; internal set; }
    public bool IsSbl { get; internal set; }
    public SblType? SblType { get; internal set; }
    public uint SocHwVersion { get; internal set; }
    public bool HasOemId { get; internal set; }
    public uint OemId { get; internal set; }
    public uint ModelId { get; internal set; }
    public uint AntiRollbackVersion { get; internal set; }
    public uint? QualcommRootCertificateSlot { get; internal set; }
    public uint? OemRootCertificateSlot { get; internal set; }
    public ulong SwId { get; internal set; }
    public uint SwSize { get; internal set; }
    public ulong HwId { get; internal set; }
    public uint MsmId { get; internal set; }
    public QualcommSocType SocType { get; internal set; } = QualcommSocType.Unknown;
    public QualcommOemType OemType { get; internal set; }
    public string QcVersion { get; internal set; } = string.Empty;
    public string OemVersion { get; internal set; } = string.Empty;
    public string ImageVariant { get; internal set; } = string.Empty;
    public string? BuildTime { get; internal set; }
    public string RootCaSubject { get; internal set; } = string.Empty;
    public string RootCaHash { get; internal set; } = string.Empty;
    public IReadOnlyList<ImageCertItem> CertChains { get; internal set; } = Array.Empty<ImageCertItem>();
    public IReadOnlyList<FirehoseCommandInfo> SupportedCommands { get; internal set; } =
        Array.Empty<FirehoseCommandInfo>();
    public ulong? MaxPayloadSizeToTargetInBytesSupported { get; internal set; }
    public string? ErrorMessage { get; internal set; }
    public string? BuildTimeDebug { get; internal set; }
}
