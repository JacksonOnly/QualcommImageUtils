namespace QcomImageUtils;

/// <summary>
/// 配置 Qualcomm 镜像解析过程中的可选成本与资源上限。
/// </summary>
public sealed class QcomImageParserOptions
{
    public bool CalculateFileSha256 { get; set; }
    public bool ExportCertificatePem { get; set; } = true;
    public bool AnalyzeFirehoseCommands { get; set; } = true;
    public int MaximumImageSize { get; set; } = 512 * 1024 * 1024;
    public int MaximumCertificateChainSize { get; set; } = 1024 * 1024;
    public int MaximumCertificateCount { get; set; } = 32;
    public int MaximumMetadataStringLength { get; set; } = 512;
}
