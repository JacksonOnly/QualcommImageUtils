namespace QcomImageUtils;

/// <summary>
/// 配置 Firehose 命令静态分析的资源与置信边界。
/// </summary>
public sealed class FirehoseCommandAnalyzerOptions
{
    public int MaximumImageSize { get; set; } = 512 * 1024 * 1024;
    public int MaximumElfCount { get; set; } = 64;
    public int MinimumCommandTableEntries { get; set; } = 3;
    public int MaximumCommandLength { get; set; } = 64;
}
