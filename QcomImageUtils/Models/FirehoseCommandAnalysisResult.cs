using System;
using System.Collections.Generic;

namespace QcomImageUtils.Models;

/// <summary>
/// 表示一次 Firehose ELF 或 SBL MBN 支持命令分析的结果。
/// </summary>
public sealed class FirehoseCommandAnalysisResult
{
    public bool IsSuccess { get; internal set; }
    public string OriginalFilePath { get; internal set; } = string.Empty;
    public string OriginalFileName { get; internal set; } = string.Empty;
    public int AnalyzedElfCount { get; internal set; }
    public IReadOnlyList<FirehoseCommandInfo> Commands { get; internal set; } =
        Array.Empty<FirehoseCommandInfo>();
    public string? ErrorMessage { get; internal set; }
}
