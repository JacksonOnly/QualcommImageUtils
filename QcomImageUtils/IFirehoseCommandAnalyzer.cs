using QcomImageUtils.Models;

namespace QcomImageUtils;

/// <summary>
/// 定义从 Firehose ELF 或 SBL MBN 静态分析支持命令的无异常契约。
/// </summary>
public interface IFirehoseCommandAnalyzer
{
    bool TryAnalyze(string filePath, out FirehoseCommandAnalysisResult result);
    bool TryAnalyze(ReadOnlySpan<byte> image, out FirehoseCommandAnalysisResult result);
}
