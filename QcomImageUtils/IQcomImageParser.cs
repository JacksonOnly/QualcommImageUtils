using QcomImageUtils.Models;

namespace QcomImageUtils;

/// <summary>
/// 定义 Qualcomm ELF 与 MBN 镜像的无异常解析契约。
/// </summary>
public interface IQcomImageParser
{
    bool TryParse(string filePath, out QcomImageParseResult result);
    bool TryParse(ReadOnlySpan<byte> image, out QcomImageParseResult result);
}
