using QcomImageUtils.Models;

namespace QcomImageUtils;

/// <summary>
/// 定义 Qualcomm ELF 与 MBN 镜像的密码学验证契约。
/// </summary>
public interface IQcomImageVerifier
{
    bool TryVerify(string filePath, out QcomImageVerificationResult result);
    bool TryVerify(ReadOnlySpan<byte> image, out QcomImageVerificationResult result);
}
