using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace QcomImageUtils.Utilities;

internal static class CertificateChainLoader
{
    /// <summary>
    /// 从 DER 编码的字节数组中提取所有 X.509 证书。
    /// </summary>
    /// <param name="derData">DER 格式的证书数据（可包含多个连续证书）。</param>
    /// <returns>证书数组，顺序与数据中出现顺序一致。</returns>
    /// <exception cref="ArgumentException">数据格式无效或解析失败。</exception>
    public static X509Certificate2[] LoadCertificatesFromDer(byte[] derData)
    {
        if (derData == null || derData.Length == 0)
            throw new ArgumentException("证书数据不能为空", nameof(derData));

        var certs = new List<X509Certificate2>();
        int offset = 0;

        while (offset < derData.Length)
        {
            if (certs.Count > 0 && derData[offset] == 0xFF)
                break;
            // 检查是否是 SEQUENCE (0x30)
            if (derData[offset] != 0x30)
                throw new FormatException($"预期 SEQUENCE 标记 (0x30)，实际在偏移 {offset} 处为 0x{derData[offset]:X2}");

            // 解析长度（支持短格式和长格式）
            int length;
            int lengthBytes;
            if ((derData[offset + 1] & 0x80) == 0) // 短格式
            {
                length = derData[offset + 1];
                lengthBytes = 1;
            }
            else // 长格式
            {
                int numLenBytes = derData[offset + 1] & 0x7F;
                if (numLenBytes > 4) // 防止溢出，最大支持 4 字节长度
                    throw new FormatException($"长度字段过长 ({numLenBytes} 字节)");

                lengthBytes = 1 + numLenBytes;
                length = 0;
                for (int i = 0; i < numLenBytes; i++)
                {
                    length = (length << 8) | derData[offset + 1 + i + 1];
                }
            }

            int totalLength = 1 + lengthBytes + length; // 标签(1) + 长度字段 + 内容
            if (offset + totalLength > derData.Length)
                throw new FormatException($"证书数据不完整，预期 {totalLength} 字节，实际剩余 {derData.Length - offset} 字节");

            // 复制该证书的字节块（必须独立副本，因为 X509Certificate2 会持有）
            byte[] certBytes = new byte[totalLength];
            Buffer.BlockCopy(derData, offset, certBytes, 0, totalLength);

            // 加载证书
            X509Certificate2 cert;
            try
            {
                cert = new X509Certificate2(certBytes);
            }
            catch (Exception ex)
            {
                throw new FormatException($"在偏移 {offset} 处解析证书失败", ex);
            }

            certs.Add(cert);
            offset += totalLength;
        }

        return certs.ToArray();
    }
}