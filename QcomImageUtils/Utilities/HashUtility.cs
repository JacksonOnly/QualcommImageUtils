using System.Security.Cryptography;

namespace QcomImageUtils.Utilities;

internal static class HashUtility
{
    public static string ComputeSha256Hex(ReadOnlySpan<byte> data)
    {
#if NET8_0_OR_GREATER
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash);
#else
        Span<byte> hash = stackalloc byte[32];
        CryptographicHash.Compute(ImageHashAlgorithm.Sha256, data, hash);
        return HexEncoding.ToHexString(hash);
#endif
    }

    public static string ComputeSha384Hex(ReadOnlySpan<byte> data)
    {
#if NET8_0_OR_GREATER
        Span<byte> hash = stackalloc byte[48];
        SHA384.HashData(data, hash);
        return Convert.ToHexString(hash);
#else
        Span<byte> hash = stackalloc byte[48];
        CryptographicHash.Compute(ImageHashAlgorithm.Sha384, data, hash);
        return HexEncoding.ToHexString(hash);
#endif
    }
}
