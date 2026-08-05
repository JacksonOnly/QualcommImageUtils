using System;
using System.Buffers;
using System.Security.Cryptography;

namespace QcomImageUtils.Utilities;

internal enum ImageHashAlgorithm
{
    Sha1,
    Sha256,
    Sha384,
    Sha512
}

internal readonly struct HashMask
{
    public HashMask(int offset, int length)
    {
        Offset = offset;
        Length = length;
    }

    public int Offset { get; }
    public int Length { get; }
}

internal static class CryptographicHash
{
    private static readonly byte[] ZeroBuffer = new byte[256];

    public static int GetDigestLength(ImageHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            ImageHashAlgorithm.Sha1 => 20,
            ImageHashAlgorithm.Sha256 => 32,
            ImageHashAlgorithm.Sha384 => 48,
            ImageHashAlgorithm.Sha512 => 64,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }

    public static HashAlgorithmName GetName(ImageHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            ImageHashAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            ImageHashAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            ImageHashAlgorithm.Sha384 => HashAlgorithmName.SHA384,
            ImageHashAlgorithm.Sha512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }

    public static string GetDisplayName(ImageHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            ImageHashAlgorithm.Sha1 => "SHA1",
            ImageHashAlgorithm.Sha256 => "SHA256",
            ImageHashAlgorithm.Sha384 => "SHA384",
            ImageHashAlgorithm.Sha512 => "SHA512",
            _ => string.Empty
        };
    }

    public static void Compute(
        ImageHashAlgorithm algorithm,
        ReadOnlySpan<byte> data,
        Span<byte> destination)
    {
        int digestLength = GetDigestLength(algorithm);
        if (destination.Length < digestLength)
            throw new ArgumentException("摘要输出缓冲区太小", nameof(destination));

#if NET8_0_OR_GREATER
        switch (algorithm)
        {
            case ImageHashAlgorithm.Sha1:
                SHA1.HashData(data, destination);
                break;
            case ImageHashAlgorithm.Sha256:
                SHA256.HashData(data, destination);
                break;
            case ImageHashAlgorithm.Sha384:
                SHA384.HashData(data, destination);
                break;
            case ImageHashAlgorithm.Sha512:
                SHA512.HashData(data, destination);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm));
        }
#else
        using HashAlgorithm hashAlgorithm = Create(algorithm);
        AppendData(hashAlgorithm, data);
        CompleteHash(hashAlgorithm, destination, digestLength);
#endif
    }

    public static void Compute(
        ImageHashAlgorithm algorithm,
        ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second,
        Span<byte> destination)
    {
#if NET8_0_OR_GREATER
        using IncrementalHash hash = IncrementalHash.CreateHash(GetName(algorithm));
        hash.AppendData(first);
        hash.AppendData(second);
        if (!hash.TryGetHashAndReset(destination, out int bytesWritten)
            || bytesWritten != GetDigestLength(algorithm))
        {
            throw new CryptographicException("无法计算镜像摘要");
        }
#else
        using HashAlgorithm hashAlgorithm = Create(algorithm);
        AppendData(hashAlgorithm, first);
        AppendData(hashAlgorithm, second);
        CompleteHash(hashAlgorithm, destination, GetDigestLength(algorithm));
#endif
    }

    public static void Compute(
        ImageHashAlgorithm algorithm,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<HashMask> masks,
        Span<byte> destination)
    {
        if (masks.IsEmpty)
        {
            Compute(algorithm, data, destination);
            return;
        }

        int digestLength = GetDigestLength(algorithm);
        if (destination.Length < digestLength)
            throw new ArgumentException("摘要输出缓冲区太小", nameof(destination));

#if NET8_0_OR_GREATER
        using IncrementalHash hash = IncrementalHash.CreateHash(GetName(algorithm));
        int dataOffset = 0;
        for (int index = 0; index < masks.Length; index++)
        {
            HashMask mask = masks[index];
            int maskEnd = ValidateMask(mask, dataOffset, data.Length);
            hash.AppendData(data.Slice(dataOffset, mask.Offset - dataOffset));
            AppendZeros(hash, mask.Length);
            dataOffset = maskEnd;
        }

        hash.AppendData(data.Slice(dataOffset));
        if (!hash.TryGetHashAndReset(destination, out int bytesWritten)
            || bytesWritten != digestLength)
        {
            throw new CryptographicException("无法计算镜像摘要");
        }
#else
        using HashAlgorithm hash = Create(algorithm);
        int dataOffset = 0;
        for (int index = 0; index < masks.Length; index++)
        {
            HashMask mask = masks[index];
            int maskEnd = ValidateMask(mask, dataOffset, data.Length);
            AppendData(hash, data.Slice(dataOffset, mask.Offset - dataOffset));
            AppendZeros(hash, mask.Length);
            dataOffset = maskEnd;
        }

        AppendData(hash, data.Slice(dataOffset));
        CompleteHash(hash, destination, digestLength);
#endif
    }

    private static int ValidateMask(HashMask mask, int minimumOffset, int dataLength)
    {
        if (mask.Offset < minimumOffset
            || mask.Length < 0
            || mask.Offset > dataLength - mask.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(mask));
        }

        return mask.Offset + mask.Length;
    }

#if NET8_0_OR_GREATER
    private static void AppendZeros(IncrementalHash hash, int length)
    {
        while (length > 0)
        {
            int blockLength = Math.Min(length, ZeroBuffer.Length);
            hash.AppendData(ZeroBuffer.AsSpan(0, blockLength));
            length -= blockLength;
        }
    }
#endif

#if !NET8_0_OR_GREATER
    private const int LegacyHashBufferSize = 128 * 1024;

    private static void AppendData(HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(data.Length, LegacyHashBufferSize));
        try
        {
            while (!data.IsEmpty)
            {
                int length = Math.Min(data.Length, buffer.Length);
                data.Slice(0, length).CopyTo(buffer);
                hashAlgorithm.TransformBlock(buffer, 0, length, buffer, 0);
                data = data.Slice(length);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void AppendZeros(HashAlgorithm hashAlgorithm, int length)
    {
        while (length > 0)
        {
            int blockLength = Math.Min(length, ZeroBuffer.Length);
            hashAlgorithm.TransformBlock(ZeroBuffer, 0, blockLength, ZeroBuffer, 0);
            length -= blockLength;
        }
    }

    private static void CompleteHash(
        HashAlgorithm hashAlgorithm,
        Span<byte> destination,
        int digestLength)
    {
        hashAlgorithm.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] hash = hashAlgorithm.Hash ?? throw new CryptographicException("无法计算镜像摘要");
        if (hash.Length != digestLength)
            throw new CryptographicException("镜像摘要长度无效");
        hash.AsSpan().CopyTo(destination);
    }

    private static HashAlgorithm Create(ImageHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            ImageHashAlgorithm.Sha1 => SHA1.Create(),
            ImageHashAlgorithm.Sha256 => SHA256.Create(),
            ImageHashAlgorithm.Sha384 => SHA384.Create(),
            ImageHashAlgorithm.Sha512 => SHA512.Create(),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }
#endif
}
