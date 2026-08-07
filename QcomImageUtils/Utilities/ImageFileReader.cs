using System;
using System.IO;
using System.Security;

namespace QcomImageUtils.Utilities;

/// <summary>
/// 以统一的资源上限和错误语义读取镜像文件。
/// </summary>
internal static class ImageFileReader
{
    public static bool TryRead(
        string filePath,
        int maximumImageSize,
        out byte[] image,
        out string fullPath,
        out string fileName,
        out string error)
    {
        image = [];
        fullPath = string.Empty;
        fileName = string.Empty;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(filePath))
        {
            error = "镜像路径不能为空";
            return false;
        }

        try
        {
            fullPath = Path.GetFullPath(filePath);
            fileName = Path.GetFileName(fullPath);
            using var stream = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.SequentialScan);
            long fileLength = stream.Length;
            if (fileLength <= 0)
            {
                error = "镜像文件为空";
                return false;
            }
            if (fileLength > maximumImageSize)
            {
                error = $"镜像文件超过配置的 {maximumImageSize} 字节上限";
                return false;
            }

#if NET5_0_OR_GREATER
            image = GC.AllocateUninitializedArray<byte>(checked((int)fileLength));
#else
            image = new byte[checked((int)fileLength)];
#endif
            int offset = 0;
            while (offset < image.Length)
            {
                int read = stream.Read(image, offset, image.Length - offset);
                if (read == 0)
                {
                    error = "读取镜像时遇到意外的文件末尾";
                    return false;
                }

                offset += read;
            }

            if (stream.ReadByte() >= 0)
            {
                error = "读取镜像时文件长度发生变化";
                return false;
            }

            return true;
        }
        catch (FileNotFoundException)
        {
            error = "镜像文件不存在";
            return false;
        }
        catch (Exception exception) when (exception is IOException
                                           or UnauthorizedAccessException
                                           or SecurityException
                                           or NotSupportedException
                                           or ArgumentException)
        {
            error = $"无法读取镜像: {exception.Message}";
            return false;
        }
    }
}
