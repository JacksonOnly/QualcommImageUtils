using System.Buffers.Binary;

namespace QcomImageUtils.Utilities;

internal static class BinaryDataReader
{
    public static bool TryReadUInt16LittleEndian(ReadOnlySpan<byte> data, int offset, out ushort value)
    {
        if (!IsRangeInside(offset, sizeof(ushort), data.Length))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, sizeof(ushort)));
        return true;
    }

    public static bool TryReadUInt32LittleEndian(ReadOnlySpan<byte> data, int offset, out uint value)
    {
        if (!IsRangeInside(offset, sizeof(uint), data.Length))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
        return true;
    }

    public static bool TryReadUInt64LittleEndian(ReadOnlySpan<byte> data, int offset, out ulong value)
    {
        if (!IsRangeInside(offset, sizeof(ulong), data.Length))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset, sizeof(ulong)));
        return true;
    }

    public static bool IsRangeInside(ulong offset, ulong length, int bufferLength)
    {
        return offset <= (ulong)bufferLength && length <= (ulong)bufferLength - offset;
    }

    public static bool IsRangeInside(int offset, int length, int bufferLength)
    {
        return offset >= 0 && length >= 0 && offset <= bufferLength && length <= bufferLength - offset;
    }
}
