namespace QcomImageUtils.Utilities;

internal static class HexEncoding
{
    private const string Digits = "0123456789ABCDEF";

    public static string ToHexString(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

#if NET5_0_OR_GREATER
        return Convert.ToHexString(data);
#else
        var characters = new char[data.Length * 2];
        int characterIndex = 0;
        for (int index = 0; index < data.Length; index++)
        {
            byte value = data[index];
            characters[characterIndex++] = Digits[value >> 4];
            characters[characterIndex++] = Digits[value & 0x0F];
        }

        return new string(characters);
#endif
    }
}
