namespace QcomImageUtils.Utilities;

/// <summary>
/// Pure arithmetic shared by the ARM data-flow readers.
/// </summary>
internal static class ArmInstructionMath
{
    public static bool TryAddSigned(
        ulong value,
        long offset,
        out ulong result)
    {
        if (offset >= 0)
        {
            ulong positive = checked((ulong)offset);
            if (value > ulong.MaxValue - positive)
            {
                result = 0;
                return false;
            }

            result = value + positive;
            return true;
        }

        ulong negative = checked((ulong)(-(offset + 1))) + 1;
        if (value < negative)
        {
            result = 0;
            return false;
        }

        result = value - negative;
        return true;
    }

    public static long SignExtend(
        ulong value,
        int bitCount)
    {
        if (bitCount is < 1 or > 64)
            throw new ArgumentOutOfRangeException(nameof(bitCount));

        int shift = 64 - bitCount;
        return ((long)(value << shift)) >> shift;
    }

    public static uint RotateRight(
        uint value,
        int count)
    {
        count &= 31;
        return count == 0
            ? value
            : (value >> count) | (value << (32 - count));
    }

    public static uint DecodeArm32Immediate(uint instruction)
    {
        return RotateRight(
            instruction & 0xFF,
            checked((int)(((instruction >> 8) & 0xF) * 2)));
    }
}
