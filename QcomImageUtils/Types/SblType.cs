namespace QcomImageUtils.Types;

public enum SblType : byte
{
    SblAarch64 = 0xF, // Indicate that SBL is a Aarch64 image
    SblAarch32 = 0x0 // Indicate that SBL is a Aarch32 image
}