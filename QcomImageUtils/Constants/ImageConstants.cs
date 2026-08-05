namespace QcomImageUtils.Constants;

internal static class ImageConstants
{
    public const byte PadByte1 = 255;
    public const byte PadByte0 = 0;
    public const int Sha256SignatureSize = 256;
    public const int MaxNumRootCerts = 4;
    public const int MiBootSblHdrSize = 80;
    public const int BootHeaderLength = 20;
    public const int SblHeaderLength = 20;
    public const int MaxPhdrCount = 100;
    public const int CertChainOnerootMaxsize = 6 * 1024;
    public const int VirtualBlockSize = 131072;
    public const int MagicCookieLength = 12;
    public const int MinImageSizeWithPad = 256 * 1024;

    public const uint FlashCodeWord = 0x844BDCD1;
    public const uint UnifiedBootCookieMagicNumber = 0x33836685;
    public const uint MagicNum = 0x73D71034;
    public const uint AutodetectPageSizeMagicNum = 0x7D0B435A;
    public const uint AutodetectPageSizeMagicNum64 = 0x7D0B5436;
    public const uint AutodetectPageSizeMagicNum128 = 0x7D0B6577;
    public const uint SblVirtualBlockMagicNum = 0xD48B54C6;

    public const uint MiPbtFlagsMask = 0x0FF00000;
    public const uint MiPbtFlagSegmentTypeMask = 0x07000000;
    public const int MiPbtFlagSegmentTypeShift = 0x18;
    public const uint MiPbtFlagPageModeMask = 0x00100000;
    public const int MiPbtFlagPageModeShift = 0x14;
    public const uint MiPbtFlagAccessTypeMask = 0x00E00000;
    public const int MiPbtFlagAccessTypeShift = 0x15;
    public const uint MiPbtFlagPoolIndexMask = 0x08000000;
    public const int MiPbtFlagPoolIndexShift = 0x1B;

    public const uint MiPbtL4Segment = 0x0;
    public const uint MiPbtAmssSegment = 0x1;
    public const uint MiPbtHashSegment = 0x2;
    public const uint MiPbtBootSegment = 0x3;
    public const uint MiPbtL4BspSegment = 0x4;
    public const uint MiPbtSwappedSegment = 0x5;
    public const uint MiPbtXblSecSegment = 0x5;
    public const uint MiPbtSwapPoolSegment = 0x6;
    public const uint MiPbtPhdrSegment = 0x7;

    public const uint MiPbtNonPagedSegment = 0x0;
    public const uint MiPbtPagedSegment = 0x1;

    public const uint MiPbtRwSegment = 0x0;
    public const uint MiPbtRoSegment = 0x1;
    public const uint MiPbtZiSegment = 0x2;
    public const uint MiPbtNotusedSegment = 0x3;
    public const uint MiPbtSharedSegment = 0x4;
    public const uint MiPbtRweSegment = 0x7;

    public const uint MiPbtElfAmssNonPagedRoSegment = 0x01200000;
    public const uint MiPbtElfAmssPagedRoSegment = 0x01300000;
    public const uint MiPbtElfSwapPoolNonPagedZiSegmentIndex0 = 0x06400000;
    public const uint MiPbtElfSwappedPagedRoSegmentIndex0 = 0x05300000;
    public const uint MiPbtElfSwapPoolNonPagedZiSegmentIndex1 = 0x0E400000;
    public const uint MiPbtElfSwappedPagedRoSegmentIndex1 = 0x0D300000;
    public const uint MiPbtElfAmssNonPagedZiSegment = 0x01400000;
    public const uint MiPbtElfAmssPagedZiSegment = 0x01500000;
    public const uint MiPbtElfAmssNonPagedRwSegment = 0x01000000;
    public const uint MiPbtElfAmssPagedRwSegment = 0x01100000;
    public const uint MiPbtElfAmssNonPagedNotusedSegment = 0x01600000;
    public const uint MiPbtElfAmssPagedNotusedSegment = 0x01700000;
    public const uint MiPbtElfAmssNonPagedSharedSegment = 0x01800000;
    public const uint MiPbtElfAmssPagedSharedSegment = 0x01900000;
    public const uint MiPbtElfHashSegment = 0x02200000;
    public const uint MiPbtElfBootSegment = 0x03200000;
    public const uint MiPbtElfPhdrSegment = 0x07000000;
    public const uint MiPbtElfNonPagedL4BspSegment = 0x04000000;
    public const uint MiPbtElfPagedL4BspSegment = 0x04100000;
    public const uint MiPbtElfAmssRelocatableImage = 0x08000000;

    public const uint MiPbtElfResidentSegment = 0x00000000;
    public const uint MiPbtElfPagedLockedSegment = 0x00100000;
    public const uint MiPbtElfPagedUnlockedSegment = 0x01100000;
    public const uint MiPbtElfUnsecureSegment = 0x03100000;
}
