namespace QcomImageUtils.Constants
{
    internal static class ImageConstants
    {
        public const byte PadByte1 = 255; // Padding byte 1s
        public const byte PadByte0 = 0; // Padding byte 0s
        public const int Sha256SignatureSize = 256; // Support SHA256
        public const int MaxNumRootCerts = 4; // Maximum number of OEM root certificates
        public const int MiBootSblHdrSize = 80; // sizeof(sbl_header)
        public const int BootHeaderLength = 20; // Boot Header Number of Elements
        public const int SblHeaderLength = 20; // SBL Header Number of Elements
        public const int MaxPhdrCount = 100; // Maximum allowable program headers
        public const int CertChainOnerootMaxsize = 6 * 1024; // Default Cert Chain Max Size for one root

        public const int
            VirtualBlockSize = 131072; // Virtual block size for MCs insertion in SBL1 if ENABLE_VIRTUAL_BLK ON

        public const int MagicCookieLength = 12; // Length of magic Cookie inserted per VIRTUAL_BLOCK_SIZE
        public const int MinImageSizeWithPad = 256 * 1024; // Minimum image size for sbl1 Nand based OTA feature


        // Magic numbers filled in for boot headers
        public const uint FlashCodeWord = 0x844BDCD1;
        public const uint UnifiedBootCookieMagicNumber = 0x33836685;
        public const uint MagicNum = 0x73D71034;
        public const uint AutodetectPageSizeMagicNum = 0x7D0B435A;
        public const uint AutodetectPageSizeMagicNum64 = 0x7D0B5436;
        public const uint AutodetectPageSizeMagicNum128 = 0x7D0B6577;
        public const uint SblVirtualBlockMagicNum = 0xD48B54C6;


        // Mask for bits 20-27 to parse program header p_flags
        public const int MiPbtFlagsMask = 0x0FF00000;

        // Helper defines to help parse ELF program headers
        public const int MiPbtFlagSegmentTypeMask = 0x07000000;
        public const int MiPbtFlagSegmentTypeShift = 0x18;
        public const int MiPbtFlagPageModeMask = 0x00100000;
        public const int MiPbtFlagPageModeShift = 0x14;
        public const int MiPbtFlagAccessTypeMask = 0x00E00000;
        public const int MiPbtFlagAccessTypeShift = 0x15;
        public const int MiPbtFlagPoolIndexMask = 0x08000000;
        public const int MiPbtFlagPoolIndexShift = 0x1B;

        // Segment Type
        public const int MiPbtL4Segment = 0x0;
        public const int MiPbtAmssSegment = 0x1;
        public const int MiPbtHashSegment = 0x2;
        public const int MiPbtBootSegment = 0x3;
        public const int MiPbtL4BspSegment = 0x4;
        public const int MiPbtSwappedSegment = 0x5;
        public const int MiPbtXblSecSegment = 0x5;
        public const int MiPbtSwapPoolSegment = 0x6;
        public const int MiPbtPhdrSegment = 0x7;

        // Page/Non-Page Type
        public const int MiPbtNonPagedSegment = 0x0;
        public const int MiPbtPagedSegment = 0x1;

        // Access Type
        public const int MiPbtRwSegment = 0x0;
        public const int MiPbtRoSegment = 0x1;
        public const int MiPbtZiSegment = 0x2;
        public const int MiPbtNotusedSegment = 0x3;
        public const int MiPbtSharedSegment = 0x4;
        public const int MiPbtRweSegment = 0x7;

        // ELF Segment Flag Definitions (pre‑composed values)
        public const int MiPbtElfAmssNonPagedRoSegment = 0x01200000;
        public const int MiPbtElfAmssPagedRoSegment = 0x01300000;
        public const int MiPbtElfSwapPoolNonPagedZiSegmentIndex0 = 0x06400000;
        public const int MiPbtElfSwappedPagedRoSegmentIndex0 = 0x05300000;
        public const int MiPbtElfSwapPoolNonPagedZiSegmentIndex1 = 0x0E400000;
        public const int MiPbtElfSwappedPagedRoSegmentIndex1 = 0x0D300000;
        public const int MiPbtElfAmssNonPagedZiSegment = 0x01400000;
        public const int MiPbtElfAmssPagedZiSegment = 0x01500000;
        public const int MiPbtElfAmssNonPagedRwSegment = 0x01000000;
        public const int MiPbtElfAmssPagedRwSegment = 0x01100000;
        public const int MiPbtElfAmssNonPagedNotusedSegment = 0x01600000;
        public const int MiPbtElfAmssPagedNotusedSegment = 0x01700000;
        public const int MiPbtElfAmssNonPagedSharedSegment = 0x01800000;
        public const int MiPbtElfAmssPagedSharedSegment = 0x01900000;
        public const int MiPbtElfHashSegment = 0x02200000;
        public const int MiPbtElfBootSegment = 0x03200000;
        public const int MiPbtElfPhdrSegment = 0x07000000;
        public const int MiPbtElfNonPagedL4BspSegment = 0x04000000;
        public const int MiPbtElfPagedL4BspSegment = 0x04100000;
        public const int MiPbtElfAmssRelocatableImage = 0x8000000; // 注意：原值 0x8000000，即 0x08000000

        // New definitions for EOS demap paging requirement
        // Bit 20 (0b) Bit 24-26(000): Non Paged = 0x0000_0000
        // Bit 20 (1b) Bit 24-26(000): Locked Paged = 0x0010_0000
        // Bit 20 (1b) Bit 24-26(001): Unlocked Paged = 0x0110_0000
        // Bit 20 (0b) Bit 24-26(011): non secure = 0x0310_0000
        public const int MiPbtElfResidentSegment = 0x00000000;
        public const int MiPbtElfPagedLockedSegment = 0x00100000;
        public const int MiPbtElfPagedUnlockedSegment = 0x01100000;
        public const int MiPbtElfUnsecureSegment = 0x03100000;
    }
}