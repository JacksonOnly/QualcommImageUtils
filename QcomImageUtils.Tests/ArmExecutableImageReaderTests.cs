using System.Buffers.Binary;
using QcomImageUtils.Utilities;

namespace QcomImageUtils.Tests;

public sealed class ArmExecutableImageReaderTests
{
    [Fact]
    public void TryReadSblMbn_UintMaxBootConfiguration_CreatesArm32Image()
    {
        const int sourceOffset = ArmExecutableImageReader.SblHeaderSize;
        const int codeSize = sizeof(uint);
        var image = new byte[sourceOffset + codeSize];
        WriteUInt32(image, 0, ArmExecutableImageReader.SblCodeword);
        WriteUInt32(image, 4, ArmExecutableImageReader.SblMagic);
        WriteUInt32(image, 20, sourceOffset);
        WriteUInt32(image, 24, 0x1000);
        WriteUInt32(image, 28, codeSize);
        WriteUInt32(image, 32, codeSize);
        WriteUInt32(image, 60, uint.MaxValue);

        bool success = ArmExecutableImageReader.TryReadSblMbn(
            image,
            out ArmExecutableImage executableImage);

        Assert.True(success);
        Assert.Equal(sizeof(uint), executableImage.PointerSize);
        Assert.Equal(ArmExecutableImageReader.ArmMachine, executableImage.Machine);
        ArmExecutableSegment segment = Assert.Single(executableImage.Segments);
        Assert.Equal((ulong)sourceOffset, segment.FileOffset);
        Assert.Equal(0x1000UL, segment.VirtualAddress);
        Assert.Equal((ulong)codeSize, segment.FileSize);
    }

    private static void WriteUInt32(Span<byte> image, int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(image.Slice(offset, sizeof(uint)), value);
    }
}
