using System.Runtime.InteropServices;
using QcomImageUtils.Models;

namespace QcomImageUtils.Tests;

public sealed class StructureLayoutTests
{
    [Fact]
    public void PublicBinaryStructures_HaveExpectedPackedSizes()
    {
        Assert.Equal(80, Marshal.SizeOf<MbnHeader>());
        Assert.Equal(40, Marshal.SizeOf<HashSegmentV3>());
        Assert.Equal(40, Marshal.SizeOf<HashSegmentV5>());
        Assert.Equal(168, Marshal.SizeOf<HashSegmentV6>());
        Assert.Equal(288, Marshal.SizeOf<HashSegmentV7>());
    }
}
