using QcomImageUtils.Types;

namespace QcomImageUtils.Tests;

public sealed class QcomImageTypeTests
{
    [Fact]
    public void ImageTypes_MatchLatestQualcommIdentifiers()
    {
        Assert.Equal(23, (int)QcomImageType.RpmImg);
        Assert.Equal(QcomImageType.RpmImg, QcomImageType.AopImg);
        Assert.Equal(32, (int)QcomImageType.QseeImg);
        Assert.False(Enum.IsDefined(typeof(QcomImageType), 35));
        Assert.Equal(57, (int)QcomImageType.CpucpDtbImg);
    }
}
