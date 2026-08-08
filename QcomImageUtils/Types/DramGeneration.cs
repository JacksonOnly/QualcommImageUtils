namespace QcomImageUtils.Types;

/// <summary>
/// 表示从引导镜像特征字符串推断出的 DRAM 代际。
/// </summary>
public enum DramGeneration
{
    Unknown,
    Ddr4,
    Ddr5,
    Combo
}
