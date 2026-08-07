using QcomImageUtils.Types;

namespace QcomImageUtils.Models;

/// <summary>
/// 表示从 Firehose ELF 中发现的一项输入命令。
/// </summary>
public sealed class FirehoseCommandInfo
{
    public string Name { get; internal set; } = string.Empty;
    public FirehoseCommandSource Source { get; internal set; }
    public int ElfImageOffset { get; internal set; }
    public ulong? TableEntryAddress { get; internal set; }
    public ulong? HandlerAddress { get; internal set; }
}
