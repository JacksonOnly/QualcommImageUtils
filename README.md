# QcomImageUtils

[![CI and Publish Native AOT](https://github.com/JacksonOnly/QualcommImageUtils/actions/workflows/publish-aot.yml/badge.svg)](https://github.com/JacksonOnly/QualcommImageUtils/actions/workflows/publish-aot.yml)
[![NuGet version (QcomImageUtils)](https://img.shields.io/nuget/v/QcomImageUtils.svg?style=flat-square)](https://www.nuget.org/packages/QcomImageUtils/)

QcomImageUtils 是面向 Qualcomm ELF/MBN 固件镜像的高性能只读解析、Firehose 命令分析与密码学验证工具。它可以识别镜像封装与 MBN 版本，提取镜像、平台、OEM、构建元数据和 QTI/OEM 证书信息，静态分析 Firehose 支持命令，并验证 ELF 哈希表、镜像签名、证书路径、metadata Root 哈希及可选的外部可信 Root。

仓库包含两个可直接使用的项目：

- `QcomImageUtils`：目标框架为 `netstandard2.0` 和 `net10.0` 的类库。
- `QcomImageUtils.App`：目标框架为 `net10.0` 的命令行工具，支持 Native AOT 发布。

## 核心能力

- 解析小端 ELF32、ELF64、常规 MBN、SBL MBN 以及 MBN v3、v5、v6、v7 哈希段。
- 枚举多 ELF/melf 容器中的程序映像，分析 Firehose 命令表及 `handle_xml` 中的内联命令。
- 提取镜像 ID/类型、SBL 架构、软件/硬件 ID、SoC、OEM、产品型号、防回滚版本和构建字符串。
- 解析 QTI/OEM DER 证书包，输出主题、颁发者、序列号、SHA-256 和可选 PEM。
- 重算普通及分页 ELF 段摘要，验证 SHA-1、SHA-256 或 SHA-384 哈希表。
- 验证 Qualcomm legacy HMAC/raw RSA、RSA-PSS、RSA PKCS#1 v1.5 和 DER 编码 ECDSA 镜像签名。
- 验证证书签名、自签 Root、v7 metadata Root CA 哈希，以及调用方提供的 SHA-256/SHA-384 可信 Root 哈希。
- 枚举多 ELF 容器中的可识别 Qualcomm 组件；任一组件无效时，整个容器不会被标记为通过。
- 对镜像大小、证书包大小、证书数量、ELF 组件数量、声明偏移和长度执行边界检查。
- 提供文件与 `ReadOnlySpan<byte>` API；CLI 支持多文件、目录递归、文本和 JSON 输出。

## 快速开始

需要 .NET 10 SDK。恢复并构建解决方案：

```powershell
dotnet restore QualcommImageUtils.slnx
dotnet build QualcommImageUtils.slnx -c Release
```

解析单个镜像：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "xbl.elf"
```

正常解析 Firehose programmer 时会同时输出其支持命令，不需要额外的分析选项。
构建时间从 ARM/Thumb 日志调用点的格式、日期和时间参数恢复；ARM 镜像不会再把未被代码引用的相邻字符串当作构建时间。

递归验证目录中的镜像：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "firmware" --verify
```

输出 JSON，并要求镜像匹配指定的外部可信 Root：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "firmware" --verify --json --trusted-root "<Root DER 证书的 SHA-256 或 SHA-384>"
```

目录输入会递归枚举子目录，跳过重解析点及 `.json`、`.txt`、`.log`、`.xml` 文件。

## 库 API

从源码引用类库项目：

```xml
<ItemGroup>
  <ProjectReference Include="../QcomImageUtils/QcomImageUtils.csproj" />
</ItemGroup>
```

### 解析镜像

> 对于SM8850之后的镜像解析，一些结果可能不在prog_*的引导中，可能会在xbl_sc.efl中出现，例如ImageVariant等字段

`QcomImageParser` 实现 `IQcomImageParser`，提供文件和内存重载：

```csharp
using QcomImageUtils;
using QcomImageUtils.Models;

var parser = new QcomImageParser(new QcomImageParserOptions
{
    CalculateFileSha256 = true,
    ExportCertificatePem = false
});

if (!parser.TryParse("xbl.elf", out QcomImageParseResult result))
{
    Console.Error.WriteLine(result.ErrorMessage);
    return;
}

Console.WriteLine($"{result.ImageFormat} / MBN v{result.HeaderVersion}");
Console.WriteLine($"SoC: {result.SocType}, OEM: {result.OemType}");
Console.WriteLine($"Boot memory: {result.BootMemoryType}, DRAM: {result.DramGeneration}");

foreach (ImageCertItem certificate in result.CertChains)
    Console.WriteLine($"{certificate.ChainType}[{certificate.Index}]: {certificate.Subject}");
```

`TryParse` 返回 `true` 只表示结构解析成功，不表示镜像签名有效或能够在目标设备上启动。

`BootMemoryType` 根据 ELF 中 `PT_LOAD`、`FileSize=0`、`MemSize>0` 且 flags 恰好为 `PF_R | PF_W` 的段推断：`16 KiB < MemSize < 1 MiB` 为 `Lite`，`MemSize > 1 MiB` 为 `Ddr`。`DramGeneration` 根据镜像中的 `DRAM Vref DQ CDC perbit` 与 `DRAM_LP5` 前缀组合输出 `Ddr4`、`Ddr5`、`Combo` 或 `Unknown`。这些字段属于启发式识别结果。

### 验证镜像

`QcomImageVerifier` 实现 `IQcomImageVerifier`。验证结果必须通过 `IsVerified` 判定：

```csharp
var verifier = new QcomImageVerifier(new QcomImageVerifierOptions
{
    TrustedRootCertificateHashes =
    [
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    ]
});

if (!verifier.TryVerify(
        "prog_firehose_ddr.elf",
        out QcomImageVerificationResult verification))
{
    Console.Error.WriteLine(verification.ErrorMessage);
    return;
}

Console.WriteLine($"验证通过: {verification.IsVerified}");
foreach (QcomImageComponentVerificationResult component in verification.Components)
    Console.WriteLine($"0x{component.ImageOffset:X}: {component.IsVerified}");
```

不需要外部信任判定时，可以省略 `TrustedRootCertificateHashes`。此时仍会检查镜像完整性、签名、证书路径和 metadata Root 哈希。

### 内存输入

已有镜像数据时，可以使用内存重载，避免文件 API 的完整文件缓冲区分配：

```csharp
ReadOnlySpan<byte> image = imageBytes;

bool parsed = parser.TryParse(image, out QcomImageParseResult parseResult);
bool completed = verifier.TryVerify(image, out QcomImageVerificationResult verifyResult);
```

内存 API 不会复制最外层镜像缓冲区，但证书对象、结果字符串和可选 PEM 等仍会产生必要分配。

### 分析 Firehose 命令

`QcomImageParser` 会在正常解析流程中自动分析 Firehose 命令，并将结果放入 `QcomImageParseResult.SupportedCommands`。没有识别到可信命令分发结构时该集合为空，不会改变镜像结构解析的成功状态：

```csharp
var parser = new QcomImageParser();
if (!parser.TryParse("prog_firehose_ddr.elf", out QcomImageParseResult result))
{
    Console.Error.WriteLine(result.ErrorMessage);
    return;
}

foreach (FirehoseCommandInfo command in result.SupportedCommands)
{
    Console.WriteLine($"{command.Name}: {command.Source}");
    if (command.HandlerAddress.HasValue)
        Console.WriteLine($"  handler = 0x{command.HandlerAddress.Value:X}");
}
```

分析器不依赖 ELF 节表。它枚举文件中的有效小端 ELF32/ELF64，按各自的 `PT_LOAD` 建立虚拟地址映射；也支持带 80 B 头的 Qualcomm SBL MBN，并根据头部启动配置选择 ARM32 或 AArch64 映射。命令表既可以是连续 `{namePointer, handler}` 指针对，也可以是 `char name[32] + handler` 固定槽。对于运行时解密 handler 表的镜像，还可在 `Calling handler` 调度锚点前恢复连续的明文命令池，但不会伪造无法静态确定的 handler 地址。

固定命令表优先从 `Supported Functions` 日志调用附近的 ARM 数据流恢复声明数量、表基址和遍历步长。每个日志引用使用独立的有界证据窗口，步长必须关联到同一表基址；同等级证据冲突时会放弃声明数量并回退到连续表结构扫描。

`CommandTable` 来源包含表项和处理地址；`InlineDispatch` 表示命令来自直接比较分发或受调度锚定的明文命令池，因此不一定存在独立表项或可恢复的 handler 地址。对于 AArch64 和 ARM32 programmer，分析器会跟踪 XML tag getter 的返回值到字符串比较参数。A32/Thumb 无表布局还会解析地址构造、寄存器复制、比较调用、条件分支和处理调用；只有共享同一比较器并包含多个 Firehose 核心命令的连续比较链才会被接受。诊断文本只作为已有分发证据的保守补充。例如小米认证流程中的 `sig` 可在没有固定诊断文案时识别，同时不会把 `TargetName` 属性值 `req`，或 `storage_type`、`reset`、`off` 等属性/值当作 XML tag。结果属于静态分析结论，不保证命令在当前认证状态、存储介质或目标设备上一定可用。

CLI 的普通文本输出会在镜像信息后列出支持命令；使用 `--json` 时，同一 `QcomImageParseResult` 对象通过 `SupportedCommands` 字段输出命令名称、来源、内嵌 ELF 偏移（SBL MBN 为 0）及可用的表项/处理地址。

## 验证结果语义

`TryVerify` 的返回值表示验证流程能否完成，而不是镜像是否通过验证：

- 返回 `false`：镜像无法读取、无法识别、超过镜像大小上限，或其他问题使验证无法得出结论；此时 `VerificationCompleted=false`。
- 返回 `true`：验证流程已经得出结论；即使哈希、签名、证书路径或可信 Root 无效，也仍可能返回 `true`。
- 是否最终通过必须检查 `QcomImageVerificationResult.IsVerified`。

主要结果字段如下：

| 字段 | 含义 |
| --- | --- |
| `VerificationCompleted` | 是否完成了可判定的验证流程 |
| `IsIntegrityValid` | ELF 的哈希表是否有效；SBL 中表示连续头/代码前缀签名是否有效 |
| `IsAuthentic` | 完整性、镜像签名、证书路径和 metadata Root 条件是否全部通过 |
| `IsTrusted` | 是否匹配外部可信 Root；未配置可信 Root 时为 `null` |
| `IsVerified` | 最终结论：`IsAuthentic` 为 `true`，且已配置的外部信任条件通过 |

`IsAuthentic` 要求：

```text
IsIntegrityValid
&& SignatureStatus == Valid
&& CertificateChainStatus == Valid
&& MetadataRootHashStatus ∈ { Valid, NotPresent }
```

未配置外部 Root 时，`TrustedRootStatus=NotChecked`、`IsTrusted=null`，内部真实性通过的镜像仍可得到 `IsVerified=true`。配置外部 Root 后，`TrustedRootStatus` 必须为 `Valid`。

对于没有关联 ELF 的独立 MBN 哈希段，验证器无法重算外层载荷摘要，因此 `HashTableStatus=NotChecked`、`IsIntegrityValid=false`。即使其签名和证书路径有效，也不会得到 `IsVerified=true`。

各验证状态使用 `QcomVerificationStatus` 表示：

| 状态 | 含义 |
| --- | --- |
| `NotChecked` | 当前输入或配置下未执行该项检查 |
| `NotPresent` | 镜像中不存在对应数据；是否可接受取决于具体检查项 |
| `Valid` | 检查已执行且通过 |
| `Invalid` | 检查已执行且失败 |
| `Unsupported` | 镜像声明了当前实现不支持的算法或形式 |

多 ELF 镜像的顶层结果聚合 `Components` 中的所有 Qualcomm 组件。普通内嵌 ELF 若已属于前一组件认证过的载荷，不会被重复视为独立 Qualcomm 组件。

## 支持范围

### 输入格式

| 输入格式 | 支持情况 | 说明 |
| --- | --- | --- |
| ELF32 | 支持 | 小端 ELF；校验程序头表、定位 Qualcomm MI_PBT 哈希段并重算段摘要 |
| ELF64 | 支持 | 小端 ELF；支持 64 位段偏移与长度 |
| 带前缀或多 ELF 容器 | 支持 | Parser 返回首个可解析候选；Verifier 枚举可识别的 Qualcomm 组件并聚合结果 |
| 常规 MBN | 支持 | v3/v5/v7 基础头为 40 B；v6 扩展头为 48 B |
| SBL MBN | 支持 | 80 B 头；验证连续头/代码前缀签名，Root 选择字段使用 1 基编号 |

Verifier 会记录后续损坏或缺少 Qualcomm 哈希段的 ELF 候选并使容器验证失败，但会忽略已由前一有效组件认证载荷中的普通内嵌 ELF 魔数。

### MBN 版本

| MBN 版本 | 头与摘要 | 主要能力 |
| --- | --- | --- |
| v3 | 40 B；SHA-1 或 SHA-256 | 镜像 ID、OEM 签名和证书；Qualcomm legacy HMAC/raw RSA |
| v5 | 40 B；SHA-256 | QTI/OEM 双签；legacy HMAC、RSA-PSS 和 RSA PKCS#1 v1.5 |
| v6 | 48 B；SHA-384 | 双签、可变 QTI/OEM metadata、MRC、SoC/OEM/型号/防回滚字段 |
| v7 | 40 B 加公共/QTI/OEM metadata；SHA-384 | 双签、ECDSA/RSA、MRC 和 OEM Root CA 哈希 |

v6/v7 的 MRC Root 槽位使用 0 基编号。支持范围表示结构解析和密码学验证能力，不表示镜像与特定设备的硬件、fuse、Boot ROM 或 Secure Boot 策略兼容。

## 配置选项

Parser 与 Verifier 使用独立选项类型，特别是 `ExportCertificatePem` 的默认值不同。

### QcomImageParserOptions

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `CalculateFileSha256` | `false` | 计算完整输入的 SHA-256 |
| `ExportCertificatePem` | `true` | 在结果中生成证书 PEM 文本 |
| `AnalyzeFirehoseCommands` | `true` | 对识别为 programmer 的镜像执行 Firehose 命令静态分析 |
| `MaximumImageSize` | `512 MiB` | 文件与内存输入的字节上限，最小为 1 B |
| `MaximumCertificateChainSize` | `1 MiB` | 单个 QTI/OEM 证书包的字节上限，范围为 1 B-64 MiB |
| `MaximumCertificateCount` | `32` | 单个 QTI/OEM 证书包的证书数量上限，范围为 1-64 |
| `MaximumMetadataStringLength` | `512` | 单个启发式元数据字符串的 UTF-8 字节上限，范围为 32-4096 |

### QcomImageVerifierOptions

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `CalculateFileSha256` | `false` | 计算完整输入的 SHA-256 |
| `ExportCertificatePem` | `false` | 在嵌套解析结果中生成证书 PEM 文本 |
| `AnalyzeFirehoseCommands` | `false` | 在嵌套解析结果中执行 Firehose 命令静态分析；CLI 验证模式会启用 |
| `MaximumImageSize` | `512 MiB` | 文件与内存输入的字节上限，最小为 1 B |
| `MaximumCertificateChainSize` | `1 MiB` | 单个 QTI/OEM 证书包的字节上限，范围为 1 B-64 MiB |
| `MaximumCertificateCount` | `32` | 单个 QTI/OEM 证书包的证书数量上限，范围为 1-64 |
| `MaximumElfComponentCount` | `64` | 单个输入中的 ELF 组件结果数量上限，范围为 1-4096 |
| `TrustedRootCertificateHashes` | 空集合 | 允许的 Root DER 证书 SHA-256/SHA-384 哈希 |

Verifier 不公开 `MaximumMetadataStringLength`；其内部解析使用 Parser 的默认上限 `512` 字节。

可信 Root 哈希匹配的是有效证书路径终端 Root 的 DER 编码证书，不是 PEM 文本或 SubjectPublicKeyInfo。输入不区分大小写，允许 `0x` 前缀、冒号、连字符和空白。无效选项会在构造 Parser/Verifier 时抛出 `ArgumentOutOfRangeException`、`ArgumentNullException` 或 `ArgumentException`。

## CLI 参考

```text
QcomImageUtils <镜像或目录路径> [更多路径] [--verify] [--trusted-root <hex>] [--json] [--hash] [--pem]
```

| 参数 | 说明 |
| --- | --- |
| `<镜像或目录路径> [更多路径]` | 一个或多个文件/目录；目录会递归枚举 |
| `--verify` | 验证哈希表、镜像签名、证书路径、metadata Root 哈希和可选可信 Root |
| `--trusted-root <hex>` | 添加 SHA-256/SHA-384 可信 Root 哈希，可重复；同时启用验证模式 |
| `--json` | JSON 输出；一个结果为对象，多个结果为数组 |
| `--hash` | 计算并输出每个完整文件的 SHA-256 |
| `--pem` | 生成证书 PEM；CLI 默认关闭 |
| `--no-pem` | 显式关闭证书 PEM |
| `-h`, `--help` | 显示用法 |

退出码：

| 退出码 | 含义 |
| --- | --- |
| `0` | 解析模式下全部成功；验证模式下全部输入均完成验证且 `IsVerified=true` |
| `1` | 至少一个输入解析失败、验证无法完成或 `IsVerified=false` |
| `2` | 参数错误、目录枚举失败、可信 Root 参数无效或没有可处理文件 |

## 性能与资源限制

- 内存 API 直接在调用方提供的 `ReadOnlySpan<byte>` 上解析，热路径使用显式小端读取和切片，不复制最外层镜像。
- 文件 API 使用启用 `SequentialScan` 的 `FileStream` 和 128 KiB 流缓冲区，但仍会一次分配并载入完整文件；峰值内存至少接近文件大小。
- 多 ELF 验证复用同一输入缓冲区，通过 Span 切片处理组件，不为每个组件复制完整镜像。
- Firehose 命令分析按 Span 扫描所有有效 ELF 和 file-backed `PT_LOAD`，不调用外部反汇编器，也不依赖节名或调试符号。
- 双签验证需要将对侧签名区域视为零时，会按遮罩区间增量哈希并注入零字节，不复制完整签名前缀。
- 证书包验证缓存证书签名关系，并只让有效路径终端 Root 参与 metadata 和外部信任匹配。
- 完整文件 SHA-256 默认关闭；Verifier 和 CLI 的 PEM 导出默认关闭，可减少额外计算与分配。
- 镜像、证书包、证书数量和 ELF 组件数量均有可配置硬上限，声明偏移和长度在切片前进行范围验证。
- CLI 使用源生成 JSON 元数据并支持 Native AOT，避免运行时 JSON 反射开销。

## 安全边界

- 本项目不实现 Qualcomm 私有 QCSIGN，也不生成生产签名、测试签名、私钥或证书链。
- 本项目不包含设备 fuse、OEM 生产信任库或 Qualcomm 私有密钥。未配置外部可信 Root 时，只能证明镜像内部密码学关系自洽，不能证明目标设备会信任该 Root。
- 证书路径验证是面向镜像格式的专用实现，并非操作系统的完整 X.509 策略。它检查证书签名、自签 Root，以及中间 CA 的 Basic Constraints、存在时的 KeyCertSign 和 pathLen；不检查有效期、吊销、系统信任库或设备 fuse，也不要求 Root 包含 CA/KeyCertSign 扩展或叶证书包含 DigitalSignature Key Usage。
- 构建字符串、版本和变体等启发式字段只用于识别，不属于 `IsAuthentic` 的认证结论。安全决策应使用哈希、签名、证书路径和受签名 metadata 的验证状态。
- 本项目不实现 PIL（Peripheral Image Loader）的加载、重定位、解密、设备认证或执行流程。
- 对签名后被加密、混淆或修改且镜像内不含可识别解密参数的载荷，验证器会报告段摘要不一致，不会根据高熵特征改判为通过。
- 解析成功或密码学验证通过都不能单独作为刷写安全、Secure Boot 兼容或设备可启动的结论。
- Firehose 命令分析是受结构和上下文约束的启发式结果，不能替代协议交互、认证状态或设备端行为验证。

## 开发、测试与发布

每次向仓库执行 `push` 时，[`publish-aot.yml`](.github/workflows/publish-aot.yml) 会先执行 Release 构建、全量测试和格式检查。CI 通过后，工作流会并行发布 `win-arm64`、`win-x64` 和 `win-x86` Native AOT，并且只为 `QcomImageUtils` 类库生成 NuGet 包；App 和 Tests 不参与 NuGet 打包。所有构建产物都会上传到该次 GitHub Actions 运行的 Artifacts，保留 14 天。

`master` 分支构建成功后，工作流还会自动创建日期与提交哈希组成的 Tag 和 GitHub 预发布版本，将三个 AOT EXE、`.nupkg` 与 `.snupkg` 附加到 Release，并通过 NuGet.org Trusted Publishing（OIDC）将 `QcomImageUtils` 包推送到 NuGet.org，不需要保存长期 API Key。也可以在 Actions 页面通过 `workflow_dispatch` 手动运行；只有从 `master` 分支运行时才会发布。

产物文件名同时包含 UTC 提交日期和 7 位提交哈希，例如：

```text
QcomImageUtils.App_win-x64_aot_2026.8.8-g1a2b3c4.exe
```

运行测试：

```powershell
dotnet test QualcommImageUtils.slnx -c Release
```

发布 Windows x64 Native AOT CLI：

```powershell
dotnet publish QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -r win-x64 --self-contained true
```

发布其他平台时应使用对应 RID。Native AOT 通常需要在目标操作系统上安装相应的原生编译工具链。

## 参考与许可证说明

实现过程中对照了以下项目公开的格式定义和实现行为：

- [`msm8916-mainline/qtestsign@0eef3b5`](https://github.com/msm8916-mainline/qtestsign/tree/0eef3b552b1ada848f22bad38ab2e40407307c5b)：[`mbn/elf.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/elf.py)、[`mbn/hashseg.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/hashseg.py)、[`mbn/cert.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/cert.py)，上游许可证为 [GPL-2.0](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/COPYING)。
- [`coreboot/coreboot@fbdef3a`](https://github.com/coreboot/coreboot/tree/fbdef3aea5b7090b75e91dad2e82fb12819a80d9)：[`util/qualcomm/mbn_tools.py`](https://github.com/coreboot/coreboot/blob/fbdef3aea5b7090b75e91dad2e82fb12819a80d9/util/qualcomm/mbn_tools.py)，该文件标注为 BSD-3-Clause；coreboot 仓库其他文件可能采用不同许可证。
- 尚未公开的本地项目 `GeekFlashCore.QcomImage` 和 `GeekFlashCore.QcomImage.Abstractions` 用于 API 与字段语义比对，因此不提供远程链接。

本仓库依据公开格式信息独立实现，不分发上述项目的源文件，也不包含 qtestsign 的测试私钥、测试证书或由其派生的签名、证书、哈希测试向量。引用、修改或再分发上游代码时，仍须分别遵守其许可证。
