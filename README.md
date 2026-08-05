# QcomImageUtils

面向 Qualcomm ELF/MBN 固件镜像的高性能只读解析与密码学验证库。项目可识别镜像封装与 MBN 版本，提取镜像、平台、OEM、构建元数据及 QTI/OEM 证书信息，重算 ELF 哈希表，并验证镜像签名、证书路径、metadata Root 哈希和可选外部可信 Root。CLI 支持文件或目录递归输入，以及文本或 JSON 输出。

库目标框架为 `netstandard2.0` 与 `net10.0`；CLI 目标框架为 `net10.0`，支持 Native AOT 发布。

## 功能

- 解析小端 ELF32、ELF64 中的 Qualcomm MI_PBT 哈希段，也可识别前方带包装数据的嵌入式 ELF。
- 解析常规 MBN、SBL MBN，以及 MBN v3、v5、v6、v7 哈希段。
- 提取镜像 ID/类型、SBL 架构、软件/硬件 ID、SoC、OEM、产品型号、防回滚版本和构建字符串。
- 解析 QTI/OEM DER 证书链，输出主题、颁发者、序列号、SHA-256 和可选 PEM。
- 重算普通及分页 ELF 段摘要，验证 SHA-1、SHA-256 或 SHA-384 哈希表。
- 验证 Qualcomm legacy HMAC/raw RSA、RSA-PSS、RSA PKCS#1 和 ECDSA 镜像签名。
- 将证书数据按叶证书、中间证书和多 Root 槽位包解析；支持 v6/v7 MRC Root 选择和无 MRC 的签名路径发现。
- 验证证书签名、自签 Root、v7 metadata Root CA 哈希，以及调用方提供的 SHA-256/SHA-384 可信 Root 哈希。
- 枚举并验证多 ELF 容器中的全部 Qualcomm 组件；任一组件失败时容器不会被标记为通过。
- 对畸形长度、越界段、异常证书数量和超长元数据进行边界检查；解析失败通过 `TryParse` 结果返回。

## 支持矩阵

| 输入格式 | 支持状态 | 说明 |
| --- | --- | --- |
| ELF32 | 支持 | 小端 ELF；校验程序头表、定位 Qualcomm 哈希段并重算段摘要 |
| ELF64 | 支持 | 小端 ELF；支持 64 位段偏移与长度 |
| 多 ELF | 支持 | 扫描并验证全部结构有效且带 Qualcomm 哈希段的组件 |
| 常规 MBN | 支持 | v3/v5/v7 基础头为 40 B；v6 扩展头为 48 B |
| SBL MBN | 支持 | 80 B 头；验证连续头/代码前缀签名，支持 1 基 Root 选择字段 |

| MBN 版本 | 头与摘要 | 可提取内容 |
| --- | --- | --- |
| v3 | 40 B、SHA-1/SHA-256 | 镜像 ID、OEM 签名/证书；支持 Qualcomm legacy HMAC/raw RSA |
| v5 | 40 B、SHA-256 | QTI/OEM 双签；支持 legacy HMAC、RSA-PSS 和 RSA PKCS#1 |
| v6 | 48 B、SHA-384 | 双签、可变 QTI/OEM 元数据、MRC、SoC/OEM/型号/防回滚字段 |
| v7 | 40 B 加公共/QTI/OEM 元数据、SHA-384 | 双签、ECDSA/RSA、MRC、生命周期字段及 OEM Root CA 哈希 |

解析器仅支持小端 ELF。文件与内存 API 默认最大处理 512 MiB，可通过选项调整。支持矩阵表示结构解析能力，不表示镜像能够在特定设备上启动。

## 安全边界

- 不实现 Qualcomm 私有 QCSIGN，也不生成生产签名、测试签名或证书链。
- 不包含设备 fuse、OEM 生产信任库或 Qualcomm 私有密钥。未提供 `TrustedRootCertificateHashes` 时，验证结果只能证明镜像内部哈希、签名和证书路径自洽，不能证明目标设备会信任该 Root。
- `IsAuthentic` 表示内部内容、签名、证书路径及 metadata Root 哈希自洽；`IsTrusted` 表示是否匹配调用方提供的外部可信 Root；`IsVerified` 同时要求真实性与已配置的信任条件通过。没有配置外部 Root 时，`TrustedRootStatus` 为 `NotChecked`。
- 构建字符串、版本和变体等启发式扫描字段仅用于识别，不属于 `IsAuthentic` 的认证结论；安全决策应使用哈希、签名、证书路径及受签名 metadata 的验证状态。
- 不实现 PIL（Peripheral Image Loader）的加载、重定位、解密、认证或执行流程。
- 对签名后被加密、混淆或修改且镜像内不含可识别解密参数的载荷，库会严格报告段摘要不一致，不根据高熵特征将其改判为通过。
- 解析或内部验证成功不能单独作为刷写安全、Secure Boot 兼容或设备可启动的结论。

## 构建

需要 .NET 10 SDK：

```powershell
dotnet restore QualcommImageUtils.slnx
dotnet build QualcommImageUtils.slnx -c Release
```

发布 Windows x64 Native AOT CLI：

```powershell
dotnet publish QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -r win-x64 --self-contained true
```

可按目标平台将 `win-x64` 替换为相应 RID。

## 库 API

从源码引用库项目：

```xml
<ItemGroup>
  <ProjectReference Include="../QcomImageUtils/QcomImageUtils.csproj" />
</ItemGroup>
```

解析文件：

```csharp
using QcomImageUtils;
using QcomImageUtils.Models;

var parser = new QcomImageParser(new QcomImageParserOptions
{
    CalculateFileSha256 = true,
    ExportCertificatePem = false,
    MaximumImageSize = 512 * 1024 * 1024,
    MaximumCertificateChainSize = 1024 * 1024,
    MaximumCertificateCount = 32,
    MaximumMetadataStringLength = 512
});

if (!parser.TryParse("xbl.elf", out QcomImageParseResult result))
{
    Console.Error.WriteLine(result.ErrorMessage);
    return;
}

Console.WriteLine($"{result.ImageFormat} / MBN v{result.HeaderVersion}");
Console.WriteLine($"SoC: {result.SocType}, OEM: {result.OemType}");

foreach (ImageCertItem certificate in result.CertChains)
    Console.WriteLine($"{certificate.ChainType}[{certificate.Index}]: {certificate.Subject}");
```

已有内存数据时，可避免文件 API 的读取与缓冲区分配：

```csharp
ReadOnlySpan<byte> image = imageBytes;
bool success = parser.TryParse(image, out QcomImageParseResult result);
```

验证镜像及其全部内嵌 ELF 组件：

```csharp
var verifier = new QcomImageVerifier(new QcomImageVerifierOptions
{
    TrustedRootCertificateHashes =
    [
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    ],
    ExportCertificatePem = false,
    MaximumElfComponentCount = 64
});

if (!verifier.TryVerify("prog_firehose_ddr.elf", out QcomImageVerificationResult verification))
{
    Console.Error.WriteLine(verification.ErrorMessage);
    return;
}

Console.WriteLine($"完整验证: {verification.IsVerified}");
foreach (QcomImageComponentVerificationResult component in verification.Components)
    Console.WriteLine($"0x{component.ImageOffset:X}: {component.IsVerified}");
```

不需要设备信任判定时可省略 `TrustedRootCertificateHashes`。此时仍会完成哈希、签名、证书路径和 metadata Root 哈希验证。

`QcomImageParser` 实现 `IQcomImageParser`。主要选项如下：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `CalculateFileSha256` | `false` | 计算完整输入的 SHA-256 |
| `ExportCertificatePem` | `true` | 在结果中生成证书 PEM 文本 |
| `MaximumImageSize` | `536870912` | 文件与内存输入的字节上限 |
| `MaximumCertificateChainSize` | `1048576` | 单条 QTI/OEM 证书链的字节上限，允许范围为 1-67108864 |
| `MaximumCertificateCount` | `32` | 每条 QTI/OEM 证书包的证书数量上限，允许范围为 1–64 |
| `MaximumMetadataStringLength` | `512` | 单个元数据字符串上限，允许范围为 32–4096 |

无效选项在构造解析器时抛出 `ArgumentOutOfRangeException`；格式错误、I/O 错误和不支持的镜像由 `TryParse` 返回 `false`，详情位于 `QcomImageParseResult.ErrorMessage`。
`QcomImageVerifierOptions` 复用镜像、证书、哈希和 PEM 选项，并额外提供默认值为 `64` 的 `MaximumElfComponentCount`；允许范围为 1–4096。

## CLI

解析单个镜像：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "xbl.elf"
```

递归验证目录并输出 JSON：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "firmware" --verify --json
```

使用外部可信 Root，并计算完整文件 SHA-256：

```powershell
dotnet run --project QcomImageUtils.App/QcomImageUtils.App.csproj -c Release -- "xbl.elf" --verify --trusted-root "<SHA-256 或 SHA-384 十六进制>" --hash
```

| 参数 | 说明 |
| --- | --- |
| `<镜像或目录路径> [更多路径]` | 一个或多个文件/目录；目录递归枚举并跳过 `.json/.txt/.log/.xml` |
| `--verify` | 验证哈希表、镜像签名、证书路径、metadata Root 哈希及可选可信 Root |
| `--trusted-root <hex>` | 添加 SHA-256/SHA-384 可信 Root 哈希，可重复；同时启用验证 |
| `--json` | JSON 输出；单文件为对象，多文件为数组 |
| `--hash` | 计算并输出每个完整文件的 SHA-256 |
| `--pem` | 生成证书 PEM；CLI 默认关闭 |
| `--no-pem` | 显式关闭证书 PEM |
| `-h`, `--help` | 显示用法 |

解析模式下，退出码 `0` 表示全部解析成功；验证模式下，只有全部镜像 `IsVerified=true` 才返回 `0`。`1` 表示至少一个输入失败或未通过验证，`2` 表示参数错误、目录枚举失败或没有可处理文件。

## 性能设计

- 内存 API 以 `ReadOnlySpan<byte>` 解析调用方缓冲区，热路径使用显式小端读取和切片，避免复制与反射式反序列化。
- 文件 API 使用 128 KiB 顺序读取缓冲并一次装载镜像；适合固件随机访问解析，但峰值内存至少接近文件大小。
- 多 ELF 验证在同一输入缓冲区上使用 Span 切片，不为每个组件复制完整镜像。
- 签名输入仅在需要清零双签对侧字段时租用共享缓冲区；SBL 连续签名前缀和哈希计算直接读取原缓冲区。
- 证书包验证缓存证书签名边，并仅让有效路径终端 Root 参与 metadata/外部信任匹配。
- 完整文件 SHA-256 默认关闭；不需要 PEM 时可关闭证书文本导出，减少计算与分配。
- 镜像大小、单条证书链大小、证书数量和元数据字符串长度均有可配置硬上限，所有声明偏移和长度在切片前完成范围验证。
- CLI 使用源生成 JSON 元数据并支持 Native AOT，减少启动时间和运行时反射开销。

## 参考与许可证注意

参考了以下项目的部分源码：

- [`msm8916-mainline/qtestsign@0eef3b5`](https://github.com/msm8916-mainline/qtestsign/tree/0eef3b552b1ada848f22bad38ab2e40407307c5b)：[`mbn/elf.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/elf.py)、[`mbn/hashseg.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/hashseg.py)、[`mbn/cert.py`](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/mbn/cert.py)，上游许可证为 [GPL-2.0](https://github.com/msm8916-mainline/qtestsign/blob/0eef3b552b1ada848f22bad38ab2e40407307c5b/COPYING)。
- [`coreboot/coreboot@fbdef3a`](https://github.com/coreboot/coreboot/tree/fbdef3aea5b7090b75e91dad2e82fb12819a80d9)：[`util/qualcomm/mbn_tools.py`](https://github.com/coreboot/coreboot/blob/fbdef3aea5b7090b75e91dad2e82fb12819a80d9/util/qualcomm/mbn_tools.py)，该文件标注为 BSD-3-Clause；coreboot 仓库其他文件可能采用不同许可证。
- 暂未Public的 `GeekFlashCore.QcomImage` 与 `GeekFlashCore.QcomImage.Abstractions` 本地源码用于 API 与字段语义比对；因未公开，不在此伪造远程链接。

本仓库是依据公开格式信息重新编写的独立实现，不包含上述项目的源代码，也不包含 qtestsign 测试私钥、测试证书或由其派生的签名/证书/哈希测试向量。引用、修改或再分发上游代码时，仍须分别遵守其许可证。
