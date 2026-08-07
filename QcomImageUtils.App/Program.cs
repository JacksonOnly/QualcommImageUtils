using System.Text;
using System.Text.Json;
using QcomImageUtils;
using QcomImageUtils.Models;
using QcomImageUtils.Types;

Console.OutputEncoding = Encoding.UTF8;
bool json = false;
bool calculateHash = false;
bool exportPem = false;
bool verify = false;
var trustedRootHashes = new List<string>();
var paths = new List<string>();

for (int index = 0; index < args.Length; index++)
{
    string argument = args[index];
    switch (argument)
    {
        case "--json":
            json = true;
            break;
        case "--hash":
            calculateHash = true;
            break;
        case "--pem":
            exportPem = true;
            break;
        case "--no-pem":
            exportPem = false;
            break;
        case "--verify":
            verify = true;
            break;
        case "--trusted-root":
            if (++index >= args.Length)
            {
                Console.Error.WriteLine("--trusted-root 后必须提供十六进制 Root CA 哈希");
                return 2;
            }

            trustedRootHashes.Add(args[index]);
            verify = true;
            break;
        case "--help":
        case "-h":
            PrintUsage();
            return 0;
        default:
            if (argument.StartsWith("--", StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"未知选项: {argument}");
                PrintUsage();
                return 2;
            }

            paths.Add(argument);
            break;
    }
}

if (paths.Count == 0)
{
    PrintUsage();
    return 2;
}

try
{
    paths = ExpandInputPaths(paths);
}
catch (Exception exception) when (exception is IOException
                                   or UnauthorizedAccessException
                                   or ArgumentException)
{
    Console.Error.WriteLine($"无法枚举输入目录: {exception.Message}");
    return 2;
}

if (paths.Count == 0)
{
    Console.Error.WriteLine("输入目录中没有可处理的镜像文件");
    return 2;
}

if (verify)
    return VerifyImages(paths, trustedRootHashes, json, calculateHash, exportPem);
return ParseImages(paths, json, calculateHash, exportPem);

static int ParseImages(
    IReadOnlyList<string> paths,
    bool json,
    bool calculateHash,
    bool exportPem)
{
    var parser = new QcomImageParser(new QcomImageParserOptions
    {
        CalculateFileSha256 = calculateHash,
        ExportCertificatePem = exportPem
    });
    var results = new QcomImageParseResult[paths.Count];
    bool allSucceeded = true;
    for (int index = 0; index < paths.Count; index++)
    {
        bool success = parser.TryParse(paths[index], out QcomImageParseResult result);
        results[index] = result;
        allSucceeded &= success;
    }

    if (json)
    {
        if (results.Length == 1)
            Console.WriteLine(JsonSerializer.Serialize(
                results[0],
                AppJsonSerializerContext.Unicode.QcomImageParseResult));
        else
            Console.WriteLine(JsonSerializer.Serialize(
                results,
                AppJsonSerializerContext.Unicode.QcomImageParseResultArray));
    }
    else
    {
        for (int index = 0; index < results.Length; index++)
        {
            if (index > 0)
                Console.WriteLine();
            PrintResult(results[index]);
        }
    }

    return allSucceeded ? 0 : 1;
}

static int VerifyImages(
    IReadOnlyList<string> paths,
    IReadOnlyCollection<string> trustedRootHashes,
    bool json,
    bool calculateHash,
    bool exportPem)
{
    QcomImageVerifier verifier;
    try
    {
        verifier = new QcomImageVerifier(new QcomImageVerifierOptions
        {
            CalculateFileSha256 = calculateHash,
            ExportCertificatePem = exportPem,
            AnalyzeFirehoseCommands = true,
            TrustedRootCertificateHashes = trustedRootHashes
        });
    }
    catch (ArgumentException exception)
    {
        Console.Error.WriteLine(exception.Message);
        return 2;
    }

    var results = new QcomImageVerificationResult[paths.Count];
    bool allVerified = true;
    for (int index = 0; index < paths.Count; index++)
    {
        bool completed = verifier.TryVerify(paths[index], out QcomImageVerificationResult result);
        results[index] = result;
        allVerified &= completed && result.IsVerified;
    }

    if (json)
    {
        if (results.Length == 1)
            Console.WriteLine(JsonSerializer.Serialize(
                results[0],
                AppJsonSerializerContext.Unicode.QcomImageVerificationResult));
        else
            Console.WriteLine(JsonSerializer.Serialize(
                results,
                AppJsonSerializerContext.Unicode.QcomImageVerificationResultArray));
    }
    else
    {
        for (int index = 0; index < results.Length; index++)
        {
            if (index > 0)
                Console.WriteLine();
            PrintResult(results[index].Image);
            PrintVerification(results[index]);
        }
    }

    return allVerified ? 0 : 1;
}

static void PrintUsage()
{
    Console.WriteLine(
        "QcomImageUtils <镜像或目录路径> [更多路径] [--verify] [--trusted-root <hex>] [--json] [--hash] [--pem]");
}

static List<string> ExpandInputPaths(IReadOnlyList<string> inputs)
{
    var expanded = new List<string>();
    var enumerationOptions = new EnumerationOptions
    {
        RecurseSubdirectories = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
        IgnoreInaccessible = false,
        ReturnSpecialDirectories = false
    };
    for (int index = 0; index < inputs.Count; index++)
    {
        string input = inputs[index];
        if (!Directory.Exists(input))
        {
            expanded.Add(input);
            continue;
        }

        foreach (string file in Directory.EnumerateFiles(input, "*", enumerationOptions))
        {
            string extension = Path.GetExtension(file);
            if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".txt", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".log", StringComparison.OrdinalIgnoreCase)
                || extension.Equals(".xml", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            expanded.Add(file);
        }
    }

    expanded.Sort(StringComparer.OrdinalIgnoreCase);
    return expanded;
}

static void PrintResult(QcomImageParseResult result)
{
    Console.WriteLine($"{(result.IsSuccess ? "[解析成功]" : "[解析失败]")} {result.OriginalFilePath}");
    if (!result.IsSuccess)
    {
        Console.WriteLine($"  原因: {result.ErrorMessage}");
        return;
    }

    Console.WriteLine($"  格式: {result.ImageFormat}{(result.IsSbl ? " / SBL" : string.Empty)}");
    if (result.HeaderVersion != 0)
        Console.WriteLine($"  MBN 版本: {result.HeaderVersion}");
    if (result.ImageId.HasValue)
        Console.WriteLine($"  镜像 ID: 0x{result.ImageId.Value:X8} ({result.ImageType})");
    if (result.SwId != 0)
        Console.WriteLine($"  软件 ID: 0x{result.SwId:X}");
    if (result.SocHwVersion != 0 || result.SocType != QualcommSocType.Unknown)
        Console.WriteLine($"  SoC: {result.SocType} (0x{result.SocHwVersion:X8})");
    Console.WriteLine(result.HasOemId
        ? $"  OEM: {result.OemType} (0x{result.OemId:X4})"
        : "  OEM: Unknown");
    if (!string.IsNullOrEmpty(result.RootCaHash))
        Console.WriteLine($"  Root CA: {result.RootCaHash}");
    Console.WriteLine($"  证书数: {result.CertChains.Count}");
    if (!string.IsNullOrEmpty(result.FileSha256))
        Console.WriteLine($"  SHA-256: {result.FileSha256}");
    if (!string.IsNullOrEmpty(result.BuildTime))
        Console.WriteLine($"  构建时间: {result.BuildTime}");
    if (result.SupportedCommands.Count == 0)
        return;

    Console.WriteLine($"  支持命令: {result.SupportedCommands.Count}");
    for (int index = 0; index < result.SupportedCommands.Count; index++)
    {
        FirehoseCommandInfo command = result.SupportedCommands[index];
        if (command.HandlerAddress.HasValue && command.TableEntryAddress.HasValue)
        {
            Console.WriteLine(
                $"  {command.Name}: 表项 0x{command.TableEntryAddress.Value:X}, "
                + $"处理地址 0x{command.HandlerAddress.Value:X}, "
                + $"映像偏移 0x{command.ElfImageOffset:X}");
        }
        else
        {
            Console.WriteLine(
                $"  {command.Name}: 内联分发, 映像偏移 0x{command.ElfImageOffset:X}");
        }
    }
}

static void PrintVerification(QcomImageVerificationResult result)
{
    if (!result.VerificationCompleted)
    {
        Console.WriteLine($"  验证: 无法完成 ({result.ErrorMessage})");
        return;
    }

    Console.WriteLine($"  内部真实性: {(result.IsAuthentic ? "通过" : "未通过")}");
    Console.WriteLine($"  完整验证: {(result.IsVerified ? "通过" : "未通过")}");
    Console.WriteLine(
        $"  哈希表: {result.HashTableStatus} ({result.VerifiedHashCount}/{result.ExpectedHashCount})");
    Console.WriteLine($"  QTI 签名: {FormatSignature(result.QualcommSignature)}");
    Console.WriteLine($"  OEM 签名: {FormatSignature(result.OemSignature)}");
    Console.WriteLine($"  证书链: {result.CertificateChainStatus}");
    Console.WriteLine($"  元数据 Root 哈希: {result.MetadataRootHashStatus}");
    Console.WriteLine($"  外部可信 Root: {result.TrustedRootStatus}");
    if (result.Components.Count > 1)
    {
        for (int index = 0; index < result.Components.Count; index++)
        {
            QcomImageComponentVerificationResult component = result.Components[index];
            Console.WriteLine(
                $"  ELF 组件 {component.ComponentIndex} (偏移 0x{component.ImageOffset:X}): "
                + $"{(component.IsVerified ? "通过" : "未通过")}, "
                + $"哈希 {component.HashTableStatus}, 签名 {component.SignatureStatus}, "
                + $"证书链 {component.CertificateChainStatus}");
        }
    }
    for (int index = 0; index < result.Issues.Count; index++)
        Console.WriteLine($"  问题: {result.Issues[index]}");
}

static string FormatSignature(QcomSignatureVerificationResult result)
{
    if (string.IsNullOrEmpty(result.Algorithm))
        return result.SignatureStatus.ToString();
    return $"{result.SignatureStatus} / {result.Algorithm}";
}
