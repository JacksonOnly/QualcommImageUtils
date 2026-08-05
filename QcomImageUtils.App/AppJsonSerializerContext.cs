using System.Text.Json.Serialization;
using QcomImageUtils.Models;

[JsonSourceGenerationOptions(
    WriteIndented = true,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(QcomImageParseResult))]
[JsonSerializable(typeof(QcomImageParseResult[]))]
[JsonSerializable(typeof(QcomImageComponentVerificationResult))]
[JsonSerializable(typeof(QcomImageComponentVerificationResult[]))]
[JsonSerializable(typeof(QcomImageVerificationResult))]
[JsonSerializable(typeof(QcomImageVerificationResult[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext;
