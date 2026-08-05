using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
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
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
    public static AppJsonSerializerContext Unicode { get; } = new(new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.All),
        WriteIndented = true
    });
}
