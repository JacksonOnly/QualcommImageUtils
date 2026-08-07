using System.Text.Encodings.Web;
using System.Text.Json;
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
[JsonSerializable(typeof(FirehoseCommandInfo))]
[JsonSerializable(typeof(FirehoseCommandInfo[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
    public static AppJsonSerializerContext Unicode { get; } = new(new JsonSerializerOptions
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = true
    });
}
