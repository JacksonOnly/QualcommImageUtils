using System;
using System.Collections.Generic;

namespace QcomImageUtils;

public sealed class QcomImageVerifierOptions
{
    public int MaximumImageSize { get; set; } = 512 * 1024 * 1024;
    public int MaximumCertificateChainSize { get; set; } = 1024 * 1024;
    public int MaximumCertificateCount { get; set; } = 32;
    public int MaximumElfComponentCount { get; set; } = 64;
    public bool CalculateFileSha256 { get; set; }
    public bool ExportCertificatePem { get; set; }
    public bool AnalyzeFirehoseCommands { get; set; }
    public IReadOnlyCollection<string> TrustedRootCertificateHashes { get; set; } =
        Array.Empty<string>();
}
