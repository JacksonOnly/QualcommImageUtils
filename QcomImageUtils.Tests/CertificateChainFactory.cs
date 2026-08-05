using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace QcomImageUtils.Tests;

internal static class CertificateChainFactory
{
    private static readonly Lazy<byte[]> Chain = new(CreateCore);

    public static byte[] CreateWithOuMetadata()
    {
        return [.. Chain.Value];
    }

    private static byte[] CreateCore()
    {
        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest(
            "CN=Qcom Test Root",
            rootKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));

        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = DateTimeOffset.UtcNow.AddDays(1);
        using X509Certificate2 root = rootRequest.CreateSelfSigned(notBefore, notAfter);

        using RSA leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest(
            "CN=Qcom Test Leaf, OU=01 0000000000000003 SW_ID, OU=02 000000AB OEM_ID, OU=03 000000CD MODEL_ID, OU=04 00001000 SW_SIZE, OU=05 1234567800AB00CD HW_ID",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        byte[] serialNumber = [1, 2, 3, 4, 5, 6, 7, 8];
        using X509Certificate2 leaf = leafRequest.Create(root, notBefore, notAfter, serialNumber);

        byte[] leafDer = leaf.Export(X509ContentType.Cert);
        byte[] rootDer = root.Export(X509ContentType.Cert);
        var chain = new byte[checked(leafDer.Length + rootDer.Length)];
        leafDer.CopyTo(chain, 0);
        rootDer.CopyTo(chain, leafDer.Length);
        return chain;
    }
}
