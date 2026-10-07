# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
param(
    [Parameter(Mandatory=$true)][ValidateSet('create', 'sign')][string]$Action,
    [Parameter(Mandatory=$true)][string]$Directory,
    [string]$AiaDerBase64
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $Directory
if ($Action -eq 'sign') {
    $key = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $read = 0
        $key.ImportPkcs8PrivateKey([System.IO.File]::ReadAllBytes('keys-private/issuer.pk8'), [ref]$read)
        $sig = $key.SignData(
            [System.IO.File]::ReadAllBytes('ocsp-tbs.der'),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
        [System.IO.File]::WriteAllBytes('ocsp-signature.der', $sig)
    } finally { $key.Dispose() }
    exit 0
}

if (-not $AiaDerBase64) { throw 'AIA DER is required' }
$curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
$issuerKey = [System.Security.Cryptography.ECDsa]::Create($curve)
$leafKey = [System.Security.Cryptography.ECDsa]::Create($curve)
try {
    $issuerRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Onyx Windows OCSP Test CA', $issuerKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $issuerRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $issuerRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign, $true))
    $issuer = $issuerRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(2))
    try {
        $leafRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=localhost', $leafKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('localhost')
        $leafRequest.CertificateExtensions.Add($san.Build())
        $leafRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
        $leafRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
        $leafRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509Extension]::new(
                [System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.1.1'),
                [Convert]::FromBase64String($AiaDerBase64), $false))
        # RFC 7633 TLS Feature status_request(5). A TLS client must reject this
        # certificate until the daemon has fetched and installed its staple.
        $leafRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509Extension]::new(
                [System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.1.24'),
                [byte[]](0x30, 0x03, 0x02, 0x01, 0x05), $false))
        $serial = [byte[]](0x46, 0x53, 0x3d, 0x21, 0x5e, 0x24, 0x0a, 0x11,
                           0x5f, 0x42, 0x48, 0x7c, 0x10, 0x70, 0x02, 0x05)
        $leaf = $leafRequest.Create(
            $issuer, [System.DateTimeOffset]::UtcNow.AddHours(-1),
            [System.DateTimeOffset]::UtcNow.AddDays(1), $serial)
        try {
            [System.IO.File]::WriteAllText('leaf.pem',
                $leaf.ExportCertificatePem() + $issuer.ExportCertificatePem())
            [System.IO.File]::WriteAllText('roots.pem', $issuer.ExportCertificatePem())
            [System.IO.File]::WriteAllBytes('leaf.der', $leaf.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            [System.IO.File]::WriteAllBytes('issuer.der', $issuer.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            [System.IO.File]::WriteAllText('keys-private/server.key', $leafKey.ExportPkcs8PrivateKeyPem())
            [System.IO.File]::WriteAllBytes('keys-private/issuer.pk8', $issuerKey.ExportPkcs8PrivateKey())
        } finally { $leaf.Dispose() }
    } finally { $issuer.Dispose() }
} finally {
    $leafKey.Dispose()
    $issuerKey.Dispose()
}
