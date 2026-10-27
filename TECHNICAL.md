# Technical findings and patch specification

## Observed failure and repair

On the investigated Word 16.66.1 installation, sign-in and entitlement retrieval succeeded, a license model was deserialized, then `LicenseFetcher::ValidateResponse - Signature validation failed` and `Error:5` appeared before the 0x0 popup.

REA Mach-O inspection and focused native disassembly located the embedded 2011 CA and its use as an explicit anchor in `SecTrustCreateWithCertificates`, `SecTrustSetAnchorCertificates`, `SecTrustSetAnchorCertificatesOnly` and `SecTrustEvaluateWithError`. Public-key signature verification follows successful trust evaluation. The embedded CA expired July 13, 2026.

The public signer certificate extracted from the old client's renewal token verified cryptographically against the 2011 CA. Catalina's own basic X.509 evaluation failed with `TemporalValidity`, OSStatus `-67818`, trust result 5. Substituting the 2023 CA alone caused an issuer-chain mismatch and did not activate.

Unmodified Word 16.83 on a supported local Mac activated and received a renewal-token signer under the 2023 CA. Its logs explicitly marked certificate and signature verification successful. Catalina separately validated that public signer with the 2023 CA (trust result 4), establishing that the OS can handle that chain.

The import table identifies `mso30` as the implementation of `Mso::Licensing::Nul::Api::Post` and `LicenseService::RestApi::BuildHeaders`. The old `mso99` header wrapper calls BuildHeaders at x86_64 VA 0xba037f through stub 0x17abcca. BuildHeaders at 0xeed40 obtains the executable version, formats major/minor, and pairs it with `X-OfficeVersion`. After changing that header value to 16.83 alongside the CA replacement, the Catalina client received the same 2023-chain signer as the local 16.83 client and logged `Activation successful` at 2026-10-27 05:34:49.145 UTC. The user confirmed success.

This strongly supports version-dependent server signing-chain selection. The server implementation was not inspected; the intervening local activation is a possible account-state confounder, and no reversal trial was performed after success. The extracted signer came from a renewal token, not a debugger capture of the outer validator's certificate argument. The practical combined-patch success is directly observed.

## Exact original inputs (SHA256)

Word build: 16.66.22101101. Both universal framework files must match:

| File | SHA256 |
|---|---|
| mso99 | `1402eab4d8b61cbfb06170ca7d7a0cffdfa8734dda6d42e146d724b1946cb865` |
| mso30 | `9712aff68e0f7ca6d01076be901d90aaa67ccb84cb7fc7cd5fde92458d39edad` |

Framework paths: `Contents/Frameworks/NAME.framework/Versions/A/NAME`.

## Authentic donor

Microsoft CDN package:
https://officecdn.microsoft.com/pr/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/Microsoft_Word_16.83.24031120_Updater.pkg

- Size: 1,234,698,125 bytes.
- Package SHA256: `6155783198cebc67706b40505f27aeeb442c0c9eb108e47428578e826f41a2f6`.
- Research verification: Developer ID Installer Microsoft Corporation `(UBF8T346G9)`, trusted Apple notarization, timestamp 2024-03-12 03:24:26 UTC. The extracted app also passed deep strict code-signature verification on the local Mac.
- Donor mso99 SHA256:`60fb321a30f2b116dfa1ee278628920fd0cd691dc58fb4a1891a9390dfa017b8`.
- Public CA: Microsoft Office Licensing CA 2023, issued by Microsoft Services Partner Root, valid 2023-07-13 through 2035-07-13.
- DER SHA256: `53e06022bfaa603f0fdb18ff193a93075e815a4359c1694d83adc616efbbb29c`.
- Donor universal-file offset 0x1d0ae70 contains 2284 UTF16 Base64 characters decoding to 1712 DER bytes.

## Patch A: mso99 certificate

- Old CA: Microsoft Office Service Infrastructure Issuing CA 2011, expired 2026-07-13.
- Old DER SHA256: `8d4a3715e616b63369c9b1187240413248f00b452464b5e63ad3cc8cccb502e0`.
- Universal-file offset 0x1a8e1a0: replace 2352 UTF16 Base64 characters with 2284 new characters and zero padding.
- Universal-file offset 0x10887a: length operand 2352→2284; instruction is `mov esi, immediate`.
- No other bytes change before signing. x86_64 only; ARM64 remains unchanged.
- Pre-signing output SHA256: `e254a2ca742f49993170f8f93f779919e6f54f893f747ca7419ab7b28c5abcb2`.

## Patch B: mso30 request header

The x86_64 slice starts at universal offset 0x4000. In BuildHeaders:

- VA 0xeee13 calls `Mso::Process::GetExeVersion`.
- Original VA 0xeee2f calls `WriteMajMinVerWithNoParanthesis`.
- Header pairing at 0xef3f5–0xef403 supplies the constructed string at stack slot `rbp-0x628` to `X-OfficeVersion`.

The patch writes UTF16 `16.83` plus terminator to zero-filled __TEXT header padding at slice offset 0x3000 (universal offset 0x7000), after load commands and before __text. At VA 0xeee24–0xeee42 it constructs that same string object using the existing constructor at 0x65d19c, then pads with NOPs. All subsequent checks remain unchanged. This changes 35 bytes before signing.

Pre-signing output SHA256: `25b87aa2d643c4af7bf53bfc7c0ebf59384b9e294473e9ac00cc054596c05a57`.

Post-signing hashes differ because code signatures change; the patcher records those hashes in a local receipt. No signature-verification return value, entitlement result, certificate validity date or license payload is modified. No account identity or token is embedded in either patch.

REA evidence for the second candidate: `ev_97d8f96c1bccf6ee06a0179ada9a34ef7874d4cbcde3cf3c42a3ec3b1c397efd`. This was static Mach-O evidence; successful activation is a separate runtime observation. Raw tool outputs and private logs are deliberately excluded from this shareable release.

## Suite profile 16.65.22091101

The investigated Excel, Outlook and OneNote apps have byte-identical mso99/mso30 pairs. Word and PowerPoint share the 16.66.1 pair described above. The 16.65 patch uses independently located instructions, not 16.66 offsets applied blindly:

| Item | 16.65 value |
|---|---|
| Original mso99 SHA256 | `c5d7f114403efe998bfc96309e166bd39c9198be5de00ada5345b4970110c73d` |
| Original mso30 SHA256 | `9026f8f7c64e587787810053307c2d87011b86f590d2fa62d6ed7eac78f1b4d8` |
| mso99 cert universal offset | `0x1a8f080` |
| mso99 length operand universal offset | `0x1076f4` |
| mso30 header replacement slice range | `0x104f54`–`0x104f72` inclusive |
| mso30 existing string constructor | `0x6747bc` |
| mso30 literal slice offset | `0x3000` |
| Patched mso99 before signing | `95df04e82d24c73252bb47bcb0607536800e134985236e4c87e346b1657859ca` |
| Patched mso30 before signing | `fee4c016394a715f917df12587f2bfdba1199c25256ecfa52b0549e29e2be395` |

The old 16.65 validator at VA 0x1036cf loads the same 2011 CA at 0x1a8b080 with length 0x930. Its BuildHeaders at 0x104e70 calls GetExeVersion at 0x104f43 and WriteMajMinVerWithNoParanthesis at 0x104f5f; it constructs the same stack string object at `rbp-0x628`. Both universal files have x86_64 slice offset 0x4000. Full expected input/output hashes are mandatory.

Suite installation backs up complete original framework directories (including their code signatures/resources), stages all replacements before modifying installed apps, records progress, and renames frameworks into their original paths. It does not re-sign main executables. Restore checks for unrelated updates and verifies saved framework signatures before restoring. Backups deliberately remain local and are not part of the release.
