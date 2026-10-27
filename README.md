# Office Catalina activation backport — 1.0.0

An independent compatibility patch for the **Intel Catalina Office suite** when a legitimate account reaches “Activating” and fails with `0x0` because of the 2026 licensing-certificate rollover.

It can patch **Word, Excel, PowerPoint, Outlook and OneNote in place**, keeping their normal names and locations. It creates restorable framework backups, not additional launchable apps. It accepts only these exact framework/app builds:

- `16.66.22101101` (Word/PowerPoint in the investigated installation).
- `16.65.22091101` (Excel/Outlook/OneNote in that installation).

**0x0 has other causes. This is not a universal fix.** All original hashes must match; unknown or previously modified builds are refused. Do not edit the hashes or force another build. See VALIDATION.md for what was actually tested versus inferred from shared frameworks.

A legitimate license and normal Microsoft sign-in remain necessary. This patch does not manufacture licenses, transfer activation tokens, or disable entitlement, certificate expiry or cryptographic signature checks.

## How it works

The old client uses a 2011 licensing CA that expired in July 2026. The patch installs Microsoft's authentic 2023 CA into the existing verifier and changes the licensing HTTP header `X-OfficeVersion` to `16.83`. In the successful Word experiment, the server then returned a 2023-chain signer and the old client activated with its original cryptographic verifier.

The modified frameworks are **locally ad hoc signed**, so they no longer carry valid Microsoft binary signatures. The main application executables and their entitlements are unchanged; the outer app resource seals no longer match the modified frameworks. The tested Office apps already permit this kind of framework loading. No SIP/Gatekeeper setting, system keychain trust, clock or macOS installation is changed. This is unsupported by Microsoft and does not add other security updates to these old Office builds.

## Requirements

- Intel Mac, Catalina, and supported original Office apps legally installed.
- Python3.8 or later (`python3 --version`). Catalina's Python2 is insufficient. No Python packages are needed.
- Apple's `codesign`, `ditto`, `pkgutil`, `curl` and `ps` utilities.
- Administrator access for changing root-owned apps in `/Applications`.
- Approximately 8 GB free for the donor download/extraction and suite staging/backups; allow more for optional test copies.
- Network access for the Microsoft donor download and normal activation.

Run the following from the extracted release directory. The donor process does **not** install or run Office 16.83 on Catalina.

## 1. Inspect all installed Office apps

```sh
python3 suite.py inspect
```

This is read-only. All installed apps from the five-name list above must have supported matching framework pairs before suite installation proceeds. Missing apps are skipped. If an app is unsupported or already modified, the whole apply operation stops before changing an app.

## 2. Obtain the authentic public CA

```sh
python3 patcher.py prepare-donor --download \
  --work-dir "$HOME/Downloads/office-backport-donor"
```

This downloads the exact Microsoft Word 16.83 updater (~1.24 GB), verifies its pinned SHA256, expands it temporarily, verifies the donor framework, and extracts the public 2023 CA. Temporary expanded files are removed; the installer and public certificate remain in the work directory. A changed upstream download is rejected.

If you already have the exact updater, substitute:

```sh
python3 patcher.py prepare-donor \
  --package "/path/to/Microsoft_Word_16.83.24031120_Updater.pkg" \
  --work-dir "$HOME/Downloads/office-backport-donor"
```

The pinned digest corresponds to the Microsoft-signed/notarized package verified during research. The script never accepts an arbitrary replacement certificate. URL, hashes and byte-level changes are in TECHNICAL.md.

## 3. Save your work and quit ALL Office apps

Quit any earlier test copies too. The installer refuses running target apps; it never forces them closed. Keep normal backups of your documents and settings. The patch only changes the two framework bundles in each app, not user documents, containers or keychain data.

## 4. Patch the main installed apps

Choose a **new** backup directory on the same filesystem as Office. Keep it for rollback:

```sh
sudo python3 suite.py apply \
  --certificate "$HOME/Downloads/office-backport-donor/office-licensing-ca-2023.der" \
  --backup-dir "/Library/Application Support/Office-Catalina-Backport/backup-1"
```

Administrator privileges are used only here because installed apps are normally root-owned. Review the source before running it with sudo.

Before replacing anything, the tool checks every app's original signature, builds and locally signs every replacement, and backs up each original framework. It then swaps the framework directories. A normal error triggers automatic restoration of affected frameworks. If the computer loses power or the process is forcibly killed, use the restore command below; the receipt records installation progress.

Backups contain only framework bundles and a receipt. They are not usable second Word/PowerPoint applications. The main app names, paths, executable bytes, document associations and Dock targets are unchanged by the tool.

## 5. Verify and activate normally

```sh
sudo python3 suite.py verify \
  --backup-dir "/Library/Application Support/Office-Catalina-Backport/backup-1"
```

Open your normal Office apps and sign in/activate if prompted. Verify each app you use. This command checks local file consistency and framework signatures, **not activation, document editing or future renewal**. Receipts are locally generated and are not publisher signatures.

Do not use whole-app `codesign --verify --deep` as the patched-app success test: the original outer seal intentionally no longer matches changed frameworks. The tool verifies the individual framework signatures and unchanged main executables. If macOS blocks an app, stop and report the exact result; do not disable system security settings to follow this guide.

## Rollback

Save work, quit Office, then:

```sh
sudo python3 suite.py restore \
  --backup-dir "/Library/Application Support/Office-Catalina-Backport/backup-1"
```

This restores the original signed frameworks and retains backups. It refuses to overwrite an unrelated Office update. Restoring the old code can reintroduce 0x0; it does not erase the shared activation state or reset your Office profile. Do not delete keychains, accounts or Office containers as a rollback step.

Keep backups outside the app bundles. Office updates may overwrite the patch; if that happens, inspect again. Do not reapply this release to a different build or change the script's expected hashes. A restored installation can be patched again using a new backup directory.

## Optional: separate Word test copy

For people who prefer testing before in-place installation, the original Word 16.66.1 copy workflow remains available:

```sh
python3 patcher.py apply \
  --source "/Applications/Microsoft Word.app" \
  --certificate "$HOME/Downloads/office-backport-donor/office-licensing-ca-2023.der" \
  --output "$HOME/Applications/Office-Catalina-Test"
```

This creates a second Word and only supports the exact 16.66.1 Word build. Both copies share user data. Quit and remove that test output through Finder after moving to the main installation. It is not needed for the suite workflow.

## Limitations

- One installation was investigated. A successful Word activation is direct evidence; shared framework bytes alone do not prove every app's activation and renewal behavior.
- Long-term renewal, offline use, document editing/export and future server changes are not established.
- The patch replaces the old CA rather than implementing 16.83's two-CA fallback. Old-chain responses can still fail.
- The header reports 16.83 while the executable remains old. Other server responses may assume newer client capabilities.
- Apple silicon and other framework versions are unsupported. The ARM64 slices are unchanged.
- The patch does not provide Microsoft support or other Office/macOS security updates.

## Sharing and privacy

Share the release ZIP containing source, tests and documentation. **Do not share generated backups, patched apps, donor installers, personal receipts, or Office logs.** The release contains no Microsoft binaries, certificates, credentials, account tokens or license files. Certificates are extracted locally from Microsoft's pinned download.

For bug reports, provide patcher version, macOS version, app/build, failing step and concise error. Redact usernames in paths. Raw Office logs may contain renewal tokens and account identifiers; do not post them.

SHA256SUMS detects changes relative to this archive, but does not authenticate its publisher. Obtain the archive through a trusted channel and review its source.
