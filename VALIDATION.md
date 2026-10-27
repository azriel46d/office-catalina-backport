# Validation scope

## Direct runtime observations

The separate Word 16.66.1 Catalina test copy activated after the two changes. A fresh log recorded `Activation successful`; its public signer matched the 2023-chain signer from unmodified local Word 16.83. The single-certificate change alone had failed. Long-term renewal and document editing/export were not tested.

## Installer and rollback

The packaged suite installer was tested against a disposable, complete original Word 16.66.1 copy on the remote Catalina machine:

1. Exact-build inspection passed.
2. Apply created original framework backups and signed replacements.
3. Installed-file verification passed, with the main executable unchanged.
4. Restore returned the original frameworks.
5. The restored whole app passed `codesign --verify --deep --strict`.

This exercises the installation and rollback mechanics on a real app. It does not substitute for activation tests of every suite application.

## Payload regression tests

Using locally held original Microsoft frameworks (not distributed), the automated tests reproduce the exact known output SHA256 for both framework files in both supported builds. They check unchanged lengths/tails, rejection of altered originals, rejection of already patched input and rejection of an incorrect certificate.

Run the included public tests:

```sh
python3 -m unittest discover -s tests -v
```

Fixture-based tests skip unless `OFFICE_TEST_FIXTURES` points to the research fixture tree. This release contains no proprietary fixtures. Source syntax and command-line parsers were also checked.

## Release privacy

Only the explicitly listed source, documentation and test files are archived. No environment file, SSH credential, user path, raw log, Microsoft binary, public certificate, license or renewal token belongs in this release. SHA256SUMS records the content hashes of included files.

## In-place suite rollout

On the investigated Catalina machine, suite apply completed for Word and PowerPoint 16.66.22101101 and Excel, Outlook and OneNote 16.65.22091101. Each original app passed signature and existing library-validation-entitlement preflight. Complete original framework bundles were retained outside the apps. No main application executable was changed.

## Failure recovery tests

Two public tests use synthetic filesystem fixtures: successful apply→verify→restore, and an injected failure while replacing the second framework. The latter confirms that the first replacement and the temporarily missing second framework are both restored, with the main executable unchanged. The complete five-test run passed, including the two-build private-fixture payload regression tests.

The `prepare-donor --package` workflow also completed against the pinned Microsoft package and produced the expected public CA hash. The donor was not installed or executed.
