# Release provenance plan

The initial release candidate does not publish signed artifacts.

Before a production or public release:

1. build from a clean checkout;
2. run the complete test suite;
3. set a fixed `SOURCE_DATE_EPOCH` and build the wheel twice;
4. require both wheel copies to have identical SHA256 values;
5. generate SHA256 hashes for every release artifact;
6. sign artifacts and checksums with an official release identity;
7. publish provenance describing source revision, builder, command, and inputs;
8. verify the downloaded artifact independently;
9. preserve a public verification instruction in the release notes.

Example on PowerShell:

```powershell
$env:SOURCE_DATE_EPOCH = "1792627200"  # 2026-10-22T00:00:00Z
python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .
python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist-second .
Get-FileHash dist\weft_governance-*.whl -Algorithm SHA256
Get-FileHash dist-second\weft_governance-*.whl -Algorithm SHA256
```

The release manifest must record the epoch used, because changing it changes the
wheel bytes even when the source is identical.

The recommended ecosystem primitives are Sigstore-compatible signing and SLSA
provenance. Neither primitive prevents copying. They make official artifacts
traceable and distinguish them from repackaged or modified copies.
