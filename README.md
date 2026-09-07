# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `patch_atas.py`: reads the original DLL and writes the patched DLL.

Current SHA-256 hashes:

```text
EC459065FF3D679CF2DE38469D3F88297AFECCBAA49885592158E232DABD3351  OFT.Platform.Core.dll
0E814DACD49F9D8DF0CED94DA5D28CAF88EB658F01E3702C395D5B12D2CA28FE  OFT.Platform.Core.patched.dll
```

## Build Patched DLL

Default command:

```powershell
python .\patch_atas.py
```

That reads:

```text
OFT.Platform.Core.dll
```

and writes/replaces:

```text
OFT.Platform.Core.patched.dll
```

Explicit input/output form:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.dll --output .\OFT.Platform.Core.patched.dll
```

Dry-run the original without writing:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.dll --dry-run
```

Expected summary for the original:

```text
0 already patched, 24 to patch, 0 need attention
```

Expected summary for the patched DLL:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.patched.dll --dry-run
```

```text
24 already patched, 0 to patch, 0 need attention
```

If the script reports `attention`, the app changed enough that the method RVAs or byte fingerprints in `patch_atas.py` need to be updated before patching.

## Patch Notes

The useful logic is in `OFT.Platform.Core.dll`. The patch changes the paywall/license checks so limited features are treated as available:

- `PayWallDataManager.TryCheckAllowFeature<T>()` returns allowed.
- limit/query helpers return not limited.
- paywall display helpers return false.
- license-expired UI helpers return false.
- `AuthorizationViewModel.IsAuthorized` returns true.
- connector feature/license checks return allowed.
- connector category active-limit checks return no limit.
- account-plan provider-list checks allow all server-backed connectors.
- connector-limited license popup returns a completed task without showing.

The DLL also has a ReadyToRun managed native header. That must be cleared, otherwise .NET can run precompiled native method bodies instead of the patched IL. `patch_atas.py` clears that header as part of the patch.

For methods without exception-handler sections, the patcher replaces the IL body and shrinks the fat method header's `CodeSize` to the exact replacement length. This is required by the .NET 10 JIT: leaving the old declared code length after an early `ret`, even with `nop` padding, can produce `InvalidProgramException`. Methods with exception-handler sections keep their offset-safe original code size.
