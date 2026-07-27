# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `patch_atas.py`: reads the original DLL and writes the patched DLL.

Current SHA-256 hashes:

```text
FFAF266C819799044B908A9A1F0EDC1EA6D81229715D2FDC49DF7E820B726139  OFT.Platform.Core.dll
121A9265397F041871A2FADC1806477D2A88B5BE44AC3F395E832AAA640F488A  OFT.Platform.Core.patched.dll
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
0 already patched, 22 to patch, 0 need attention
```

Expected summary for the patched DLL:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.patched.dll --dry-run
```

```text
22 already patched, 0 to patch, 0 need attention
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
- connector-limited license popup returns a completed task without showing.

The DLL also has a ReadyToRun managed native header. That must be cleared, otherwise .NET can run precompiled native method bodies instead of the patched IL. `patch_atas.py` clears that header as part of the patch.
