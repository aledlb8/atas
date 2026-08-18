# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `patch_atas.py`: reads the original DLL and writes the patched DLL.

Current SHA-256 hashes:

```text
DD2D7BA8508C94E7558940E5C61B6FCC83230D8C6ACD4AE20AA40FA0D0CCF852  OFT.Platform.Core.dll
A65674C359649B4D82C3D835EA2C857243FD34B9CBE823DB66940979BA509EC4  OFT.Platform.Core.patched.dll
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
