# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `patch_atas.py`: reads the original DLL and writes the patched DLL.
- `install.ps1`: copies the patched DLL into Program Files with the original DLL name.

Current SHA-256 hashes:

```text
D76606F7F81DB6D2C6491A1E0D0FA5B87C60F667856C5189D96365E3BC05A3E9  OFT.Platform.Core.dll
CDA7AB188E19AC292D2536D46C506C5966C73A8130DD338583C97A6D1B837EE5  OFT.Platform.Core.patched.dll
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
0 already patched, 20 to patch, 0 need attention
```

Expected summary for the patched DLL:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.patched.dll --dry-run
```

```text
20 already patched, 0 to patch, 0 need attention
```

If the script reports `attention`, the app changed enough that the method RVAs or byte fingerprints in `patch_atas.py` need to be updated before patching.

## Install

Close ATAS X, open PowerShell as Administrator, then run:

```powershell
.\install.ps1
```

The installer copies:

```text
OFT.Platform.Core.patched.dll
```

to:

```text
C:\Program Files\ATAS X\OFT.Platform.Core.dll
```

If the installed file already matches the patched DLL, the installer exits without copying.

## Patch Notes

The useful logic is in `OFT.Platform.Core.dll`. The patch changes the paywall/license checks so limited features are treated as available:

- `PayWallDataManager.TryCheckAllowFeature<T>()` returns allowed.
- limit/query helpers return not limited.
- paywall display helpers return false.
- license-expired UI helpers return false.
- `AuthorizationViewModel.IsAuthorized` returns true.

The DLL also has a ReadyToRun managed native header. That must be cleared, otherwise .NET can run precompiled native method bodies instead of the patched IL. `patch_atas.py` clears that header as part of the patch.
