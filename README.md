# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `patch_atas.py`: resolves the current targets from .NET metadata, then writes
  the patched DLL.
- `dotnet_method_map.py`: metadata parser used by the patcher and available for
  diagnostics.

Current SHA-256 hashes:

```text
EC459065FF3D679CF2DE38469D3F88297AFECCBAA49885592158E232DABD3351  OFT.Platform.Core.dll
0E814DACD49F9D8DF0CED94DA5D28CAF88EB658F01E3702C395D5B12D2CA28FE  OFT.Platform.Core.patched.dll
```

## Build Patched DLL

After an application update, replace `OFT.Platform.Core.dll` with the new
original DLL and run the same command as before:

```powershell
python .\patch_atas.py
```

No RVA, method-size, metadata-token, or IL-prefix values need to be copied into
`patch_atas.py`. They are resolved from the current DLL on every run.

Most targets are located by their stable `TypeDef::MethodDef` names. Three
obfuscated helper methods are located relative to stable neighboring MethodDefs;
the patcher verifies their declaring type, obfuscated-name form, parameter count,
and return type before accepting them. If those relationships change, the run
fails before writing an output file instead of guessing.

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

## Inspect Method Metadata

`dotnet_method_map.py` is a read-only helper that resolves .NET MethodDef
metadata directly from the DLL. It does not load the assembly and has no
third-party dependencies.

Resolve one method:

```powershell
python .\dotnet_method_map.py .\OFT.Platform.Core.dll `
  --symbol "OFT.Platform.ViewModels.Connections.SelectConnectorTypeViewModel::InitializeAsync"
```

The output includes the current metadata token, RVA, method-header size, IL
code size, signature blob, and the first 16 IL bytes. Use `--prefix-bytes N` to
change the prefix length or `--json` for machine-readable output.

For diagnostics or unrelated reverse-engineering work, save symbols in a text
file, one `Full.Namespace.Type::Method` per line, then run:

```powershell
python .\dotnet_method_map.py .\OFT.Platform.Core.dll --symbols-file .\methods.txt --json
```

Blank lines and `#` comments are ignored. Normal patching does not require a
symbols file; `patch_atas.py` performs its own target resolution automatically.

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

If the script reports a metadata-resolution error or `attention`, the relevant
method or method relationship changed enough that it should be reviewed. Do not
manually refresh RVAs first; the resolver already handles ordinary relocation,
token renumbering, method-size changes, and IL-prefix changes.

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
