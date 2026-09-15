# ATAS Patch

Minimal workspace layout:

- `OFT.Platform.Core.dll`: original unpatched DLL.
- `OFT.Platform.Core.patched.dll`: patched DLL generated from the original.
- `OFT.Core.dll`: original core DLL containing the final market-data fallback.
- `OFT.Core.patched.dll`: patched core DLL generated from the original.
- `patch_atas.py`: resolves the current targets from .NET metadata, then writes
  the patched DLL.
- `dotnet_method_map.py`: metadata parser used by the patcher and available for
  diagnostics.

Current SHA-256 hashes:

```text
C0825A05FAD312F93158A6D83A64B448E7F6AA43940B02D80448F7D247FF7D20  OFT.Platform.Core.dll
D4743C0A4771F234B0CE266C03F6A0B7B451428C039DCDDCB0787FC7BE36AE72  OFT.Platform.Core.patched.dll
7DB42C1B7F15BB1A03C67099F03210551889E2B81C9C711D64509858C8D2EE45  OFT.Core.dll
A00DC9915BFDF2E65257071FFAE5840CC44B9F692897179701AEC7E82FF2105B  OFT.Core.patched.dll
```

## Build Patched DLL

After an application update, replace both original DLLs with the new versions
and build both patched copies:

```powershell
python .\patch_atas.py
python .\patch_atas.py .\OFT.Core.dll
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
python .\patch_atas.py .\OFT.Core.dll --output .\OFT.Core.patched.dll
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
0 already patched, 25 to patch, 0 need attention
```

Expected summary for the patched DLL:

```powershell
python .\patch_atas.py .\OFT.Platform.Core.patched.dll --dry-run
```

```text
25 already patched, 0 to patch, 0 need attention
```

The `OFT.Core.dll` check reports `0 already patched, 2 to patch` for the
original and `2 already patched, 0 to patch` for the patched copy. The second
target in each count is the ReadyToRun header.

If the script reports a metadata-resolution error or `attention`, the relevant
method or method relationship changed enough that it should be reviewed. Do not
manually refresh RVAs first; the resolver already handles ordinary relocation,
token renumbering, method-size changes, and IL-prefix changes.

## Patch Notes

The useful logic is split between `OFT.Platform.Core.dll` and `OFT.Core.dll`.
Both patched DLLs must be installed. The patch changes the paywall/license
checks so limited features are treated as available:

- `PayWallDataManager.TryCheckAllowFeature<T>()` returns allowed.
- limit/query helpers return not limited.
- the default-aware market-data request corrector does not substitute a
  fallback history limit when no paywall limit exists.
- the final core request-limit fallback returns no limit instead of trimming
  real-time chart history to 10 days.
- paywall display helpers return false.
- license-expired UI helpers return false.
- `AuthorizationViewModel.IsAuthorized` returns true.
- connector feature/license checks return allowed.
- connector category active-limit checks return no limit.
- account-plan provider-list checks allow all server-backed connectors.
- connector-limited license popup returns a completed task without showing.

Both DLLs have ReadyToRun managed native headers. Those must be cleared,
otherwise .NET can run precompiled native method bodies instead of the patched
IL. `patch_atas.py` clears the relevant header as part of each patch.

For methods without exception-handler sections, the patcher replaces the IL body and shrinks the fat method header's `CodeSize` to the exact replacement length. This is required by the .NET 10 JIT: leaving the old declared code length after an early `ret`, even with `nop` padding, can produce `InvalidProgramException`. Methods with exception-handler sections keep their offset-safe original code size.
