# ATAS Patcher

## Quick Start

You do not need to find method addresses or edit the DLLs manually. The script
locates the required methods and creates patched copies for you.

### What you need

- Python 3 installed (`py` or `python` must work in PowerShell).
- The original `OFT.Platform.Core.dll` file.
- The original `OFT.Core.dll` file.
- All files placed in the same folder as `patch_atas.py`.

Keep a backup of the original DLLs. The script normally writes new files and
does not replace the originals.

### Create both patched DLLs

Open PowerShell in this folder and run:

```powershell
py .\patch_atas.py
py .\patch_atas.py .\OFT.Core.dll
```

If your system uses `python` instead of `py`, run:

```powershell
python .\patch_atas.py
python .\patch_atas.py .\OFT.Core.dll
```

The commands create:

- `OFT.Platform.Core.patched.dll`
- `OFT.Core.patched.dll`

Both patched DLLs are required. Use the generated copies, renamve them
to its original name and replaced them wherever you have installed ATAS.

### How to recognize success

For an original `OFT.Platform.Core.dll`, the expected summary is:

```text
Summary: 0 already patched, 26 to patch, 0 need attention.
```

For an original `OFT.Core.dll`, the expected summary is:

```text
Summary: 0 already patched, 2 to patch, 0 need attention.
```

The script then prints the path of the patched DLL it wrote. If it says
`Output already up to date`, the existing output already contains the same
patches and does not need to be rewritten.

### Check without creating a file

Use `--dry-run` to inspect a DLL without changing or writing anything:

```powershell
py .\patch_atas.py .\OFT.Platform.Core.dll --dry-run
py .\patch_atas.py .\OFT.Core.dll --dry-run
```

To verify generated copies, run:

```powershell
py .\patch_atas.py .\OFT.Platform.Core.patched.dll --dry-run
py .\patch_atas.py .\OFT.Core.patched.dll --dry-run
```

The expected summaries are:

```text
Summary: 26 already patched, 0 to patch, 0 need attention.
Summary: 2 already patched, 0 to patch, 0 need attention.
```

## Common Problems

### `py` is not recognized

Install Python 3 or replace `py` with `python` in the commands.

### Input file not found

Make sure the two original DLLs are beside `patch_atas.py`, or provide the full
path to the input file.

### Metadata, signature, or relative-target error

The binary changed enough that one of the patcher's safety checks no
longer matches. The script stops before writing an output rather than guessing
and modifying the wrong method. The affected target must be reviewed and the
corresponding patch specification updated.

### `need attention` is not zero

Do not use that output. A method contains bytes that are neither the expected
original code nor the expected patch. Restore the original DLL and
try again, or inspect the reported method.

## Workspace Files

- `patch_atas.py` — resolves targets, validates method bodies, and writes the
  patched DLL.
- `dotnet_method_map.py` — read-only .NET metadata inspection helper used for
  diagnostics.
- `OFT.Platform.Core.dll` — original platform assembly.
- `OFT.Platform.Core.patched.dll` — generated patched platform assembly.
- `OFT.Core.dll` — original core assembly.
- `OFT.Core.patched.dll` — generated patched core assembly.

---

# Technical Reference

## Input and output selection

With no input argument, `patch_atas.py` reads `OFT.Platform.Core.dll` beside
the script and writes `OFT.Platform.Core.patched.dll`.

Explicit input and output paths are also supported:

```powershell
py .\patch_atas.py .\OFT.Platform.Core.dll `
  --output .\OFT.Platform.Core.patched.dll

py .\patch_atas.py .\OFT.Core.dll `
  --output .\OFT.Core.patched.dll
```

The alternative `--input` form is equivalent:

```powershell
py .\patch_atas.py --input .\OFT.Platform.Core.dll --dry-run
```

Run `py .\patch_atas.py --help` for the complete command-line reference.

## Target resolution and validation

The patcher parses the PE and CLI metadata directly. It does not load or
execute either assembly and has no third-party Python dependencies.

Most targets are resolved by a stable `TypeDef::MethodDef` pair. A small number
of obfuscated compiler-generated helpers are resolved by their position relative
to a stable neighboring method. Before accepting a relative target, the patcher
checks its declaring type, obfuscated-name form, parameter count, and return
type.

This design avoids hard-coded RVAs, metadata tokens, method sizes, and IL
prefixes. Ordinary relocation and token renumbering therefore do not require a
manual update. If a structural relationship changes, resolution fails closed
before any output is written.

## Patch behavior

The useful logic is split between `OFT.Platform.Core.dll` and `OFT.Core.dll`,
which is why both generated files are required.

The platform patches make the treat restricted functionality as
available:

- feature checks return allowed;
- limit-query helpers report no limit;
- paywall and license-expired UI helpers return false;
- authorization checks return true;
- connector feature and category-limit checks allow access;
- provider-list checks allow server-backed connectors;
- the connector-limited popup completes without being displayed;
- AI-agent market-data policy results report `IsAllowed = true` while retaining
  source name, source type, and delay metadata;
- the default-aware request corrector does not insert a fallback history limit.

The core patch changes the final request-limit fallback so it reports no limit
instead of trimming real-time chart history to ten days.

## ReadyToRun handling

Both assemblies contain a ReadyToRun managed native header. If it remains
active, .NET may execute precompiled native bodies instead of the modified IL.
The patcher clears the managed native header in each generated DLL so the
runtime uses the patched method bodies.

The ReadyToRun header counts as one result in each summary. Consequently:

- the platform assembly reports 26 total patch operations;
- the core assembly reports 2 total patch operations.

## Method-body rewriting

For methods without exception-handler sections, the patcher replaces the IL
body and changes a fat method header's `CodeSize` to the exact replacement
length. This is required for the .NET 10 JIT: leaving the original declared
length after an early `ret`, even with `nop` padding, can produce an
`InvalidProgramException`.

Methods with exception-handler sections retain their original code size so the
section offsets remain valid.

## Inspecting .NET method metadata

`dotnet_method_map.py` resolves MethodDef information without loading the
assembly. To inspect one method:

```powershell
py .\dotnet_method_map.py .\OFT.Platform.Core.dll `
  --symbol "OFT.Platform.ViewModels.Connections.SelectConnectorTypeViewModel::InitializeAsync"
```

The output includes the metadata token, RID, RVA, method-header size, IL code
size, signature blob, and initial IL bytes. Use `--prefix-bytes N` to change the
prefix length or `--json` for machine-readable output.

For multiple symbols, create a text file containing one
`Full.Namespace.Type::Method` per line, then run:

```powershell
py .\dotnet_method_map.py .\OFT.Platform.Core.dll `
  --symbols-file .\methods.txt --json
```

Blank lines and lines beginning with `#` are ignored. A symbols file is only a
diagnostic convenience; normal patching resolves its own target list.

## Reproducible hashes

DLL hashes change whenever it publishes a new build, so this README
does not store fixed values. Calculate the hashes for the exact files in your
workspace with:

```powershell
Get-FileHash -Algorithm SHA256 `
  .\OFT.Platform.Core.dll, `
  .\OFT.Platform.Core.patched.dll, `
  .\OFT.Core.dll, `
  .\OFT.Core.patched.dll
```

Record both original and patched hashes when documenting a solution
so another participant can identify the exact build that was tested.
