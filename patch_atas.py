#!/usr/bin/env python3
"""
- it validates the PE/CLI layout;
- it checks each known method body against the original byte fingerprint;
- it treats already-patched methods as OK;
- it clears the ReadyToRun managed native header;
- it refuses to write anything if any method is in an unexpected state.
"""

from __future__ import annotations

import argparse
import dataclasses
import struct
import sys
from pathlib import Path


DLL_NAME = "OFT.Platform.Core.dll"
PATCHED_DLL_NAME = "OFT.Platform.Core.patched.dll"


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclasses.dataclass(frozen=True)
class MethodPatch:
    name: str
    rva: int
    expected_header_size: int
    expected_code_size: int
    original_prefix: bytes
    patch_bytes: bytes


@dataclasses.dataclass
class Result:
    name: str
    status: str
    detail: str


class PatchError(Exception):
    pass


PATCHES = [
    MethodPatch(
        "PayWallDataManager.TryCheckAllowFeature<T>",
        0x9F5868,
        12,
        68,
        bytes.fromhex("0203120028b10e002b2d0a171a2d0326"),
        bytes.fromhex("170bde3e"),
    ),
    MethodPatch(
        "PayWallDataManager.TryGetLimitValue<T>",
        0x9F59D4,
        12,
        318,
        bytes.fromhex("14152d03262b030c2b000228a2660006"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallDataManager.HasPayWallData",
        0x9F5C60,
        12,
        32,
        bytes.fromhex("0217152d1426031b152d112628b50e00"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallDataManager.ExistsEnabledFeature",
        0x9F5C8C,
        12,
        131,
        bytes.fromhex("73dc660006172d1326027b183b000403"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallDataManager.ExistsFeature",
        0x9F5C34,
        12,
        31,
        bytes.fromhex("02191d2d13267b183b000403171c2d0b"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.IsLimited<T>",
        0x898220,
        12,
        49,
        bytes.fromhex("021e182d162603151e2d1326041e172d"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfLimit<T>",
        0x8982B4,
        12,
        57,
        bytes.fromhex("28e92800066f3717000a031d162c1026"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "LicenseInformationViewModelBase.get_IsLicenseExpired",
        0x937DF0,
        12,
        17,
        bytes.fromhex("02171b2d08267be72900042b03262bf6"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "LicenseState.get_IsLicenseExpired",
        0xB0D43C,
        12,
        17,
        bytes.fromhex("021b182d08267bd65800042b03262bf6"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "LicenseState.get_IsLicenseExpiredMessageError",
        0xB0D49C,
        12,
        17,
        bytes.fromhex("021e1c2d08267bd95800042b03262bf6"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "LicenseState.get_ShowAlert",
        0xB0D4DC,
        12,
        17,
        bytes.fromhex("0219192d08267bdb5800042b03262bf6"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "AuthorizationViewModel.get_IsAuthorized",
        0xAA5480,
        12,
        17,
        bytes.fromhex("021d192d08267b7f4d00042b03262bf6"),
        bytes.fromhex("172a"),
    ),
    MethodPatch(
        "ConnectorsManager.connection-license check",
        0x8A4FE0,
        12,
        103,
        bytes.fromhex("036f3b17000a1c2d07260617350f2b03"),
        bytes.fromhex("172a"),
    ),
    MethodPatch(
        "ConnectorPayWallRestrictions.category-active-limit mapper",
        0x90A5E8,
        12,
        40,
        bytes.fromhex("02171d2d19267b5a230004031d192d11"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "SelectConnectorTypeViewModel.server-feature predicate",
        0xAB4AE0,
        12,
        56,
        bytes.fromhex("031c182d0a26281e2800062c292b0326"),
        bytes.fromhex("172a"),
    ),
    MethodPatch(
        "PlatformViewExtensions.ShowConnectorLimitedMessage",
        0x89C1C8,
        12,
        94,
        bytes.fromhex("1200288f01000a162c3e26261200021d"),
        bytes.fromhex("28210a000a2a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowLimit",
        0x898260,
        12,
        71,
        bytes.fromhex("021e1e2d05262c122b03262bf903181b"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfEnabledLimit",
        0x898174,
        12,
        43,
        bytes.fromhex("02037ef0150004252d1b2614fe06ee28"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfExistsLimit",
        0x8981E4,
        12,
        47,
        bytes.fromhex("02037ee4150004252d1f267ee3150004"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfHeatmapsCountLimit",
        0x8982FC,
        12,
        28,
        bytes.fromhex("02181a2d10261f42031b192d0b2628f8"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfIndicatorsPerHeatmapLimit",
        0x898324,
        12,
        28,
        bytes.fromhex("021a1d2d10261f43031c172d0b2628f8"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.ShowIfIndicatorsPerChartLimit",
        0x89834C,
        12,
        35,
        bytes.fromhex("021d1d2d1426031e1d2d1126041a1d2d"),
        bytes.fromhex("162a"),
    ),
    MethodPatch(
        "PayWallExtensions.indicator-count helper",
        0x89837C,
        12,
        48,
        bytes.fromhex("730f290006182d1d2606041d2d1a2626"),
        bytes.fromhex("162a"),
    ),
]


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def require_range(data: bytes | bytearray, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise PatchError(f"{what} is outside the file")


class PEImage:
    def __init__(self, data: bytes | bytearray):
        self.data = data
        self.sections: list[Section] = []
        self.cli_header_rva = 0
        self.cli_header_size = 0
        self._parse()

    def _parse(self) -> None:
        require_range(self.data, 0, 0x40, "DOS header")
        if self.data[0:2] != b"MZ":
            raise PatchError("missing MZ signature")

        pe_offset = u32(self.data, 0x3C)
        require_range(self.data, pe_offset, 24, "PE header")
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PatchError("missing PE signature")

        number_of_sections = u16(self.data, pe_offset + 6)
        optional_header_size = u16(self.data, pe_offset + 20)
        optional_offset = pe_offset + 24
        require_range(self.data, optional_offset, optional_header_size, "optional header")

        magic = u16(self.data, optional_offset)
        if magic == 0x10B:
            data_directory_offset = optional_offset + 96
        elif magic == 0x20B:
            data_directory_offset = optional_offset + 112
        else:
            raise PatchError(f"unsupported optional header magic 0x{magic:04x}")

        cli_directory_offset = data_directory_offset + (14 * 8)
        require_range(self.data, cli_directory_offset, 8, "CLI data directory")
        self.cli_header_rva = u32(self.data, cli_directory_offset)
        self.cli_header_size = u32(self.data, cli_directory_offset + 4)
        if self.cli_header_rva == 0 or self.cli_header_size == 0:
            raise PatchError("CLI data directory is empty")

        section_offset = optional_offset + optional_header_size
        require_range(self.data, section_offset, number_of_sections * 40, "section table")
        for index in range(number_of_sections):
            offset = section_offset + (index * 40)
            raw_name = bytes(self.data[offset : offset + 8]).split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size = u32(self.data, offset + 8)
            virtual_address = u32(self.data, offset + 12)
            raw_size = u32(self.data, offset + 16)
            raw_offset = u32(self.data, offset + 20)
            self.sections.append(
                Section(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                )
            )

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            section_size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + section_size:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise PatchError(
                        f"RVA 0x{rva:x} maps past raw data for section {section.name}"
                    )
                offset = section.raw_offset + delta
                require_range(self.data, offset, 1, f"RVA 0x{rva:x}")
                return offset
        raise PatchError(f"RVA 0x{rva:x} is not in any section")

    def cli_header_offset(self) -> int:
        offset = self.rva_to_offset(self.cli_header_rva)
        require_range(self.data, offset, min(self.cli_header_size, 72), "CLI header")
        return offset


def parse_method_body(data: bytes | bytearray, offset: int) -> tuple[int, int, int]:
    require_range(data, offset, 1, "method header")
    first = data[offset]

    if (first & 0x3) == 0x2:
        header_size = 1
        code_size = first >> 2
        code_offset = offset + header_size
        require_range(data, code_offset, code_size, "tiny method body")
        return header_size, code_size, code_offset

    if (first & 0x3) != 0x3:
        raise PatchError(f"unknown method header format byte 0x{first:02x}")

    require_range(data, offset, 12, "fat method header")
    flags_and_size = u16(data, offset)
    header_size_dwords = (flags_and_size >> 12) & 0xF
    header_size = header_size_dwords * 4
    if header_size < 12:
        raise PatchError(f"invalid fat method header size {header_size}")
    code_size = u32(data, offset + 4)
    code_offset = offset + header_size
    require_range(data, code_offset, code_size, "fat method body")
    return header_size, code_size, code_offset


def patch_ready_to_run(data: bytearray, image: PEImage) -> Result:
    cli_offset = image.cli_header_offset()
    managed_native_header_offset = cli_offset + 64
    require_range(data, managed_native_header_offset, 8, "managed native header directory")

    rva = u32(data, managed_native_header_offset)
    size = u32(data, managed_native_header_offset + 4)
    if rva == 0 and size == 0:
        return Result("ReadyToRun managed native header", "already", "already cleared")

    data[managed_native_header_offset : managed_native_header_offset + 8] = b"\0" * 8
    return Result(
        "ReadyToRun managed native header",
        "patch",
        f"clear RVA 0x{rva:x}, size {size}",
    )


def apply_method_patch(data: bytearray, image: PEImage, patch: MethodPatch) -> Result:
    try:
        method_offset = image.rva_to_offset(patch.rva)
        header_size, code_size, code_offset = parse_method_body(data, method_offset)
    except PatchError as exc:
        return Result(patch.name, "attention", str(exc))

    if header_size != patch.expected_header_size:
        return Result(
            patch.name,
            "attention",
            (
                "method shape changed: "
                f"header {header_size} bytes, code {code_size} bytes; "
                f"expected header {patch.expected_header_size}, "
                f"code {patch.expected_code_size}"
            ),
        )

    if len(patch.patch_bytes) > code_size:
        return Result(
            patch.name,
            "attention",
            (
                f"patch is {len(patch.patch_bytes)} bytes but method body is only "
                f"{code_size} bytes at RVA 0x{patch.rva:x}"
            ),
        )

    # Most target methods have no exception-handling data after their IL body.
    # For those methods, replace the body and shrink the fat header's CodeSize
    # to the exact replacement length.  .NET 10 can reject an early-return body
    # when the header still declares the old trailing bytes (even if those bytes
    # are NOP padding), so the unused space must be outside the declared IL body.
    #
    # Methods with CorILMethod_MoreSects set have EH clauses whose offsets are
    # tied to the original body, so they keep their deliberately crafted
    # prefix-only patches instead.
    has_extra_sections = False
    if header_size != 1:
        has_extra_sections = bool(u16(data, method_offset) & 0x8)

    if not has_extra_sections:
        # Compact patched form: the method header already declares exactly the
        # replacement bytes as its IL body.
        if code_size == len(patch.patch_bytes):
            current_code = bytes(data[code_offset : code_offset + code_size])
            if current_code == patch.patch_bytes:
                return Result(patch.name, "already", f"RVA 0x{patch.rva:x}")
            return Result(
                patch.name,
                "attention",
                (
                    f"unexpected compact method bytes at RVA 0x{patch.rva:x}; "
                    f"found {current_code.hex()}"
                ),
            )

        if code_size != patch.expected_code_size:
            return Result(
                patch.name,
                "attention",
                (
                    "method shape changed: "
                    f"header {header_size} bytes, code {code_size} bytes; "
                    f"expected header {patch.expected_header_size}, "
                    f"code {patch.expected_code_size} (or compact patched size "
                    f"{len(patch.patch_bytes)})"
                ),
            )

        current_code = bytes(data[code_offset : code_offset + code_size])
        if current_code == patch.patch_bytes:
            return Result(patch.name, "already", f"RVA 0x{patch.rva:x}")

        # Accept both previous patch forms as upgrade paths: the old short-prefix
        # patch and the later full-size NOP-padded body.  This lets an installed
        # DLL be repaired without first restoring the original file.
        legacy_prefix_patch = current_code.startswith(patch.patch_bytes)
        if not legacy_prefix_patch:
            current_prefix = bytes(
                data[code_offset : code_offset + len(patch.original_prefix)]
            )
            if current_prefix != patch.original_prefix:
                return Result(
                    patch.name,
                    "attention",
                    (
                        f"unexpected method bytes at RVA 0x{patch.rva:x}; "
                        f"found {current_prefix.hex()}"
                    ),
                )

        data[code_offset : code_offset + len(patch.patch_bytes)] = patch.patch_bytes
        data[
            code_offset + len(patch.patch_bytes) : code_offset + code_size
        ] = b"\x00" * (code_size - len(patch.patch_bytes))

        # All non-EH targets in this patch table use fat method headers.  Keep
        # the existing header/metadata in place and only shrink the declared IL
        # byte count.  The following bytes remain harmless alignment/padding.
        if header_size == 1:
            return Result(
                patch.name,
                "attention",
                "cannot compact a tiny-header method in place",
            )
        struct.pack_into("<I", data, method_offset + 4, len(patch.patch_bytes))
        detail = f"RVA 0x{patch.rva:x}"
        if legacy_prefix_patch:
            detail += " (upgrade previous patch form)"
        return Result(patch.name, "patch", detail)

    if code_size != patch.expected_code_size:
        return Result(
            patch.name,
            "attention",
            (
                "method shape changed: "
                f"header {header_size} bytes, code {code_size} bytes; "
                f"expected header {patch.expected_header_size}, "
                f"code {patch.expected_code_size}"
            ),
        )

    current_patch = bytes(data[code_offset : code_offset + len(patch.patch_bytes)])
    if current_patch == patch.patch_bytes:
        return Result(patch.name, "already", f"RVA 0x{patch.rva:x}")

    current_prefix = bytes(data[code_offset : code_offset + len(patch.original_prefix)])
    if current_prefix != patch.original_prefix:
        return Result(
            patch.name,
            "attention",
            (
                f"unexpected method bytes at RVA 0x{patch.rva:x}; "
                f"found {current_prefix.hex()}"
            ),
        )

    data[code_offset : code_offset + len(patch.patch_bytes)] = patch.patch_bytes
    return Result(patch.name, "patch", f"RVA 0x{patch.rva:x}")


def default_output_for(input_path: Path) -> Path:
    if input_path.name.lower() == DLL_NAME.lower():
        return input_path.with_name(PATCHED_DLL_NAME)
    return input_path.with_name(f"{input_path.stem}.patched{input_path.suffix}")


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.input_path and args.input:
        raise PatchError("pass the input DLL either positionally or with --input, not both")

    script_dir = Path(__file__).resolve().parent
    input_arg = args.input_path or args.input
    input_path = (
        Path(input_arg).expanduser().resolve()
        if input_arg
        else (script_dir / DLL_NAME).resolve()
    )

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else default_output_for(input_path).resolve()
    )

    if input_path == output_path:
        raise PatchError("input and output must be different files")

    return input_path, output_path


def print_results(results: list[Result], dry_run: bool) -> None:
    label_for = {
        "already": "already",
        "patch": "would patch" if dry_run else "patch",
        "attention": "attention",
    }

    for result in results:
        label = label_for.get(result.status, result.status)
        print(f"[{label:11}] {result.name} - {result.detail}")

    already = sum(1 for result in results if result.status == "already")
    to_patch = sum(1 for result in results if result.status == "patch")
    attention = sum(1 for result in results if result.status == "attention")
    print()
    print(
        "Summary: "
        f"{already} already patched, {to_patch} to patch, {attention} need attention."
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read an original OFT.Platform.Core.dll and write a patched copy."
    )
    parser.add_argument(
        "input",
        nargs="?",
        help=f"Original DLL to patch. Defaults to {DLL_NAME} beside this script.",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input_path",
        help="Original DLL to patch. Alternative to the positional input.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help=(
            f"Patched DLL to write. Defaults to {PATCHED_DLL_NAME} when the input "
            f"is {DLL_NAME}, otherwise '<input>.patched.dll'."
        ),
    )
    parser.add_argument(
        "--dry-run",
        "--check",
        dest="dry_run",
        action="store_true",
        help="Report status without writing changes.",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        input_path, output_path = resolve_paths(args)
    except PatchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Input:  {input_path}")
    if not args.dry_run:
        print(f"Output: {output_path}")
    print(f"Mode:   {'check only' if args.dry_run else 'write patched copy'}")
    print()

    if not input_path.exists():
        print(f"error: input does not exist: {input_path}", file=sys.stderr)
        return 2

    try:
        original_data = input_path.read_bytes()
        patched_data = bytearray(original_data)
        image = PEImage(patched_data)
    except (OSError, PatchError, struct.error) as exc:
        print(f"error: could not read/parse input: {exc}", file=sys.stderr)
        return 2

    results: list[Result] = []
    try:
        results.append(patch_ready_to_run(patched_data, image))
    except (PatchError, struct.error) as exc:
        results.append(
            Result("ReadyToRun managed native header", "attention", str(exc))
        )

    for patch in PATCHES:
        results.append(apply_method_patch(patched_data, image, patch))

    print_results(results, args.dry_run)

    attention_count = sum(1 for result in results if result.status == "attention")
    patch_count = sum(1 for result in results if result.status == "patch")

    if attention_count:
        print()
        print("No changes written because at least one check needs attention.")
        return 2

    if args.dry_run:
        print()
        print("Dry run only; no changes written.")
        return 0

    if output_path.exists():
        try:
            if output_path.read_bytes() == patched_data:
                print()
                print(f"Output already up to date: {output_path}")
                return 0
        except OSError as exc:
            print()
            print(f"error: could not read existing output: {exc}", file=sys.stderr)
            return 3

    if patch_count == 0 and not output_path.exists():
        print()
        print("Input is already patched; writing a copy anyway.")

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(patched_data)
    except PermissionError as exc:
        print()
        print(f"error: permission denied while writing {output_path}: {exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print()
        print(f"error: could not write patched DLL: {exc}", file=sys.stderr)
        return 3

    print()
    print(f"Wrote patched DLL: {output_path}")
    if patch_count == 0:
        print("Input already contained the patch; output is a copy of that patched input.")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
