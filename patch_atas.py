#!/usr/bin/env python3
"""
- it validates the PE/CLI layout;
- it resolves patch targets from .NET metadata on every run;
- it guards relative lookups for obfuscated helpers with structural checks;
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

from dotnet_method_map import CliMetadata, MetadataError, method_info


DLL_NAME = "OFT.Platform.Core.dll"
PATCHED_DLL_NAME = "OFT.Platform.Core.patched.dll"
CORE_DLL_NAME = "OFT.Core.dll"
PATCHED_CORE_DLL_NAME = "OFT.Core.patched.dll"


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


@dataclasses.dataclass(frozen=True)
class PatchSpec:
    name: str
    owner: str
    method: str
    patch_bytes: bytes
    relative_rid: int = 0
    require_obfuscated: bool = False
    expected_parameter_count: int | None = None
    expected_return_element: int | None = None


@dataclasses.dataclass
class Result:
    name: str
    status: str
    detail: str


class PatchError(Exception):
    pass


PLATFORM_PATCH_SPECS = [
    PatchSpec(
        "PayWallDataManager.TryCheckAllowFeature<T>",
        "OFT.Platform.Managers.PayWallDataManager",
        "TryCheckAllowFeature",
        bytes.fromhex("170bde3e"),
    ),
    PatchSpec(
        "PayWallDataManager.TryGetLimitValue<T>",
        "OFT.Platform.Managers.PayWallDataManager",
        "TryGetLimitValue",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "DefaultAwarePayWallRequestLimitCorrector<T>.TryResolveLimit",
        "OFT.Platform.Core.Marketing.DefaultAwarePayWallRequestLimitCorrector`1",
        "TryResolveLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallDataManager.HasPayWallData",
        "OFT.Platform.Managers.PayWallDataManager",
        "HasPayWallData",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallDataManager.ExistsEnabledFeature",
        "OFT.Platform.Managers.PayWallDataManager",
        "ExistsEnabledFeature",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallDataManager.ExistsFeature",
        "OFT.Platform.Managers.PayWallDataManager",
        "ExistsFeature",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.IsLimited<T>",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "IsLimited",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfLimit<T>",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "LicenseInformationViewModelBase.get_IsLicenseExpired",
        "OFT.Platform.Core.ViewModels.LicenseInformation.LicenseInformationViewModelBase",
        "get_IsLicenseExpired",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "LicenseState.get_IsLicenseExpired",
        "OFT.Platform.ViewModels.LicenseState",
        "get_IsLicenseExpired",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "LicenseState.get_IsLicenseExpiredMessageError",
        "OFT.Platform.ViewModels.LicenseState",
        "get_IsLicenseExpiredMessageError",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "LicenseState.get_ShowAlert",
        "OFT.Platform.ViewModels.LicenseState",
        "get_ShowAlert",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "AuthorizationViewModel.get_IsAuthorized",
        "OFT.Platform.ViewModels.Connections.AuthorizationViewModel",
        "get_IsAuthorized",
        bytes.fromhex("172a"),
    ),
    PatchSpec(
        "AgentDataAccess.get_IsAllowed",
        "OFT.Platform.Services.AIConnect.AgentDataAccess",
        "get_IsAllowed",
        bytes.fromhex("172a"),
    ),
    PatchSpec(
        "ConnectorsManager.connection-license check",
        "OFT.Platform.Core.Managers.Connections.ConnectorsManager",
        "EnsureMarketDataConnectorExistsAsync",
        bytes.fromhex("172a"),
        relative_rid=8,
        require_obfuscated=True,
        expected_parameter_count=1,
        expected_return_element=0x02,
    ),
    PatchSpec(
        "ConnectorPayWallRestrictions.category-active-limit mapper",
        "OFT.Platform.Core.Services.ConnectorPayWallRestrictions",
        "GetLimitAddFromCategory",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "SelectConnectorTypeViewModel.server-feature predicate",
        "OFT.Platform.ViewModels.Connections.SelectConnectorTypeViewModel",
        "InitializeAsync",
        bytes.fromhex("172a"),
        relative_rid=2,
        require_obfuscated=True,
        expected_parameter_count=1,
        expected_return_element=0x02,
    ),
    PatchSpec(
        "PlatformViewExtensions.ShowConnectorLimitedMessage",
        "OFT.Platform.Core.Extensions.PlatformViewExtensions",
        "ShowConnectorLimitedMessage",
        bytes.fromhex("28210a000a2a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfEnabledLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfEnabledLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfExistsLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfExistsLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfHeatmapsCountLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfHeatmapsCountLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfIndicatorsPerHeatmapLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfIndicatorsPerHeatmapLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.ShowIfIndicatorsPerChartLimit",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfIndicatorsPerChartLimit",
        bytes.fromhex("162a"),
    ),
    PatchSpec(
        "PayWallExtensions.indicator-count helper",
        "OFT.Platform.Core.Extensions.PayWallExtensions",
        "ShowIfIndicatorsPerChartLimit",
        bytes.fromhex("162a"),
        relative_rid=1,
        require_obfuscated=True,
        expected_parameter_count=3,
        expected_return_element=0x02,
    ),
]


CORE_PATCH_SPECS = [
    PatchSpec(
        "RequestLimitCorrector.TryGetLimit<TRequest>",
        "OFT.Core.DataProvider.RequestLimitCorrector",
        "TryGetLimit",
        bytes.fromhex("162a"),
    ),
]


PATCH_SPECS_BY_DLL = {
    DLL_NAME.lower(): PLATFORM_PATCH_SPECS,
    PATCHED_DLL_NAME.lower(): PLATFORM_PATCH_SPECS,
    CORE_DLL_NAME.lower(): CORE_PATCH_SPECS,
    PATCHED_CORE_DLL_NAME.lower(): CORE_PATCH_SPECS,
}


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


def _compressed_uint_from_blob(blob: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(blob):
        raise PatchError("truncated method signature")
    first = blob[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        if offset + 2 > len(blob):
            raise PatchError("truncated method signature")
        return ((first & 0x3F) << 8) | blob[offset + 1], offset + 2
    if first & 0xE0 == 0xC0:
        if offset + 4 > len(blob):
            raise PatchError("truncated method signature")
        value = (
            ((first & 0x1F) << 24)
            | (blob[offset + 1] << 16)
            | (blob[offset + 2] << 8)
            | blob[offset + 3]
        )
        return value, offset + 4
    raise PatchError("invalid compressed integer in method signature")


def _signature_summary(signature: bytes) -> tuple[int, int]:
    if not signature:
        raise PatchError("method has an empty metadata signature")
    call_convention = signature[0]
    cursor = 1
    if call_convention & 0x10:  # IMAGE_CEE_CS_CALLCONV_GENERIC
        _, cursor = _compressed_uint_from_blob(signature, cursor)
    parameter_count, cursor = _compressed_uint_from_blob(signature, cursor)
    if cursor >= len(signature):
        raise PatchError("method signature has no return type")

    # Custom modifiers and pinned/sentinel markers are not expected on these
    # return values.  Keeping this check intentionally small means metadata token
    # renumbering in parameter types does not invalidate an otherwise stable
    # target between releases.
    return_element = signature[cursor]
    return parameter_count, return_element


def resolve_patches(
    data: bytes | bytearray,
    image: PEImage,
    specs: list[PatchSpec],
) -> list[MethodPatch]:
    """Resolve release-specific MethodDef values from the current assembly.

    Stable targets are found by TypeDef + MethodDef name.  A few obfuscated
    helpers are located by a stable neighboring MethodDef and a small RID delta;
    those relative lookups are guarded by owner/name/signature checks so a
    changed layout fails closed instead of patching the wrong method.
    """

    try:
        metadata = CliMetadata(data, image)
        methods = metadata.methods()
    except (MetadataError, struct.error) as exc:
        raise PatchError(f"could not parse CLI metadata: {exc}") from exc

    by_symbol: dict[tuple[str, str], list[object]] = {}
    by_rid = {method.rid: method for method in methods}
    for method in methods:
        by_symbol.setdefault((method.owner, method.name), []).append(method)

    resolved: list[MethodPatch] = []
    for spec in specs:
        anchors = by_symbol.get((spec.owner, spec.method), [])
        if len(anchors) != 1:
            raise PatchError(
                f"{spec.name}: expected exactly one metadata anchor "
                f"{spec.owner}::{spec.method}, found {len(anchors)}"
            )

        anchor = anchors[0]
        target_rid = anchor.rid + spec.relative_rid
        target = by_rid.get(target_rid)
        if target is None:
            raise PatchError(
                f"{spec.name}: MethodDef RID {target_rid} does not exist "
                f"(anchor RID {anchor.rid}, delta {spec.relative_rid:+d})"
            )
        if target.owner != spec.owner:
            raise PatchError(
                f"{spec.name}: relative target moved outside {spec.owner}; "
                f"found owner {target.owner} at RID {target_rid}"
            )
        if spec.require_obfuscated and not target.name.startswith("#="):
            raise PatchError(
                f"{spec.name}: relative target is no longer obfuscated; "
                f"found {target.name!r} at RID {target_rid}"
            )

        try:
            info = method_info(data, image, metadata, target, 16)
        except (MetadataError, struct.error) as exc:
            raise PatchError(f"{spec.name}: could not read method body: {exc}") from exc

        if spec.expected_parameter_count is not None or spec.expected_return_element is not None:
            parameter_count, return_element = _signature_summary(info.signature)
            if (
                spec.expected_parameter_count is not None
                and parameter_count != spec.expected_parameter_count
            ):
                raise PatchError(
                    f"{spec.name}: relative target signature changed; "
                    f"expected {spec.expected_parameter_count} parameters, "
                    f"found {parameter_count}"
                )
            if (
                spec.expected_return_element is not None
                and return_element != spec.expected_return_element
            ):
                raise PatchError(
                    f"{spec.name}: relative target return type changed; "
                    f"expected element 0x{spec.expected_return_element:02x}, "
                    f"found 0x{return_element:02x}"
                )

        resolved.append(
            MethodPatch(
                name=spec.name,
                rva=target.rva,
                expected_header_size=info.header_size,
                expected_code_size=info.code_size,
                original_prefix=info.il_prefix,
                patch_bytes=spec.patch_bytes,
            )
        )

    return resolved


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
    if input_path.name.lower() == CORE_DLL_NAME.lower():
        return input_path.with_name(PATCHED_CORE_DLL_NAME)
    return input_path.with_name(f"{input_path.stem}.patched{input_path.suffix}")


def patch_specs_for(input_path: Path) -> list[PatchSpec]:
    specs = PATCH_SPECS_BY_DLL.get(input_path.name.lower())
    if specs is None:
        supported = ", ".join(sorted(PATCH_SPECS_BY_DLL))
        raise PatchError(
            f"unsupported input DLL {input_path.name!r}; supported names: {supported}"
        )
    return specs


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
        description=(
            "Read an original OFT.Platform.Core.dll or OFT.Core.dll and write "
            "a patched copy."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        help=(
            f"Original DLL to patch ({DLL_NAME} or {CORE_DLL_NAME}). "
            f"Defaults to {DLL_NAME} beside this script."
        ),
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
        specs = patch_specs_for(input_path)
        patches = resolve_patches(patched_data, image, specs)
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

    for patch in patches:
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
