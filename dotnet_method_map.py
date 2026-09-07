#!/usr/bin/env python3
"""Resolve .NET MethodDef metadata without loading the target assembly.

This is intentionally a read-only utility.  Given one or more fully-qualified
``Type::Method`` names, it prints the current metadata token, RVA, method-body
shape, signature blob, and an IL prefix.  It is useful when a rebuilt assembly
moves method bodies or renumbers metadata tokens between releases.

No third-party packages are required.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from pathlib import Path


class MetadataError(Exception):
    pass


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def require_range(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise MetadataError(f"{what} is outside the file")


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclasses.dataclass(frozen=True)
class MethodDef:
    rid: int
    owner: str
    name: str
    rva: int
    signature_index: int

    @property
    def token(self) -> int:
        return 0x06000000 | self.rid


@dataclasses.dataclass(frozen=True)
class MethodInfo:
    method: MethodDef
    header_size: int
    code_size: int
    il_prefix: bytes
    signature: bytes


class PEImage:
    def __init__(self, data: bytes):
        self.data = data
        self.sections: list[Section] = []
        self.cli_header_rva = 0
        self.cli_header_size = 0
        self._parse()

    def _parse(self) -> None:
        data = self.data
        require_range(data, 0, 0x40, "DOS header")
        if data[:2] != b"MZ":
            raise MetadataError("missing MZ signature")

        pe_offset = u32(data, 0x3C)
        require_range(data, pe_offset, 24, "PE header")
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise MetadataError("missing PE signature")

        number_of_sections = u16(data, pe_offset + 6)
        optional_header_size = u16(data, pe_offset + 20)
        optional_offset = pe_offset + 24
        require_range(data, optional_offset, optional_header_size, "optional header")

        magic = u16(data, optional_offset)
        if magic == 0x10B:
            data_directory_offset = optional_offset + 96
        elif magic == 0x20B:
            data_directory_offset = optional_offset + 112
        else:
            raise MetadataError(f"unsupported PE optional-header magic 0x{magic:04x}")

        cli_directory_offset = data_directory_offset + (14 * 8)
        require_range(data, cli_directory_offset, 8, "CLI data directory")
        self.cli_header_rva = u32(data, cli_directory_offset)
        self.cli_header_size = u32(data, cli_directory_offset + 4)
        if not self.cli_header_rva or not self.cli_header_size:
            raise MetadataError("file has no CLI header")

        section_offset = optional_offset + optional_header_size
        require_range(data, section_offset, number_of_sections * 40, "section table")
        for index in range(number_of_sections):
            offset = section_offset + index * 40
            raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
            self.sections.append(
                Section(
                    name=raw_name.decode("ascii", errors="replace"),
                    virtual_size=u32(data, offset + 8),
                    virtual_address=u32(data, offset + 12),
                    raw_size=u32(data, offset + 16),
                    raw_offset=u32(data, offset + 20),
                )
            )

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            section_size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + section_size:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise MetadataError(
                        f"RVA 0x{rva:x} maps past raw data for section {section.name}"
                    )
                offset = section.raw_offset + delta
                require_range(self.data, offset, 1, f"RVA 0x{rva:x}")
                return offset
        raise MetadataError(f"RVA 0x{rva:x} is not in a PE section")

    def cli_header_offset(self) -> int:
        offset = self.rva_to_offset(self.cli_header_rva)
        require_range(self.data, offset, min(self.cli_header_size, 72), "CLI header")
        return offset


def parse_method_body(data: bytes, offset: int) -> tuple[int, int, int]:
    require_range(data, offset, 1, "method body")
    first = data[offset]

    if (first & 0x3) == 0x2:
        header_size = 1
        code_size = first >> 2
        code_offset = offset + 1
        require_range(data, code_offset, code_size, "tiny method body")
        return header_size, code_size, code_offset

    if (first & 0x3) != 0x3:
        raise MetadataError(f"unknown method-header byte 0x{first:02x}")

    require_range(data, offset, 12, "fat method header")
    flags_and_size = u16(data, offset)
    header_size = ((flags_and_size >> 12) & 0xF) * 4
    if header_size < 12:
        raise MetadataError(f"invalid fat method-header size {header_size}")
    code_size = u32(data, offset + 4)
    code_offset = offset + header_size
    require_range(data, code_offset, code_size, "fat method body")
    return header_size, code_size, code_offset


class CliMetadata:
    def __init__(self, data: bytes, image: PEImage):
        self.data = data
        self.image = image
        self.row_counts = [0] * 64
        self.table_offsets: dict[int, int] = {}
        self.streams: dict[str, tuple[int, int]] = {}
        self.string_index_size = 2
        self.guid_index_size = 2
        self.blob_index_size = 2
        self._parse_root()
        self._parse_tables_header()

    def _parse_root(self) -> None:
        cli = self.image.cli_header_offset()
        metadata_rva = u32(self.data, cli + 8)
        metadata_size = u32(self.data, cli + 12)
        if not metadata_rva or not metadata_size:
            raise MetadataError("CLI metadata directory is empty")

        root = self.image.rva_to_offset(metadata_rva)
        require_range(self.data, root, 20, "metadata root")
        if self.data[root : root + 4] != b"BSJB":
            raise MetadataError("invalid CLI metadata signature")

        version_length = u32(self.data, root + 12)
        cursor = root + 16 + version_length
        cursor = (cursor + 3) & ~3
        require_range(self.data, cursor, 4, "metadata stream header")
        stream_count = u16(self.data, cursor + 2)
        cursor += 4

        for _ in range(stream_count):
            require_range(self.data, cursor, 9, "metadata stream")
            relative_offset = u32(self.data, cursor)
            size = u32(self.data, cursor + 4)
            name_start = cursor + 8
            try:
                name_end = self.data.index(0, name_start)
            except ValueError as exc:
                raise MetadataError("unterminated metadata stream name") from exc
            name = self.data[name_start:name_end].decode("ascii", errors="replace")
            name_size = name_end - name_start + 1
            cursor = name_start + ((name_size + 3) & ~3)
            self.streams[name] = (root + relative_offset, size)

        if "#Strings" not in self.streams or "#Blob" not in self.streams:
            raise MetadataError("required #Strings/#Blob metadata heaps are missing")
        if "#~" not in self.streams and "#-" not in self.streams:
            raise MetadataError("metadata tables stream is missing")

    def _parse_tables_header(self) -> None:
        tables_offset, _ = self.streams.get("#~", self.streams.get("#-", (0, 0)))
        require_range(self.data, tables_offset, 24, "metadata tables header")

        heap_sizes = self.data[tables_offset + 6]
        self.string_index_size = 4 if heap_sizes & 0x01 else 2
        self.guid_index_size = 4 if heap_sizes & 0x02 else 2
        self.blob_index_size = 4 if heap_sizes & 0x04 else 2

        valid_mask = u64(self.data, tables_offset + 8)
        cursor = tables_offset + 24
        for table_id in range(64):
            if valid_mask & (1 << table_id):
                require_range(self.data, cursor, 4, "metadata row count")
                self.row_counts[table_id] = u32(self.data, cursor)
                cursor += 4

        table_data = cursor
        current = table_data
        # MethodDef is table 6.  We only need to size tables 0..6 to locate it.
        for table_id in range(7):
            self.table_offsets[table_id] = current
            current += self.row_counts[table_id] * self._row_size(table_id)

    def _table_index_size(self, table_id: int) -> int:
        return 2 if self.row_counts[table_id] < 0x10000 else 4

    def _coded_index_size(self, table_ids: list[int], tag_bits: int) -> int:
        limit = 1 << (16 - tag_bits)
        largest = max(self.row_counts[table_id] for table_id in table_ids)
        return 2 if largest < limit else 4

    def _row_size(self, table_id: int) -> int:
        string = self.string_index_size
        guid = self.guid_index_size
        blob = self.blob_index_size

        if table_id == 0:  # Module
            return 2 + string + guid + guid + guid
        if table_id == 1:  # TypeRef
            resolution_scope = self._coded_index_size([0, 26, 35, 1], 2)
            return resolution_scope + string + string
        if table_id == 2:  # TypeDef
            typedef_or_ref = self._coded_index_size([2, 1, 27], 2)
            return (
                4
                + string
                + string
                + typedef_or_ref
                + self._table_index_size(4)
                + self._table_index_size(6)
            )
        if table_id == 3:  # FieldPtr
            return self._table_index_size(4)
        if table_id == 4:  # Field
            return 2 + string + blob
        if table_id == 5:  # MethodPtr
            return self._table_index_size(6)
        if table_id == 6:  # MethodDef
            return 4 + 2 + 2 + string + blob + self._table_index_size(8)
        raise MetadataError(f"unsupported metadata table {table_id}")

    def _read_index(self, offset: int, size: int) -> int:
        return u16(self.data, offset) if size == 2 else u32(self.data, offset)

    def string_at(self, index: int) -> str:
        if index == 0:
            return ""
        base, size = self.streams["#Strings"]
        if index >= size:
            raise MetadataError(f"#Strings index 0x{index:x} is out of range")
        try:
            end = self.data.index(0, base + index, base + size)
        except ValueError as exc:
            raise MetadataError("unterminated #Strings entry") from exc
        return self.data[base + index : end].decode("utf-8", errors="replace")

    def blob_at(self, index: int) -> bytes:
        if index == 0:
            return b""
        base, size = self.streams["#Blob"]
        if index >= size:
            raise MetadataError(f"#Blob index 0x{index:x} is out of range")
        length, prefix_size = self._compressed_uint(base + index, base + size)
        start = base + index + prefix_size
        require_range(self.data, start, length, "#Blob entry")
        return self.data[start : start + length]

    def _compressed_uint(self, offset: int, end: int) -> tuple[int, int]:
        if offset >= end:
            raise MetadataError("truncated compressed integer")
        first = self.data[offset]
        if first & 0x80 == 0:
            return first, 1
        if first & 0xC0 == 0x80:
            if offset + 2 > end:
                raise MetadataError("truncated 2-byte compressed integer")
            return ((first & 0x3F) << 8) | self.data[offset + 1], 2
        if first & 0xE0 == 0xC0:
            if offset + 4 > end:
                raise MetadataError("truncated 4-byte compressed integer")
            value = (
                ((first & 0x1F) << 24)
                | (self.data[offset + 1] << 16)
                | (self.data[offset + 2] << 8)
                | self.data[offset + 3]
            )
            return value, 4
        raise MetadataError("invalid compressed integer")

    def typedefs(self) -> list[tuple[int, str, int]]:
        row_size = self._row_size(2)
        row_base = self.table_offsets[2]
        extends_size = self._coded_index_size([2, 1, 27], 2)
        field_index_size = self._table_index_size(4)
        method_index_size = self._table_index_size(6)
        output: list[tuple[int, str, int]] = []

        for rid in range(1, self.row_counts[2] + 1):
            cursor = row_base + (rid - 1) * row_size + 4
            name_index = self._read_index(cursor, self.string_index_size)
            cursor += self.string_index_size
            namespace_index = self._read_index(cursor, self.string_index_size)
            cursor += self.string_index_size
            cursor += extends_size + field_index_size
            method_list = self._read_index(cursor, method_index_size)

            name = self.string_at(name_index)
            namespace = self.string_at(namespace_index)
            full_name = f"{namespace}.{name}" if namespace else name
            output.append((rid, full_name, method_list))

        return output

    def methods(self) -> list[MethodDef]:
        typedefs = self.typedefs()
        owner_by_method: dict[int, str] = {}
        for index, (_, owner, first_method) in enumerate(typedefs):
            next_method = (
                typedefs[index + 1][2]
                if index + 1 < len(typedefs)
                else self.row_counts[6] + 1
            )
            for method_rid in range(first_method, next_method):
                owner_by_method[method_rid] = owner

        row_size = self._row_size(6)
        row_base = self.table_offsets[6]
        param_index_size = self._table_index_size(8)
        output: list[MethodDef] = []

        for rid in range(1, self.row_counts[6] + 1):
            cursor = row_base + (rid - 1) * row_size
            rva = u32(self.data, cursor)
            cursor += 8  # RVA + ImplFlags + Flags
            name_index = self._read_index(cursor, self.string_index_size)
            cursor += self.string_index_size
            signature_index = self._read_index(cursor, self.blob_index_size)
            cursor += self.blob_index_size + param_index_size
            output.append(
                MethodDef(
                    rid=rid,
                    owner=owner_by_method.get(rid, "<unknown>"),
                    name=self.string_at(name_index),
                    rva=rva,
                    signature_index=signature_index,
                )
            )
        return output


def split_symbol(value: str) -> tuple[str, str]:
    if "::" not in value:
        raise argparse.ArgumentTypeError("symbol must use Full.Namespace.Type::Method")
    owner, method = value.rsplit("::", 1)
    if not owner or not method:
        raise argparse.ArgumentTypeError("symbol must use Full.Namespace.Type::Method")
    return owner, method


def load_symbols_file(path_value: str) -> list[tuple[str, str]]:
    path = Path(path_value).expanduser().resolve()
    try:
        # utf-8-sig accepts both ordinary UTF-8 and the BOM-prefixed UTF-8 that
        # Windows PowerShell 5.1 writes with ``Set-Content -Encoding UTF8``.
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise MetadataError(f"could not read symbols file {path}: {exc}") from exc

    symbols: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            symbols.append(split_symbol(line))
        except argparse.ArgumentTypeError as exc:
            raise MetadataError(
                f"{path}:{line_number}: {exc}"
            ) from exc
    return symbols


def method_info(
    data: bytes,
    image: PEImage,
    metadata: CliMetadata,
    method: MethodDef,
    prefix_bytes: int,
) -> MethodInfo:
    if method.rva == 0:
        raise MetadataError("method has no IL body (RVA is zero)")
    method_offset = image.rva_to_offset(method.rva)
    header_size, code_size, code_offset = parse_method_body(data, method_offset)
    prefix_size = min(prefix_bytes, code_size)
    return MethodInfo(
        method=method,
        header_size=header_size,
        code_size=code_size,
        il_prefix=data[code_offset : code_offset + prefix_size],
        signature=metadata.blob_at(method.signature_index),
    )


def as_record(info: MethodInfo) -> dict[str, object]:
    return {
        "type": info.method.owner,
        "method": info.method.name,
        "token": f"0x{info.method.token:08X}",
        "rid": info.method.rid,
        "rva": f"0x{info.method.rva:X}",
        "header_size": info.header_size,
        "code_size": info.code_size,
        "signature": info.signature.hex(),
        "il_prefix": info.il_prefix.hex(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve .NET MethodDef RVAs and method-body metadata directly from a DLL."
        )
    )
    parser.add_argument("assembly", help="Path to a managed PE/.NET assembly")
    parser.add_argument(
        "-s",
        "--symbol",
        action="append",
        type=split_symbol,
        metavar="TYPE::METHOD",
        help="Exact fully-qualified Type::Method to resolve; may be repeated.",
    )
    parser.add_argument(
        "--symbols-file",
        action="append",
        metavar="PATH",
        help=(
            "Read Type::Method entries from a UTF-8 text file; blank lines and "
            "lines beginning with # are ignored. May be repeated."
        ),
    )
    parser.add_argument(
        "--prefix-bytes",
        type=int,
        default=16,
        help="Number of IL bytes to include from each method body (default: 16).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a text table.",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.prefix_bytes < 0:
        parser.error("--prefix-bytes must be >= 0")

    requested_symbols: list[tuple[str, str]] = list(args.symbol or [])
    try:
        for symbols_file in args.symbols_file or []:
            requested_symbols.extend(load_symbols_file(symbols_file))
    except MetadataError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not requested_symbols:
        parser.error("pass at least one --symbol or --symbols-file")

    path = Path(args.assembly).expanduser().resolve()
    try:
        data = path.read_bytes()
        image = PEImage(data)
        metadata = CliMetadata(data, image)
        methods = metadata.methods()
    except (OSError, MetadataError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    by_symbol: dict[tuple[str, str], list[MethodDef]] = {}
    for method in methods:
        by_symbol.setdefault((method.owner, method.name), []).append(method)

    records: list[dict[str, object]] = []
    missing: list[str] = []
    for owner, method_name in requested_symbols:
        matches = by_symbol.get((owner, method_name), [])
        if not matches:
            missing.append(f"{owner}::{method_name}")
            continue
        for method in matches:
            try:
                records.append(
                    as_record(method_info(data, image, metadata, method, args.prefix_bytes))
                )
            except (MetadataError, struct.error) as exc:
                records.append(
                    {
                        "type": owner,
                        "method": method_name,
                        "token": f"0x{method.token:08X}",
                        "rid": method.rid,
                        "rva": f"0x{method.rva:X}",
                        "error": str(exc),
                    }
                )

    if args.json:
        print(json.dumps({"assembly": str(path), "methods": records}, indent=2))
    else:
        for record in records:
            symbol = f"{record['type']}::{record['method']}"
            print(symbol)
            print(
                f"  token={record['token']}  rva={record['rva']}  "
                f"header={record.get('header_size', '?')}  code={record.get('code_size', '?')}"
            )
            if "error" in record:
                print(f"  error={record['error']}")
            else:
                print(f"  signature={record['signature']}")
                print(f"  il_prefix={record['il_prefix']}")

    for symbol in missing:
        print(f"not found: {symbol}", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
