################################################################################################################

# Copyright (C) 2026 by Uwe Martens * www.namecoin.pro  * https://dotbit.app

################################################################################################################

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ecdsa import SECP256k1, SigningKey


DEFAULT_NAME = "642f6578616d706c65"  # 'd/example' hex encoded
NAMECOIN_MAINNET_WIF_PREFIX = 0xB4
HARDENED = 1 << 31
CURVE_ORDER = SECP256k1.order
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: index for index, char in enumerate(B58_ALPHABET)}
EXTENDED_PRIVATE_KEY_VERSIONS = {
	bytes.fromhex("0488ade4"),  # xprv (mainnet)
}

class ToolError(RuntimeError):
	pass

def b58decode(value: str) -> bytes:
	number = 0
	try:
		for char in value:
			number = number * 58 + B58_INDEX[char]
	except KeyError as exc:
		raise ValueError("Invalid Base58 character") from exc

	encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
	leading_zeroes = len(value) - len(value.lstrip("1"))
	return b"\x00" * leading_zeroes + encoded

def b58encode(value: bytes) -> str:
	number = int.from_bytes(value, "big")
	encoded = ""
	while number:
		number, remainder = divmod(number, 58)
		encoded = B58_ALPHABET[remainder] + encoded
	leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
	return "1" * leading_zeroes + encoded

def base58check_decode(value: str) -> bytes:
	raw = b58decode(value)
	if len(raw) < 5:
		raise ValueError("Base58Check value is too short")
	payload, checksum = raw[:-4], raw[-4:]
	expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	if checksum != expected:
		raise ValueError("Invalid Base58Check checksum")
	return payload

def base58check_encode(payload: bytes) -> str:
	checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
	return b58encode(payload + checksum)

def private_key_to_wif(private_key: bytes, prefix: int, compressed: bool = True) -> str:
	if len(private_key) != 32:
		raise ValueError("A private key must contain exactly 32 bytes")
	payload = bytes([prefix]) + private_key + (b"\x01" if compressed else b"")
	return base58check_encode(payload)

def decode_wif(value: str, expected_prefix: int | None = None) -> tuple[bytes, bool, int]:
	payload = base58check_decode(value)
	if len(payload) == 34 and payload[-1] == 1:
		private_key, compressed = payload[1:-1], True
	elif len(payload) == 33:
		private_key, compressed = payload[1:], False
	else:
		raise ValueError("Invalid WIF length or compression marker")

	prefix = payload[0]
	if expected_prefix is not None and prefix != expected_prefix:
		raise ValueError("WIF belongs to a different network")
	scalar = int.from_bytes(private_key, "big")
	if not 1 <= scalar < CURVE_ORDER:
		raise ValueError("WIF contains an invalid private scalar")
	return private_key, compressed, prefix

def public_keys_from_private(private_key: bytes) -> tuple[str, str]:
	signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
	point = signing_key.verifying_key.to_string()
	compressed_prefix = b"\x02" if point[-1] % 2 == 0 else b"\x03"
	compressed = (compressed_prefix + point[:32]).hex()
	uncompressed = (b"\x04" + point).hex()
	return compressed, uncompressed

def redact_error(text: str) -> str:
	text = re.sub(r"[1-9A-HJ-NP-Za-km-z]{40,}", "<redacted-base58>", text)
	text = re.sub(r"\b[0-9a-fA-F]{64,}\b", "<redacted-hex>", text)
	return text.strip()

def cli_argument(value: Any) -> str:
	if isinstance(value, bool):
		return "true" if value else "false"
	if isinstance(value, (dict, list, tuple)):
		return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
	value = str(value)
	if "\n" in value or "\r" in value:
		raise ToolError("RPC arguments must not contain line breaks")
	return value

def find_namecoin_cli() -> Path:
	candidates: list[Path] = []
	script_dir = Path(__file__).resolve().parent
	candidates.extend((script_dir / "namecoin-cli.exe", script_dir / "namecoin-cli"))

	program_files = os.environ.get("ProgramFiles")
	if program_files:
		candidates.append(Path(program_files) / "Namecoin" / "daemon" / "namecoin-cli.exe")

	for executable_name in ("namecoin-cli.exe", "namecoin-cli"):
		located = shutil.which(executable_name)
		if located:
			candidates.append(Path(located))

	for candidate in candidates:
		if candidate.is_file():
			return candidate.resolve()
	raise ToolError(
		"namecoin-cli was not found beside the script, in the standard daemon directory, or on PATH."
	)

class RpcClient:
	def __init__(self, executable: Path):
		self.executable = executable

	def call(self, method: str, *params: Any) -> Any:
		command = [str(self.executable)]
		command.extend(("-stdin", method))
		stdin = "".join(f"{cli_argument(param)}\n" for param in params)

		try:
			completed = subprocess.run(
				command,
				input=stdin,
				capture_output=True,
				text=True,
				encoding="utf-8",
				errors="replace",
				timeout=180,
				check=False,
			)
		except (OSError, subprocess.TimeoutExpired) as exc:
			raise ToolError(f"RPC call {method} failed: {exc}") from exc

		if completed.returncode != 0:
			detail = redact_error(completed.stderr or completed.stdout)
			if not detail:
				detail = f"namecoin-cli exited with code {completed.returncode}"
			raise ToolError(f"RPC call {method} failed: {detail}")

		try:
			return json.loads(completed.stdout)
		except json.JSONDecodeError as exc:
			# Never include stdout here: listdescriptors may contain private keys.
			raise ToolError(f"RPC call {method} returned invalid JSON") from exc

@dataclass(frozen=True)
class SingleKeyDescriptor:
	kind: str
	key_expression: str

	def with_key(self, key: str) -> str:
		if self.kind == "pkh":
			return f"pkh({key})"
		if self.kind == "wpkh":
			return f"wpkh({key})"
		if self.kind == "sh-wpkh":
			return f"sh(wpkh({key}))"
		if self.kind == "tr":
			return f"tr({key})"
		raise ValueError(f"Unsupported descriptor kind: {self.kind}")

def parse_single_key_descriptor(descriptor: str | None) -> SingleKeyDescriptor | None:
	if not descriptor:
		return None
	body = descriptor.split("#", 1)[0]
	if body.startswith("sh(wpkh(") and body.endswith("))"):
		key_expression = body[8:-2]
		return SingleKeyDescriptor("sh-wpkh", key_expression) if key_expression else None
	if body.startswith("wpkh(") and body.endswith(")"):
		key_expression = body[5:-1]
		return SingleKeyDescriptor("wpkh", key_expression) if key_expression else None
	if body.startswith("pkh(") and body.endswith(")"):
		key_expression = body[4:-1]
		return SingleKeyDescriptor("pkh", key_expression) if key_expression else None
	if body.startswith("tr(") and body.endswith(")"):
		key_expression = body[3:-1]
		if key_expression and "," not in key_expression:  # No Taproot script tree.
			return SingleKeyDescriptor("tr", key_expression)
	return None

def strip_key_origin(key_expression: str) -> tuple[str, str | None]:
	if not key_expression.startswith("["):
		return key_expression, None
	closing = key_expression.find("]")
	if closing == -1:
		raise ValueError("Unterminated descriptor key origin")
	origin = key_expression[1:closing]
	if not re.fullmatch(r"[0-9a-fA-F]{8}(?:/[0-9]+[hH']?)*", origin):
		raise ValueError("Invalid descriptor key origin")
	return key_expression[closing + 1 :], origin

@dataclass(frozen=True)
class DerivationStep:
	index: int | None
	hardened: bool

def parse_derivation_suffix(suffix: str) -> tuple[DerivationStep, ...]:
	if not suffix:
		return ()
	if not suffix.startswith("/"):
		raise ValueError("Derivation suffix must start with a slash")

	result: list[DerivationStep] = []
	for component in suffix[1:].split("/"):
		if not component:
			raise ValueError("Empty derivation path component")
		hardened = component.endswith(("h", "H", "'"))
		core = component[:-1] if hardened else component
		if core == "*":
			result.append(DerivationStep(None, hardened))
			continue
		if not re.fullmatch(r"[0-9]+", core):
			raise ValueError(f"Unsupported derivation component: {component}")
		index = int(core)
		if not 0 <= index < HARDENED:
			raise ValueError("Derivation index is out of range")
		result.append(DerivationStep(index, hardened))

	wildcard_positions = [i for i, step in enumerate(result) if step.index is None]
	if len(wildcard_positions) > 1 or (wildcard_positions and wildcard_positions[0] != len(result) - 1):
		raise ValueError("Only one trailing descriptor wildcard is supported")
	return tuple(result)

@dataclass(frozen=True)
class ExtendedPrivateKey:
	private_key: bytes
	chain_code: bytes
	suffix: tuple[DerivationStep, ...]

def parse_extended_private_key(key_expression: str) -> ExtendedPrivateKey | None:
	try:
		without_origin, _origin = strip_key_origin(key_expression)
		slash = without_origin.find("/")
		encoded = without_origin if slash == -1 else without_origin[:slash]
		suffix_text = "" if slash == -1 else without_origin[slash:]
		payload = base58check_decode(encoded)
		if (
			len(payload) != 78
			or payload[:4] not in EXTENDED_PRIVATE_KEY_VERSIONS
			or payload[45] != 0
		):
			return None
		depth = payload[4]
		if depth == 0 and (payload[5:9] != b"\x00" * 4 or payload[9:13] != b"\x00" * 4):
			return None
		private_key = payload[46:78]
		scalar = int.from_bytes(private_key, "big")
		if not 1 <= scalar < CURVE_ORDER:
			raise ValueError("Extended key contains an invalid private scalar")
		return ExtendedPrivateKey(private_key, payload[13:45], parse_derivation_suffix(suffix_text))
	except (ValueError, IndexError):
		return None

def resolve_derivation_path(
	suffix: tuple[DerivationStep, ...], wildcard_index: int
) -> list[int]:
	if not 0 <= wildcard_index < HARDENED:
		raise ValueError("Wildcard index is out of range")
	path: list[int] = []
	for step in suffix:
		index = wildcard_index if step.index is None else step.index
		path.append(index | HARDENED if step.hardened else index)
	return path

def derive_private_key(root: ExtendedPrivateKey, path: list[int]) -> bytes:
	private_key = root.private_key
	chain_code = root.chain_code

	for index in path:
		if not 0 <= index <= 0xFFFFFFFF:
			raise ValueError("BIP32 child index is out of range")
		if index & HARDENED:
			data = b"\x00" + private_key + struct.pack(">I", index)
		else:
			compressed, _uncompressed = public_keys_from_private(private_key)
			data = bytes.fromhex(compressed) + struct.pack(">I", index)

		digest = hmac.new(chain_code, data, hashlib.sha512).digest()
		left, chain_code = digest[:32], digest[32:]
		left_number = int.from_bytes(left, "big")
		if left_number >= CURVE_ORDER:
			raise ToolError("BIP32 produced an invalid child; Core should advance the index")
		child = (left_number + int.from_bytes(private_key, "big")) % CURVE_ORDER
		if child == 0:
			raise ToolError("BIP32 produced a zero child; Core should advance the index")
		private_key = child.to_bytes(32, "big")

	return private_key

def parse_hd_index(path: str) -> int:
	component = path.rsplit("/", 1)[-1]
	if component.endswith(("h", "H", "'")):
		component = component[:-1]
	if not re.fullmatch(r"[0-9]+", component):
		raise ToolError(f"Unsupported hdkeypath: {path}")
	index = int(component)
	if not 0 <= index < HARDENED:
		raise ToolError("HD address index is out of range")
	return index

def load_descriptors_from_file(path: Path) -> list[dict[str, Any]]:
	try:
		with path.open("r", encoding="utf-8") as handle:
			data = json.load(handle)
	except (OSError, json.JSONDecodeError) as exc:
		raise ToolError(f"Could not read descriptor file {path}: {exc}") from exc

	if isinstance(data, dict) and data.get("error"):
		clear_private_descriptor_data(data)
		raise ToolError("The descriptor file contains an RPC error instead of descriptors")
	if isinstance(data, dict) and "result" in data:
		data = data["result"]
	descriptors = data.get("descriptors") if isinstance(data, dict) else data
	if not isinstance(descriptors, list) or not all(isinstance(item, dict) for item in descriptors):
		clear_private_descriptor_data(data)
		raise ToolError("Descriptor file has an unsupported JSON structure")
	return descriptors

def clear_private_descriptor_data(value: Any) -> None:
	if isinstance(value, dict):
		for key in list(value):
			clear_private_descriptor_data(value[key])
			value[key] = None
		value.clear()
	elif isinstance(value, list):
		for index in range(len(value)):
			clear_private_descriptor_data(value[index])
			value[index] = None
		value.clear()

def descriptor_range(entry: dict[str, Any]) -> tuple[int, int] | None:
	value = entry.get("range")
	if not isinstance(value, list) or len(value) != 2:
		return None
	if any(isinstance(item, bool) for item in value):
		return None
	try:
		start, end = int(value[0]), int(value[1])
	except (TypeError, ValueError):
		return None
	return (start, end) if 0 <= start <= end else None

def build_and_verify_leaf_descriptor(
	rpc: RpcClient,
	descriptor: SingleKeyDescriptor,
	wif: str,
	expected_address: str,
) -> str | None:
	body = descriptor.with_key(wif)
	descriptor_info = rpc.call("getdescriptorinfo", body)
	checksum = descriptor_info.get("checksum") if isinstance(descriptor_info, dict) else None
	if not isinstance(checksum, str):
		raise ToolError("getdescriptorinfo did not return a descriptor checksum")
	private_descriptor = f"{body}#{checksum}"
	derived = rpc.call("deriveaddresses", private_descriptor)
	if isinstance(derived, list) and derived == [expected_address]:
		return private_descriptor
	return None

@dataclass
class ExtractionResult:
	address: str
	wif: str
	private_descriptor: str
	source: str
	hd_path: str | None = None

def find_hd_result(
	rpc: RpcClient,
	descriptors: list[dict[str, Any]],
	address_info: dict[str, Any],
	address: str,
	wif_prefix: int,
) -> ExtractionResult | None:
	embedded = address_info.get("embedded") if isinstance(address_info.get("embedded"), dict) else {}
	hd_path = address_info.get("hdkeypath") or embedded.get("hdkeypath")
	if not isinstance(hd_path, str) or hd_path in {"", "m"}:
		return None
	wildcard_index = parse_hd_index(hd_path)

	matches: list[ExtractionResult] = []
	ordered = sorted(descriptors, key=lambda entry: not bool(entry.get("active")))
	for entry in ordered:
		ranged = descriptor_range(entry)
		descriptor_text = entry.get("desc")
		parsed = parse_single_key_descriptor(descriptor_text)
		if ranged is None or parsed is None or not isinstance(descriptor_text, str):
			continue
		extended = parse_extended_private_key(parsed.key_expression)
		if extended is None or not any(step.index is None for step in extended.suffix):
			continue
		if not ranged[0] <= wildcard_index <= ranged[1]:
			continue

		derived_addresses = rpc.call("deriveaddresses", descriptor_text, [wildcard_index, wildcard_index])
		if derived_addresses != [address]:
			continue

		child_path = resolve_derivation_path(extended.suffix, wildcard_index)
		private_key = derive_private_key(extended, child_path)
		wif = private_key_to_wif(private_key, wif_prefix, compressed=True)
		leaf_descriptor = build_and_verify_leaf_descriptor(rpc, parsed, wif, address)
		if leaf_descriptor:
			matches.append(
				ExtractionResult(address, wif, leaf_descriptor, "internally generated HD descriptor", hd_path)
			)

	unique = {(item.wif, item.private_descriptor): item for item in matches}
	if len(unique) > 1:
		raise ToolError("More than one HD private key matched the target address")
	return next(iter(unique.values()), None)

def collect_target_pubkeys(address_info: dict[str, Any]) -> set[str]:
	candidates: list[Any] = [address_info.get("pubkey")]
	embedded = address_info.get("embedded")
	if isinstance(embedded, dict):
		candidates.append(embedded.get("pubkey"))

	for source in (address_info, embedded if isinstance(embedded, dict) else {}):
		for field in ("desc", "parent_desc"):
			descriptor = source.get(field)
			if not isinstance(descriptor, str):
				continue
			candidates.extend(
				match.group(1)
				for match in re.finditer(
					r"(?<![0-9a-fA-F])((?:02|03)[0-9a-fA-F]{64}|04[0-9a-fA-F]{128}|[0-9a-fA-F]{64})(?![0-9a-fA-F])",
					descriptor,
				)
			)
	return {value.lower() for value in candidates if isinstance(value, str)}

def public_key_matches(
	compressed: str,
	uncompressed: str,
	wif_is_compressed: bool,
	targets: set[str],
) -> bool:
	actual = compressed if wif_is_compressed else uncompressed
	if actual in targets:
		return True
	return wif_is_compressed and compressed[2:] in targets  # Taproot/x-only key.

def find_imported_result(
	rpc: RpcClient,
	descriptors: list[dict[str, Any]],
	address_info: dict[str, Any],
	address: str,
	wif_prefix: int,
) -> ExtractionResult | None:
	targets = collect_target_pubkeys(address_info)
	if not targets:
		return None

	target_descriptor = parse_single_key_descriptor(
		address_info.get("parent_desc") or address_info.get("desc")
	)
	target_kind = target_descriptor.kind if target_descriptor else None
	checked = 0
	matches: list[ExtractionResult] = []

	for entry in descriptors:
		parsed = parse_single_key_descriptor(entry.get("desc"))
		if parsed is None or (target_kind and parsed.kind != target_kind):
			continue
		try:
			without_origin, _origin = strip_key_origin(parsed.key_expression)
			if "/" in without_origin:
				continue
			private_key, compressed_wif, _prefix = decode_wif(without_origin, wif_prefix)
		except ValueError:
			continue

		checked += 1
		compressed_pubkey, uncompressed_pubkey = public_keys_from_private(private_key)
		if not public_key_matches(compressed_pubkey, uncompressed_pubkey, compressed_wif, targets):
			if checked % 10000 == 0:
				print(f"  {checked:,} imported single keys checked ...")
			continue

		leaf_descriptor = build_and_verify_leaf_descriptor(rpc, parsed, without_origin, address)
		if leaf_descriptor:
			matches.append(
				ExtractionResult(address, without_origin, leaf_descriptor, "imported single key")
			)

	unique = {(item.wif, item.private_descriptor): item for item in matches}
	if len(unique) > 1:
		raise ToolError("More than one imported private key matched the target address")
	return next(iter(unique.values()), None)

def network_wif_prefix(rpc: RpcClient) -> tuple[str, int]:
	info = rpc.call("getblockchaininfo")
	chain = info.get("chain") if isinstance(info, dict) else None
	if chain == "main":
		return chain, NAMECOIN_MAINNET_WIF_PREFIX
	raise ToolError(
		f"Unsupported chain {chain!r}; this maintenance tool intentionally supports Namecoin mainnet only"
	)

def resolve_target_address(rpc: RpcClient, args: argparse.Namespace) -> str:
	if args.address is not None:
		if args.name is not None:
			raise ToolError("NAME and --address cannot be used together")
		address = args.address.strip()
		if not address:
			raise ToolError("--address must not be empty")
		return address

	name = args.name if args.name is not None else DEFAULT_NAME
	if args.name_encoding == "hex":
		if len(name) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", name):
			raise ToolError("With --name-encoding hex, NAME must be an even-length hexadecimal string")

	name_info = rpc.call(
		"name_show",
		name,
		{"nameEncoding": args.name_encoding, "valueEncoding": "hex"},
	)
	if not isinstance(name_info, dict) or not isinstance(name_info.get("address"), str):
		raise ToolError("name_show did not return an address")
	if name_info.get("expired") is True:
		raise ToolError("The name is expired")
	if name_info.get("ismine") is not True:
		raise ToolError("The current name output is not owned by the loaded wallet")
	return name_info["address"]

def extract(args: argparse.Namespace) -> ExtractionResult:
	cli = find_namecoin_cli()
	rpc = RpcClient(cli)
	chain, wif_prefix = network_wif_prefix(rpc)
	address = resolve_target_address(rpc, args)
	address_info = rpc.call("getaddressinfo", address)
	if not isinstance(address_info, dict):
		raise ToolError("getaddressinfo returned an invalid result")
	canonical_address = address_info.get("address")
	if isinstance(canonical_address, str):
		address = canonical_address
	if address_info.get("ismine") is not True:
		raise ToolError("The address is not owned by the loaded wallet")
	if address_info.get("solvable") is not True:
		raise ToolError("The loaded wallet cannot solve the address")

	descriptors: list[dict[str, Any]] | None = None
	private_descriptor_data: Any = None
	try:
		if args.descriptors_file:
			descriptors = load_descriptors_from_file(Path(args.descriptors_file))
			private_descriptor_data = descriptors
			descriptor_source = str(Path(args.descriptors_file))
		else:
			try:
				private_descriptor_data = rpc.call("listdescriptors", True)
			except ToolError as exc:
				raise ToolError(
					f"Could not read private descriptors. Unlock an encrypted wallet first. {exc}"
				) from exc
			descriptors = (
				private_descriptor_data.get("descriptors")
				if isinstance(private_descriptor_data, dict)
				else None
			)
			if not isinstance(descriptors, list):
				raise ToolError("listdescriptors true returned no descriptor list")
			descriptor_source = "live wallet"

		print(f"Chain: {chain}; private descriptors: {len(descriptors):,} ({descriptor_source})")
		print("Checking internally generated HD descriptors first ...")
		result = find_hd_result(rpc, descriptors, address_info, address, wif_prefix)
		if result is None:
			print("Checking imported single-key descriptors ...")
			result = find_imported_result(rpc, descriptors, address_info, address, wif_prefix)
		if result is None:
			raise ToolError(
				"No matching private key was found. The wallet may be watch-only, use an external signer, "
				"or use an unsupported multisig/miniscript descriptor."
			)
		return result
	finally:
		had_descriptor_data = isinstance(private_descriptor_data, (dict, list))
		clear_private_descriptor_data(private_descriptor_data)
		if had_descriptor_data:
			print("Temporary private descriptor data released (best-effort).")

def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="Export the WIF private key controlling a Namecoin name or wallet address."
	)
	target = parser.add_mutually_exclusive_group()
	target.add_argument(
		"name",
		nargs="?",
		default=None,
		metavar="NAME",
		help="Inspect this name (default: the configured hexadecimal name).",
	)
	target.add_argument(
		"--address",
		metavar="ADDRESS",
		help="Inspect this owned Legacy or Bech32 wallet address instead of resolving a name.",
	)
	parser.add_argument(
		"--name-encoding",
		choices=("hex", "ascii", "utf8"),
		default="hex",
		help="Encoding of NAME passed to name_show (default: hex).",
	)
	parser.add_argument(
		"--descriptors-file",
		help="Use an existing private listdescriptors JSON export instead of querying it live.",
	)
	return parser

def main() -> int:
	args = build_parser().parse_args()
	try:
		result = extract(args)
	except (ToolError, ValueError) as exc:
		print(f"ERROR: {exc}", file=sys.stderr)
		return 1

	print(f"Address: {result.address}")
	print(f"Source: {result.source}")
	if result.hd_path:
		print(f"HD path: {result.hd_path}")
	print(f"WIF: {result.wif}")
	print(f"Private descriptor: {result.private_descriptor}")
	print("WARNING: These values can be used to transfer funds or assets. Do not share or log them!")
	return 0

if __name__ == "__main__":
	raise SystemExit(main())
