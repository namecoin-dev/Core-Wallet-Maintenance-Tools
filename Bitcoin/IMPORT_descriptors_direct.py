################################################################################################################

# Copyright (C) 2026 by Uwe Martens * www.namecoin.pro  * https://dotbit.app

################################################################################################################

from __future__ import annotations

import sys
sys.dont_write_bytecode = True

def configure_standard_streams() -> None:
	for stream_name in ("stdout", "stderr"):
		stream = getattr(sys, stream_name, None)
		try:
			stream.reconfigure(errors="replace")
		except (AttributeError, OSError, TypeError, ValueError):
			pass

configure_standard_streams()

import hashlib
import json
import time
import traceback
from pathlib import Path
from typing import Any

from GET_privkey import (
	RpcClient,
	ToolError,
	clear_private_descriptor_data,
	find_bitcoin_cli,
	network_wif_prefix,
	redact_error,
	remove_bytecode_cache,
	wait_for_close,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIRECTORY = SCRIPT_DIR
DESCRIPTOR_FILES = ["descriptors_hd.txt", "descriptors_utxos.txt"]
RESCAN_MANIFEST_FILE = DATA_DIRECTORY / "rescan_start.json"
RESCAN_MANIFEST_FORMAT = "core-wallet-maintenance-rescan-start-v1"
MAX_RESCAN_MANIFEST_BYTES = 4096
RESCAN_MANIFEST_FIELDS = {
	"format",
	"chain",
	"start_height",
	"start_blockhash",
}
BATCH_SIZE = 1000
ALLOWED_REQUEST_FIELDS = {
	"desc",
	"timestamp",
	"active",
	"internal",
	"range",
	"next_index",
	"label",
}

def configured_descriptor_paths() -> list[Path]:
	configured = DESCRIPTOR_FILES
	if isinstance(configured, (str, Path)):
		entries = [configured]
	elif isinstance(configured, (list, tuple)):
		entries = list(configured)
	else:
		raise ToolError("DESCRIPTOR_FILES must be a path or a list or tuple of paths")
	if not entries:
		raise ToolError("DESCRIPTOR_FILES must contain at least one descriptor file")

	paths: list[Path] = []
	for entry in entries:
		if isinstance(entry, str):
			if not entry.strip():
				raise ToolError("DESCRIPTOR_FILES contains an empty filename")
			path = Path(entry)
		elif isinstance(entry, Path):
			path = entry
		else:
			raise ToolError("DESCRIPTOR_FILES entries must be filenames or paths")
		if not path.is_absolute():
			path = DATA_DIRECTORY / path
		if path in paths:
			raise ToolError(f"DESCRIPTOR_FILES contains a duplicate path: {path}")
		paths.append(path)
	return paths

def validate_wallet(rpc: RpcClient) -> dict[str, Any]:
	wallets = rpc.call("listwallets")
	if not isinstance(wallets, list) or len(wallets) != 1:
		raise ToolError("Exactly one Bitcoin Core wallet must be loaded")

	info = rpc.call("getwalletinfo")
	if not isinstance(info, dict):
		raise ToolError("getwalletinfo returned an invalid result")
	if info.get("descriptors") is not True:
		raise ToolError("The loaded wallet is not a descriptor wallet")
	if info.get("private_keys_enabled") is not True:
		raise ToolError("Private keys are disabled in the loaded wallet")
	return info

def valid_block_hash(value: Any) -> bool:
	return (
		isinstance(value, str)
		and len(value) == 64
		and all(character in "0123456789abcdefABCDEF" for character in value)
	)

def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
	result: dict[str, Any] = {}
	for key, value in pairs:
		if key in result:
			raise ToolError(f"{RESCAN_MANIFEST_FILE} contains a duplicate JSON field")
		result[key] = value
	return result

def load_and_validate_rescan_manifest(rpc: RpcClient, chain: str) -> dict[str, Any]:
	path = RESCAN_MANIFEST_FILE
	if path.is_symlink() or not path.is_file():
		raise ToolError(f"Rescan manifest is missing or is not a regular file: {path}")
	try:
		size = path.stat().st_size
		if not 0 < size <= MAX_RESCAN_MANIFEST_BYTES:
			raise ToolError(f"Rescan manifest has an invalid size: {path}")
		text = path.read_text(encoding="utf-8")
	except (OSError, UnicodeError) as exc:
		raise ToolError(f"Could not read rescan manifest {path}: {exc}") from exc
	if not text.strip():
		raise ToolError(f"Rescan manifest is empty: {path}")
	try:
		manifest = json.loads(text, object_pairs_hook=reject_duplicate_json_keys)
	except json.JSONDecodeError as exc:
		raise ToolError(f"Rescan manifest is not valid JSON: {exc.msg}") from exc
	if not isinstance(manifest, dict):
		raise ToolError("Rescan manifest must contain one JSON object")
	if set(manifest) != RESCAN_MANIFEST_FIELDS:
		raise ToolError("Rescan manifest has missing or unsupported fields")
	if manifest.get("format") != RESCAN_MANIFEST_FORMAT:
		raise ToolError("Rescan manifest uses an unsupported format")
	if manifest.get("chain") != chain:
		raise ToolError("Rescan manifest belongs to a different chain")
	start_blockhash = manifest.get("start_blockhash")
	start_height = manifest.get("start_height")
	if not isinstance(start_height, int) or isinstance(start_height, bool) or start_height < 0:
		raise ToolError("Rescan manifest has an invalid start height")
	if not valid_block_hash(start_blockhash):
		raise ToolError("Rescan manifest has an invalid start block hash")
	start_blockhash = start_blockhash.lower()
	manifest["start_blockhash"] = start_blockhash
	blockchain_info = rpc.call("getblockchaininfo")
	if not isinstance(blockchain_info, dict) or blockchain_info.get("chain") != chain:
		raise ToolError("getblockchaininfo returned an invalid or changed active chain")
	current_tip = blockchain_info.get("blocks")
	if not isinstance(current_tip, int) or isinstance(current_tip, bool) or current_tip < 0:
		raise ToolError("getblockchaininfo returned an invalid block height")
	if start_height > current_tip:
		raise ToolError("Rescan manifest start height is above the active chain tip")
	pruned = blockchain_info.get("pruned")
	if not isinstance(pruned, bool):
		raise ToolError("getblockchaininfo returned an invalid pruned state")
	if pruned:
		prune_height = blockchain_info.get("pruneheight")
		if (
			not isinstance(prune_height, int)
			or isinstance(prune_height, bool)
			or prune_height < 0
		):
			raise ToolError("getblockchaininfo returned an invalid prune height")
		if start_height < prune_height:
			raise ToolError(
				"The node has pruned block data required by this rescan; use an unpruned node"
			)
	actual_start = rpc.call("getblockhash", start_height)
	if not valid_block_hash(actual_start) or actual_start.lower() != start_blockhash:
		raise ToolError(
			"Rescan manifest start block does not match the active chain; rerun the exporter"
		)
	return manifest

def valid_timestamp(value: Any) -> bool:
	return value == "now" or (
		isinstance(value, int)
		and not isinstance(value, bool)
		and value >= 0
	)

def normalized_range(value: Any) -> tuple[int, int] | None:
	if isinstance(value, int) and not isinstance(value, bool):
		return (0, value) if value >= 0 else None
	if not isinstance(value, list) or len(value) != 2:
		return None
	if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
		return None
	start, end = value
	return (start, end) if 0 <= start <= end else None

def clear_loaded_records(records: list[tuple[int, dict[str, Any]]]) -> None:
	for _line_number, request in records:
		clear_private_descriptor_data(request)
	records.clear()

def load_json_lines(path: Path) -> list[tuple[int, dict[str, Any]]]:
	records: list[tuple[int, dict[str, Any]]] = []
	try:
		with path.open("r", encoding="utf-8") as handle:
			for line_number, line in enumerate(handle, 1):
				if not line.strip():
					continue
				try:
					request = json.loads(line)
				except json.JSONDecodeError as exc:
					raise ToolError(
						f"{path} line {line_number} is not valid JSON: {exc.msg}"
					) from exc
				if not isinstance(request, dict):
					raise ToolError(f"{path} line {line_number} must contain a JSON object")
				records.append((line_number, request))
	except OSError as exc:
		clear_loaded_records(records)
		raise ToolError(f"Could not read {path}: {exc}") from exc
	except BaseException:
		clear_loaded_records(records)
		raise
	return records

def preflight_request(
	rpc: RpcClient,
	request: dict[str, Any],
	path: Path,
	line_number: int,
) -> bytes:
	location = f"{path} line {line_number}"
	unknown = set(request) - ALLOWED_REQUEST_FIELDS
	if unknown:
		raise ToolError(f"{location} contains unsupported import fields")

	descriptor = request.get("desc")
	if not isinstance(descriptor, str) or not descriptor:
		raise ToolError(f"{location} has no descriptor")
	if "#" not in descriptor:
		raise ToolError(f"{location} has no descriptor checksum")
	if not valid_timestamp(request.get("timestamp")):
		raise ToolError(f"{location} has an invalid timestamp")

	for field in ("active", "internal"):
		if field in request and not isinstance(request[field], bool):
			raise ToolError(f"{location} has an invalid {field} value")
	if "label" in request and not isinstance(request["label"], str):
		raise ToolError(f"{location} has an invalid label")
	if "internal" in request and "label" in request:
		raise ToolError(f"{location} cannot combine internal with a label")

	info = rpc.call("getdescriptorinfo", descriptor)
	try:
		if not isinstance(info, dict):
			raise ToolError(f"{location} failed descriptor validation")
		if info.get("hasprivatekeys") is not True:
			raise ToolError(f"{location} does not contain private keys")

		provided_checksum = descriptor.rsplit("#", 1)[1]
		if not provided_checksum or info.get("checksum") != provided_checksum:
			raise ToolError(f"{location} has an invalid descriptor checksum")

		is_ranged = info.get("isrange") is True
		range_value = normalized_range(request.get("range")) if "range" in request else None
		if is_ranged and range_value is None:
			raise ToolError(f"{location} must preserve a valid descriptor range")
		if is_ranged and "active" not in request:
			raise ToolError(f"{location} does not preserve the descriptor's active state")
		if is_ranged and "next_index" not in request:
			raise ToolError(f"{location} does not preserve the descriptor's next index")
		if is_ranged and "label" in request:
			raise ToolError(f"{location} cannot assign a label to a ranged descriptor")
		if not is_ranged and ("range" in request or "next_index" in request):
			raise ToolError(f"{location} assigns range metadata to a fixed descriptor")
		if request.get("active") is True and not is_ranged:
			raise ToolError(f"{location} marks a fixed descriptor as active")
		if request.get("active") is True and "internal" not in request:
			raise ToolError(f"{location} does not preserve the active descriptor's internal state")

		if "next_index" in request:
			next_index = request["next_index"]
			if not isinstance(next_index, int) or isinstance(next_index, bool) or next_index < 0:
				raise ToolError(f"{location} has an invalid next index")
			if range_value is None or not range_value[0] <= next_index <= range_value[1]:
				raise ToolError(f"{location} has a next index outside its range")
	finally:
		clear_private_descriptor_data(info)

	return hashlib.sha256(descriptor.encode("utf-8")).digest()

def load_descriptor_files() -> list[dict[str, Any]]:
	sources: list[dict[str, Any]] = []
	try:
		for path in configured_descriptor_paths():
			if not path.exists():
				print(f"[INFO] {path} not found; skipping.")
				continue
			if not path.is_file():
				raise ToolError(f"Descriptor input is not a regular file: {path}")
			loaded_records = load_json_lines(path)
			if not loaded_records:
				print(f"[INFO] No descriptor records found in {path}; skipping.")
				continue

			try:
				sources.append(
					{
						"path": path,
						"line_numbers": [line_number for line_number, _request in loaded_records],
						"requests": [request for _line_number, request in loaded_records],
					}
				)
			except BaseException:
				clear_loaded_records(loaded_records)
				raise
			loaded_records.clear()
	except BaseException:
		clear_private_descriptor_data(sources)
		raise
	return sources

def is_scanning(rpc: RpcClient) -> bool:
	info = rpc.call("getwalletinfo")
	if not isinstance(info, dict):
		raise ToolError("getwalletinfo returned an invalid result")
	return info.get("scanning", False) is not False

def wait_for_rescan_complete(rpc: RpcClient) -> None:
	while is_scanning(rpc):
		print("Wallet is scanning; waiting 5 seconds ...")
		time.sleep(5)

def validate_import_result(result: object, expected: int) -> None:
	if not isinstance(result, list) or len(result) != expected:
		raise ToolError("importdescriptors returned an invalid result")

	for entry in result:
		if not isinstance(entry, dict):
			continue
		warnings = entry.get("warnings")
		if isinstance(warnings, list):
			for warning in warnings:
				if isinstance(warning, str):
					print(f"[WARNING] {redact_error(warning)}")

	failures = [entry for entry in result if not isinstance(entry, dict) or entry.get("success") is not True]
	if not failures:
		return

	messages: list[str] = []
	for entry in failures[:3]:
		if not isinstance(entry, dict):
			continue
		error = entry.get("error")
		if isinstance(error, dict) and isinstance(error.get("message"), str):
			messages.append(redact_error(error["message"]))
	detail = f": {'; '.join(messages)}" if messages else ""
	raise ToolError(f"{len(failures)} descriptor imports failed{detail}")

def copy_import_request(request: dict[str, Any]) -> dict[str, Any]:
	copy: dict[str, Any] = {}
	for key, value in request.items():
		copy[key] = list(value) if isinstance(value, list) else value
	copy["timestamp"] = "now"
	return copy

def import_sources(
	rpc: RpcClient,
	sources: list[dict[str, Any]],
	rescan_start_height: int,
) -> int:
	imported = 0
	batch_may_be_partially_applied = False
	seen: set[bytes] = set()
	try:
		for source in sources:
			path = source["path"]
			line_numbers = source["line_numbers"]
			requests = source["requests"]
			total_records = len(requests)
			print(f"\nProcessing {path} with {total_records} descriptors...")

			for offset in range(0, total_records, BATCH_SIZE):
				end = min(offset + BATCH_SIZE, total_records)
				for index in range(offset, end):
					request = requests[index]
					line_number = line_numbers[index]
					digest = preflight_request(rpc, request, path, line_number)
					if digest in seen:
						raise ToolError(
							f"{path} line {line_number} duplicates another descriptor"
						)
					seen.add(digest)

				batch = [copy_import_request(request) for request in requests[offset:end]]
				result: object = None
				try:
					wait_for_rescan_complete(rpc)
					batch_may_be_partially_applied = True
					result = rpc.call("importdescriptors", batch)
					validate_import_result(result, len(batch))
					batch_may_be_partially_applied = False
					imported += len(batch)
					print(f"→ {end}/{total_records} descriptors processed...")
				finally:
					clear_private_descriptor_data(result)
					clear_private_descriptor_data(batch)
	except BaseException:
		if imported or batch_may_be_partially_applied:
			confirmed = (
				f"At least {imported:,} descriptor records were confirmed imported before the failure. "
				if imported
				else ""
			)
			possibly_partial = (
				"The failed import batch may have been partially applied. "
				if batch_may_be_partially_applied
				else ""
			)
			print(
				f"[WARNING] {confirmed}{possibly_partial}"
				f"Run rescanblockchain {rescan_start_height} before relying on accepted descriptors. "
				"If the input contains "
				"active ranged descriptors, a complete retry requires a fresh blank descriptor wallet.",
				file=sys.stderr,
			)
		raise
	return imported

def validate_rescan_result(result: object, expected_start_height: int) -> int:
	if not isinstance(result, dict):
		raise ToolError("rescanblockchain returned an invalid result")
	start_height = result.get("start_height")
	stop_height = result.get("stop_height")
	if (
		not isinstance(start_height, int)
		or isinstance(start_height, bool)
		or start_height != expected_start_height
	):
		raise ToolError("rescanblockchain returned an unexpected start height")
	if (
		not isinstance(stop_height, int)
		or isinstance(stop_height, bool)
		or stop_height < start_height
	):
		raise ToolError("rescanblockchain returned an invalid stop height")
	return stop_height

def run_rescan(rpc: RpcClient, start_height: int) -> int:
	wait_for_rescan_complete(rpc)
	print(f"Rescanning chain from block {start_height:,} ...")
	result = rpc.call("rescanblockchain", start_height)
	return validate_rescan_result(result, start_height)

def run_import() -> None:
	if not isinstance(BATCH_SIZE, int) or isinstance(BATCH_SIZE, bool) or BATCH_SIZE <= 0:
		raise ToolError("BATCH_SIZE must be a positive integer")

	print(f"Data directory: {DATA_DIRECTORY}")
	rpc = RpcClient(find_bitcoin_cli(), timeout=None)
	chain, _wif_prefix = network_wif_prefix(rpc)
	wallet_info = validate_wallet(rpc)
	sources: list[dict[str, Any]] = []
	rescan_manifest: dict[str, Any] = {}
	try:
		rescan_manifest = load_and_validate_rescan_manifest(rpc, chain)
		sources = load_descriptor_files()
		if not sources:
			raise ToolError("No non-empty descriptor input file was found")
		total_records = sum(len(source["requests"]) for source in sources)
		requires_blank_wallet = any(
			request.get("active") is True
			for source in sources
			for request in source["requests"]
		)
		if requires_blank_wallet and wallet_info.get("blank") is not True:
			raise ToolError("Active ranged descriptors may only be imported into a blank descriptor wallet")
		start_height = rescan_manifest["start_height"]
		print(
			f"Chain: {chain}; {total_records:,} descriptor records and the rescan manifest "
			"passed initial validation."
		)

		imported = import_sources(rpc, sources, start_height)
		print(f"[INFO] All {imported:,} descriptor records imported successfully.")
		try:
			stop_height = run_rescan(rpc, start_height)
		except BaseException:
			print(
				f"[WARNING] All descriptor imports succeeded, but the rescan did not complete "
				f"or returned an invalid result. Run rescanblockchain {start_height} before "
				"relying on the wallet balance.",
				file=sys.stderr,
			)
			raise
		print(f"[INFO] Rescan completed successfully through block {stop_height:,}.")
	finally:
		clear_private_descriptor_data(sources)
		rescan_manifest.clear()
		print("Temporary private descriptor data released (best-effort).")

def main() -> int:
	remove_bytecode_cache()
	try:
		run_import()
	except (ToolError, ValueError, OSError) as exc:
		print(f"ERROR: {exc}", file=sys.stderr)
		return 1
	return 0

def run_cli() -> int:
	try:
		exit_code = main()
	except KeyboardInterrupt:
		print("\nOperation cancelled.", file=sys.stderr)
		exit_code = 130
	except Exception:
		traceback.print_exc()
		exit_code = 1
	wait_for_close()
	return exit_code

if __name__ == "__main__":
	raise SystemExit(run_cli())
