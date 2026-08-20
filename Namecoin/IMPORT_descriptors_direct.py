################################################################################################################

# Copyright (C) 2025 by Uwe Martens * www.namecoin.pro  * https://dotbit.app

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
	find_namecoin_cli,
	network_wif_prefix,
	redact_error,
	remove_bytecode_cache,
	wait_for_close,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIRECTORY = SCRIPT_DIR
DESCRIPTOR_FILES = ["descriptors_hd.txt", "descriptors_names.txt", "descriptors_utxos.txt"]
RESCAN_METADATA_FILE = DATA_DIRECTORY / "rescan_start.json"
RESCAN_METADATA_FORMAT = "core-wallet-maintenance-rescan-start-v1"
MAX_RESCAN_METADATA_BYTES = 4096
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
		raise ToolError("Exactly one Namecoin Core wallet must be loaded")

	info = rpc.call("getwalletinfo")
	if not isinstance(info, dict):
		raise ToolError("getwalletinfo returned an invalid result")
	if info.get("descriptors") is not True:
		raise ToolError("The loaded wallet is not a descriptor wallet")
	if info.get("private_keys_enabled") is not True:
		raise ToolError("Private keys are disabled in the loaded wallet")
	return info

def valid_timestamp(value: Any) -> bool:
	return value == "now" or (
		isinstance(value, int)
		and not isinstance(value, bool)
		and value >= 0
	)

def valid_block_height(value: Any) -> bool:
	return isinstance(value, int) and not isinstance(value, bool) and value >= 0

def valid_block_hash(value: Any) -> bool:
	return (
		isinstance(value, str)
		and len(value) == 64
		and all(character in "0123456789abcdefABCDEF" for character in value)
	)

def reject_duplicate_rescan_metadata_keys(
	pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
	metadata: dict[str, Any] = {}
	for key, value in pairs:
		if key in metadata:
			raise ToolError(f"Rescan metadata contains a duplicate JSON field: {key}")
		metadata[key] = value
	return metadata

def load_rescan_metadata(path: Path = RESCAN_METADATA_FILE) -> dict[str, Any]:
	if path.is_symlink() or (path.exists() and not path.is_file()):
		raise ToolError(f"Rescan metadata is not a regular file: {path}")
	try:
		size = path.stat().st_size
	except FileNotFoundError as exc:
		raise ToolError(f"Required rescan metadata file not found: {path}") from exc
	except OSError as exc:
		raise ToolError(f"Could not inspect rescan metadata {path}: {exc}") from exc
	if size <= 0 or size > MAX_RESCAN_METADATA_BYTES:
		raise ToolError(f"Rescan metadata has an invalid size: {path}")

	try:
		with path.open("r", encoding="utf-8") as handle:
			metadata = json.load(
				handle,
				object_pairs_hook=reject_duplicate_rescan_metadata_keys,
			)
	except (OSError, UnicodeError, json.JSONDecodeError) as exc:
		raise ToolError(f"Could not read valid rescan metadata from {path}: {exc}") from exc
	if not isinstance(metadata, dict):
		raise ToolError(f"Rescan metadata must contain one JSON object: {path}")
	expected_fields = {
		"format",
		"chain",
		"start_height",
		"start_blockhash",
	}
	if set(metadata) != expected_fields:
		raise ToolError(f"Rescan metadata has unsupported or missing fields: {path}")
	if metadata.get("format") != RESCAN_METADATA_FORMAT:
		raise ToolError(f"Rescan metadata uses an unsupported format: {path}")
	if not isinstance(metadata.get("chain"), str) or not metadata["chain"]:
		raise ToolError(f"Rescan metadata has an invalid chain: {path}")
	if not valid_block_height(metadata.get("start_height")):
		raise ToolError(f"Rescan metadata has an invalid start height: {path}")
	if not valid_block_hash(metadata.get("start_blockhash")):
		raise ToolError(f"Rescan metadata has an invalid start block hash: {path}")
	metadata["start_blockhash"] = metadata["start_blockhash"].lower()
	return metadata

def validate_rescan_chain(
	rpc: RpcClient,
	chain: str,
	metadata: dict[str, Any],
) -> int:
	if metadata["chain"] != chain:
		raise ToolError(
			f"Rescan metadata is for chain {metadata['chain']!r}, not the active chain {chain!r}"
		)
	blockchain_info = rpc.call("getblockchaininfo")
	if not isinstance(blockchain_info, dict) or blockchain_info.get("chain") != chain:
		raise ToolError("getblockchaininfo returned an invalid or changed active chain")
	current_tip = blockchain_info.get("blocks")
	if not valid_block_height(current_tip):
		raise ToolError("getblockchaininfo returned no usable block height")
	start_height = metadata["start_height"]
	if start_height > current_tip:
		raise ToolError(
			f"Rescan start height {start_height} is above the active chain tip {current_tip}"
		)
	pruned = blockchain_info.get("pruned")
	if not isinstance(pruned, bool):
		raise ToolError("getblockchaininfo returned an invalid pruned state")
	if pruned:
		prune_height = blockchain_info.get("pruneheight")
		if not valid_block_height(prune_height):
			raise ToolError("getblockchaininfo returned an invalid prune height")
		if start_height < prune_height:
			raise ToolError(
				f"Required block data starts at {start_height}, but this pruned node only has "
				f"blocks from height {prune_height}"
			)

	start_blockhash = rpc.call("getblockhash", start_height)
	if not valid_block_hash(start_blockhash):
		raise ToolError("getblockhash returned an invalid result while validating rescan metadata")
	if start_blockhash.lower() != metadata["start_blockhash"]:
		raise ToolError(
			"The blockchain changed at the exported rescan start height; run the exporter again"
		)
	return start_height

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

def clear_descriptor_sources(sources: list[dict[str, Any]]) -> None:
	for source in sources:
		records = source.get("records")
		if isinstance(records, list):
			clear_loaded_records(records)
		source.clear()
	sources.clear()

def load_descriptor_records(path: Path) -> list[tuple[int, dict[str, Any]]]:
	records: list[tuple[int, dict[str, Any]]] = []
	try:
		with path.open("r", encoding="utf-8") as handle:
			for line_number, line in enumerate(handle, 1):
				content = line.strip()
				if not content:
					continue
				if content.startswith(("{", "[", '"')):
					try:
						request = json.loads(content)
					except json.JSONDecodeError as exc:
						raise ToolError(
							f"{path} line {line_number} is not valid JSON: {exc.msg}"
						) from exc
					if not isinstance(request, dict):
						raise ToolError(f"{path} line {line_number} must contain a JSON object")
					if "timestamp" not in request:
						request["timestamp"] = "now"
				else:
					request = {"desc": content, "timestamp": "now"}
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

def load_descriptor_sources() -> list[dict[str, Any]]:
	sources: list[dict[str, Any]] = []
	try:
		for path in configured_descriptor_paths():
			if not path.exists():
				print(f"[INFO] {path} not found; skipping.")
				continue
			if not path.is_file():
				raise ToolError(f"Descriptor input is not a regular file: {path}")
			loaded_records = load_descriptor_records(path)
			if not loaded_records:
				print(f"[INFO] No descriptor records found in {path}; skipping.")
				continue
			sources.append({"path": path, "records": loaded_records})
	except BaseException:
		clear_descriptor_sources(sources)
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

def process_descriptor_sources(
	rpc: RpcClient,
	sources: list[dict[str, Any]],
	rescan_start_height: int,
) -> int:
	seen: set[bytes] = set()
	imported = 0
	submitted = False
	uncertain_batch = False
	try:
		for source in sources:
			path = source["path"]
			records = source["records"]
			total_records = len(records)
			print(f"\nProcessing {path} with {total_records} descriptors...")
			for offset in range(0, total_records, BATCH_SIZE):
				end = min(offset + BATCH_SIZE, total_records)
				requests: list[dict[str, Any]] = []
				batch: list[dict[str, Any]] = []
				result: object = None
				try:
					for line_number, request in records[offset:end]:
						digest = preflight_request(rpc, request, path, line_number)
						if digest in seen:
							clear_private_descriptor_data(request)
						else:
							seen.add(digest)
							requests.append(request)

					if requests:
						batch = [copy_import_request(request) for request in requests]
						wait_for_rescan_complete(rpc)
						submitted = True
						uncertain_batch = True
						result = rpc.call("importdescriptors", batch)
						validate_import_result(result, len(batch))
						uncertain_batch = False
						imported += len(batch)
					print(f"→ {end}/{total_records} descriptors processed...")
				finally:
					clear_private_descriptor_data(result)
					clear_private_descriptor_data(batch)
					clear_private_descriptor_data(requests)
			records.clear()
	except BaseException:
		if submitted:
			confirmed = (
				f"At least {imported:,} descriptor records were confirmed imported before the failure. "
				if imported
				else ""
			)
			uncertain = (
				"The failed import batch may have been partially applied. "
				if uncertain_batch
				else ""
			)
			print(
				f"[WARNING] {confirmed}{uncertain}"
				f"Run rescanblockchain {rescan_start_height} before relying on accepted descriptors. "
				"If the input contains "
				"active ranged descriptors, a complete retry requires a fresh blank descriptor wallet.",
				file=sys.stderr,
			)
		raise
	return imported

def rescan_wallet(rpc: RpcClient, start_height: int) -> int:
	wait_for_rescan_complete(rpc)
	print(f"Rescanning chain from block {start_height:,} ...")
	result = rpc.call("rescanblockchain", start_height)
	if not isinstance(result, dict):
		raise ToolError("rescanblockchain returned an invalid result")
	result_start = result.get("start_height")
	stop_height = result.get("stop_height")
	if result_start != start_height or not valid_block_height(stop_height) or stop_height < start_height:
		raise ToolError("rescanblockchain returned invalid scan boundaries")
	return stop_height

def run_import() -> None:
	if not isinstance(BATCH_SIZE, int) or isinstance(BATCH_SIZE, bool) or BATCH_SIZE <= 0:
		raise ToolError("BATCH_SIZE must be a positive integer")

	print(f"Data directory: {DATA_DIRECTORY}")
	rpc = RpcClient(find_namecoin_cli(), timeout=None)
	chain, _wif_prefix = network_wif_prefix(rpc)
	wallet_info = validate_wallet(rpc)
	rescan_metadata = load_rescan_metadata()
	sources: list[dict[str, Any]] = []
	try:
		start_height = validate_rescan_chain(rpc, chain, rescan_metadata)
		sources = load_descriptor_sources()
		if not sources:
			raise ToolError("No non-empty descriptor input file was found")
		total_records = sum(len(source["records"]) for source in sources)
		requires_blank_wallet = any(
			request.get("active") is True
			for source in sources
			for _line_number, request in source["records"]
		)
		if requires_blank_wallet and wallet_info.get("blank") is not True:
			raise ToolError("Active ranged descriptors may only be imported into a blank descriptor wallet")
		validated_start_height = validate_rescan_chain(rpc, chain, rescan_metadata)
		if validated_start_height != start_height:
			raise ToolError("The validated rescan start height changed unexpectedly")
		print(f"Chain: {chain}; {total_records:,} descriptor records loaded.")
		print(f"Rescan metadata passed validation; start height: {start_height:,}.")

		imported = process_descriptor_sources(rpc, sources, start_height)
		print(f"[INFO] All {imported:,} descriptor records imported successfully.")
		try:
			stop_height = rescan_wallet(rpc, start_height)
		except BaseException:
			print(
				f"[WARNING] The descriptors were imported, but the rescan failed. Run "
				f"rescanblockchain {start_height} before using this wallet.",
				file=sys.stderr,
			)
			raise
		print(f"[INFO] Rescan completed through block {stop_height:,}.")
	finally:
		rescan_metadata.clear()
		clear_descriptor_sources(sources)
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
