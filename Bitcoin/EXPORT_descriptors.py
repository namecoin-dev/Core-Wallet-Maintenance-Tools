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
import os
import platform
import secrets
import stat
import traceback
from collections.abc import Iterable
from pathlib import Path
from typing import Any

try:
	import requests
except ImportError as exc:
	failed_import = getattr(exc, "name", None)
	safe_import_name = (
		isinstance(failed_import, str)
		and 0 < len(failed_import) <= 128
		and failed_import.isascii()
		and all(part and part.replace("_", "").isalnum() for part in failed_import.split("."))
	)
	dependency_note = f" (failed import: {failed_import})" if safe_import_name else ""
	print(
		"ERROR: The required Python package 'requests' or one of its dependencies "
		f"could not be imported{dependency_note}. Repair it with: "
		"python -m pip install --upgrade --force-reinstall requests",
		file=sys.stderr,
	)
	if len(sys.argv) == 1 and sys.stdin is not None and sys.stdout is not None:
		try:
			if sys.stdin.isatty() and sys.stdout.isatty():
				input("\nPress Enter to close ...")
		except (AttributeError, EOFError, KeyboardInterrupt, OSError, ValueError):
			pass
	raise SystemExit(1) from None

from GET_privkey import (
	ExtractionResult,
	RpcTransportError,
	ToolError,
	clear_private_descriptor_data,
	collect_target_pubkeys,
	decode_wif,
	descriptor_range,
	find_hd_result,
	find_imported_result,
	network_wif_prefix,
	parse_extended_private_key,
	parse_single_key_descriptor,
	public_keys_from_private,
	redact_error,
	remove_bytecode_cache,
	strip_key_origin,
	wait_for_close,
)


url = "http://127.0.0.1:8332/"

SCRIPT_DIR = Path(__file__).resolve().parent
# None = auto-detect; a custom cookie path may be absolute or relative to the script directory.
COOKIE_FILE: str | Path | None = None
DATA_DIRECTORY = SCRIPT_DIR
HD_OUTPUT_FILE = DATA_DIRECTORY / "descriptors_hd.txt"
UTXO_OUTPUT_FILE = DATA_DIRECTORY / "descriptors_utxos.txt"
UNEXTRACTED_OUTPUT_FILE = DATA_DIRECTORY / "unextracted_utxos.txt"
RESCAN_OUTPUT_FILE = DATA_DIRECTORY / "rescan_start.json"
RESCAN_MANIFEST_FORMAT = "core-wallet-maintenance-rescan-start-v1"
RESCAN_REORG_MARGIN = 6
EXCLUSIVE_CREATE_ATTEMPTS = 32
RPC_CONNECT_TIMEOUT = 10
RPC_READ_TIMEOUT = 180
MAX_COOKIE_FILE_BYTES = 4096
MISSING_COOKIE_ERROR = (
	"RPC cookie file not found; make sure the intended Core instance is running, no hardcoded "
	"rpcuser/rpcpassword credentials are set in bitcoin.conf, and the configured or expected "
	"cookie path is correct"
)


def get_cookie_path() -> Path:
	if COOKIE_FILE is not None:
		configured_path = Path(COOKIE_FILE)
		return configured_path if configured_path.is_absolute() else SCRIPT_DIR / configured_path

	home = Path.home()
	system = platform.system()

	if system == "Windows":
		roaming_directory = Path(
			os.environ.get("APPDATA") or home / "AppData/Roaming"
		) / "Bitcoin"
		if roaming_directory.is_dir():
			return roaming_directory / ".cookie"
		return Path(
			os.environ.get("LOCALAPPDATA") or home / "AppData/Local"
		) / "Bitcoin/.cookie"
	elif system == "Darwin": # macOS (Darwin)
		return home / "Library/Application Support/Bitcoin/.cookie"
	else: # Linux and other Unix-like systems
		return home / ".bitcoin/.cookie"

def is_windows_reparse_point(file_status: os.stat_result) -> bool:
	attributes = getattr(file_status, "st_file_attributes", 0)
	reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
	return bool(attributes & reparse_attribute)

def read_rpc_cookie(cookie_path: Path) -> tuple[str, str]:
	raw_cookie = bytearray(MAX_COOKIE_FILE_BYTES + 1)
	raw_length = 0
	file_descriptor: int | None = None
	cookie_file: Any = None
	cookie_text = ""
	rpc_user = ""
	rpc_pass = ""
	try:
		try:
			path_status = os.lstat(cookie_path)
		except FileNotFoundError:
			raise ToolError(MISSING_COOKIE_ERROR) from None
		except OSError:
			raise ToolError("Could not securely inspect the RPC cookie file") from None

		if (
			stat.S_ISLNK(path_status.st_mode)
			or is_windows_reparse_point(path_status)
			or not stat.S_ISREG(path_status.st_mode)
		):
			raise ToolError("The RPC cookie path is not a secure regular file") from None

		open_flags = os.O_RDONLY
		for flag_name in ("O_BINARY", "O_CLOEXEC", "O_NOINHERIT", "O_NOFOLLOW", "O_NONBLOCK"):
			open_flags |= getattr(os, flag_name, 0)
		try:
			file_descriptor = os.open(cookie_path, open_flags)
		except FileNotFoundError:
			raise ToolError(MISSING_COOKIE_ERROR) from None
		except OSError:
			raise ToolError("Could not securely open the RPC cookie file") from None

		try:
			opened_status = os.fstat(file_descriptor)
		except OSError:
			raise ToolError("Could not securely inspect the open RPC cookie file") from None
		if (
			not stat.S_ISREG(opened_status.st_mode)
			or is_windows_reparse_point(opened_status)
			or not os.path.samestat(path_status, opened_status)
		):
			raise ToolError("The RPC cookie file changed while it was being opened") from None
		if not 1 <= opened_status.st_size <= MAX_COOKIE_FILE_BYTES:
			raise ToolError("The RPC cookie file has an invalid size") from None

		try:
			cookie_file = os.fdopen(file_descriptor, "rb", buffering=0)
			file_descriptor = None
			cookie_view = memoryview(raw_cookie)
			try:
				while raw_length < len(raw_cookie):
					cookie_chunk_view = cookie_view[raw_length:]
					try:
						read_count = cookie_file.readinto(cookie_chunk_view)
					finally:
						cookie_chunk_view.release()
						cookie_chunk_view = None
					if not read_count:
						break
					raw_length += read_count
			finally:
				cookie_view.release()
				cookie_view = None
		except OSError:
			raise ToolError("Could not securely read the RPC cookie file") from None
		if not 1 <= raw_length <= MAX_COOKIE_FILE_BYTES:
			raise ToolError("The RPC cookie file has an invalid size") from None

		content_length = raw_length
		if raw_cookie[content_length - 1] == 0x0A:
			content_length -= 1
			if content_length and raw_cookie[content_length - 1] == 0x0D:
				content_length -= 1
		if content_length == 0:
			raise ToolError("The RPC cookie file has invalid contents") from None
		if any(
			raw_cookie[index] < 0x20 or raw_cookie[index] > 0x7E
			for index in range(content_length)
		):
			raise ToolError("The RPC cookie file has invalid contents") from None

		cookie_text = raw_cookie[:content_length].decode("ascii")
		try:
			rpc_user, rpc_pass = cookie_text.split(":", 1)
		except ValueError:
			raise ToolError("The RPC cookie file has invalid contents") from None
		if not rpc_user or not rpc_pass:
			raise ToolError("The RPC cookie file has invalid contents") from None
		return rpc_user, rpc_pass
	finally:
		cookie_text = ""
		rpc_user = ""
		rpc_pass = ""
		if cookie_file is not None:
			try:
				cookie_file.close()
			except OSError:
				pass
		elif file_descriptor is not None:
			try:
				os.close(file_descriptor)
			except OSError:
				pass
		for index in range(len(raw_cookie)):
			raw_cookie[index] = 0
		raw_cookie.clear()

def clear_prepared_request_data(prepared_request: Any) -> None:
	if prepared_request is None:
		return
	try:
		prepared_request.body = None
	except Exception:
		pass
	try:
		headers = prepared_request.headers
	except Exception:
		headers = None
	if headers is not None:
		try:
			headers.pop("Authorization", None)
		except Exception:
			pass

def clear_rpc_response_data(response: Any) -> bool:
	if response is None:
		return False
	try:
		prepared_request = getattr(response, "request", None)
	except Exception:
		prepared_request = None
	clear_prepared_request_data(prepared_request)
	try:
		response.request = None
	except Exception:
		pass
	try:
		response.headers.pop("Authorization", None)
	except Exception:
		pass
	try:
		response._content = b""
	except Exception:
		pass
	close_failed = False
	try:
		response.close()
	except Exception:
		close_failed = True
	try:
		response.raw = None
	except Exception:
		pass
	return close_failed

def clear_exception_private_data(exception: BaseException) -> None:
	pending: list[BaseException] = [exception]
	seen: set[int] = set()
	while pending:
		current = pending.pop()
		identity = id(current)
		if identity in seen:
			continue
		seen.add(identity)
		try:
			context = current.__context__
		except Exception:
			context = None
		try:
			cause = current.__cause__
		except Exception:
			cause = None
		if isinstance(context, BaseException):
			pending.append(context)
		if isinstance(cause, BaseException):
			pending.append(cause)
		try:
			prepared_request = getattr(current, "request", None)
		except Exception:
			prepared_request = None
		clear_prepared_request_data(prepared_request)
		try:
			response = getattr(current, "response", None)
		except Exception:
			response = None
		clear_rpc_response_data(response)
		try:
			current.request = None
		except Exception:
			pass
		try:
			current.response = None
		except Exception:
			pass
		for attribute, replacement in (
			("doc", ""),
			("msg", ""),
			("pos", 0),
			("lineno", 0),
			("colno", 0),
		):
			try:
				if hasattr(current, attribute):
					setattr(current, attribute, replacement)
			except Exception:
				pass
		try:
			current.args = ()
		except Exception:
			pass
		try:
			current.__traceback__ = None
		except Exception:
			pass
		try:
			current.__context__ = None
		except Exception:
			pass
		try:
			current.__cause__ = None
		except Exception:
			pass

class RpcClient:
	def __init__(self) -> None:
		self._request_id = 0
		self._auth: list[str] = []
		self._session: requests.Session | None = None
		rpc_user = ""
		rpc_pass = ""
		try:
			rpc_user, rpc_pass = read_rpc_cookie(get_cookie_path())
			self._auth.extend((rpc_user, rpc_pass))
			self._session = requests.Session()
			adapter = requests.adapters.HTTPAdapter(
				pool_connections=1,
				pool_maxsize=1,
				max_retries=0,
				pool_block=True,
			)
			self._session.mount("http://", adapter)
			self._session.auth = (self._auth[0], self._auth[1])
			self._session.headers.update(
				{
					"Accept": "application/json",
					"Content-Type": "application/json",
				}
			)
			self._session.trust_env = False
		except ToolError:
			self.close()
			raise
		except Exception as exc:
			self.close()
			raise RpcTransportError("Could not initialize the RPC HTTP session") from exc
		finally:
			rpc_user = ""
			rpc_pass = ""

	def close(self) -> None:
		session = self._session
		self._session = None
		if session is not None:
			try:
				session.auth = None
				session.headers.pop("Authorization", None)
			except Exception:
				pass
		try:
			if session is not None:
				session.close()
		except Exception:
			print("[WARNING] Could not close the RPC HTTP session.", file=sys.stderr)
		finally:
			for index in range(len(self._auth)):
				self._auth[index] = ""
			self._auth.clear()

	def call(self, method: str, *params: Any) -> Any:
		if self._session is None:
			params = ()
			raise RpcTransportError("The RPC HTTP session is closed")
		if not isinstance(method, str) or not method:
			params = ()
			raise RpcTransportError("An invalid RPC method was requested")

		self._request_id += 1
		request_id = self._request_id
		payload = {
			"jsonrpc": "1.0",
			"id": request_id,
			"method": method,
			"params": list(params),
		}
		response: Any = None
		post_error_message: str | None = None
		try:
			response = self._session.post(
				url,
				json=payload,
				timeout=(RPC_CONNECT_TIMEOUT, RPC_READ_TIMEOUT),
				allow_redirects=False,
			)
		except requests.Timeout as exc:
			clear_exception_private_data(exc)
			post_error_message = f"RPC call {method} timed out"
		except (requests.ConnectionError, requests.RequestException, TypeError, ValueError) as exc:
			error_name = type(exc).__name__
			clear_exception_private_data(exc)
			post_error_message = f"RPC connection failed during {method} ({error_name})"
		finally:
			params = ()
			payload["params"] = []
			payload.clear()
		if post_error_message is not None:
			raise RpcTransportError(post_error_message) from None

		status_code = response.status_code
		envelope: Any = None
		result: Any = None
		error: Any = None
		message = ""
		detail = ""
		response_id: Any = None
		code: Any = None
		response_cleanup_failed = False
		try:
			if status_code in {401, 403}:
				raise RpcTransportError(
					"RPC authentication failed; the cookie may be stale or belong to a different "
					"Core instance or data directory. Make sure the intended Core instance is "
					"running with the correct data directory, then restart this tool to reload the cookie"
				)
			if status_code not in {200, 400, 404, 500}:
				raise RpcTransportError(
					f"RPC call {method} returned HTTP status {status_code}"
				)
			try:
				envelope = response.json()
			except ValueError as exc:
				clear_exception_private_data(exc)
				invalid_json = True
			else:
				invalid_json = False
			if invalid_json:
				raise RpcTransportError(f"RPC call {method} returned invalid JSON") from None
		finally:
			response_cleanup_failed = clear_rpc_response_data(response)
			response = None

		try:
			if response_cleanup_failed:
				raise RpcTransportError(f"RPC connection failed during {method}") from None
			if not isinstance(envelope, dict):
				raise RpcTransportError(f"RPC call {method} returned an invalid JSON-RPC envelope")
			response_id = envelope.get("id")
			if not isinstance(response_id, int) or isinstance(response_id, bool) or response_id != request_id:
				raise RpcTransportError(f"RPC call {method} returned an invalid response ID")
			if "result" not in envelope or "error" not in envelope:
				raise RpcTransportError(f"RPC call {method} returned an invalid JSON-RPC result")
			error = envelope["error"]
			if error is not None:
				if not isinstance(error, dict):
					raise RpcTransportError(f"RPC call {method} returned an invalid JSON-RPC error")
				code = error.get("code")
				message = error.get("message")
				if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str):
					raise RpcTransportError(f"RPC call {method} returned an invalid JSON-RPC error")
				detail = redact_error(message)
				raise ToolError(f"RPC call {method} failed with code {code}: {detail}")
			if status_code != 200:
				raise RpcTransportError(f"RPC call {method} returned HTTP status {status_code}")
			result = envelope["result"]
			return result
		finally:
			envelope = None
			result = None
			error = None
			message = ""
			detail = ""
			response_id = None
			code = None

def create_exclusive_file(directory: Path, prefix: str, suffix: str) -> tuple[int, Path]:
	try:
		directory.mkdir(parents=True, exist_ok=True)
	except OSError as exc:
		raise ToolError(f"Could not create data directory {directory}: {exc}") from exc
	if not directory.is_dir():
		raise ToolError(f"Data directory is not a directory: {directory}")

	flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
	if hasattr(os, "O_BINARY"):
		flags |= os.O_BINARY
	for _attempt in range(EXCLUSIVE_CREATE_ATTEMPTS):
		path = directory / f"{prefix}{secrets.token_hex(8)}{suffix}"
		try:
			file_descriptor = os.open(path, flags, 0o600)
		except FileExistsError:
			continue
		except OSError as exc:
			raise ToolError(f"Data directory is not writable: {directory}") from exc
		return file_descriptor, path
	raise ToolError(f"Could not create a unique temporary file in {directory}")

def remove_private_temporary_file(path: Path) -> None:
	try:
		path.unlink()
	except FileNotFoundError:
		pass
	except OSError:
		print(f"[WARNING] Could not remove private temporary file: {path}", file=sys.stderr)

def validate_output_directory(paths: tuple[Path, ...]) -> None:
	parents = {path.parent.resolve() for path in paths}
	if len(parents) != 1:
		raise ToolError("All export files must use the same data directory")
	directory = next(iter(parents))
	for path in paths:
		if path.is_symlink() or (path.exists() and not path.is_file()):
			raise ToolError(f"Export target is not a regular file: {path}")

	file_descriptor, probe_path = create_exclusive_file(
		directory,
		".wallet-maintenance-write-test-",
		".tmp",
	)
	try:
		os.close(file_descriptor)
		file_descriptor = -1
		probe_path.unlink()
	except OSError as exc:
		if file_descriptor >= 0:
			try:
				os.close(file_descriptor)
			except OSError:
				pass
		remove_private_temporary_file(probe_path)
		raise ToolError(f"Data directory failed its write/delete test: {directory}") from exc

def validate_wallet(rpc: RpcClient) -> None:
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
	if info.get("scanning") is not False:
		raise ToolError("The loaded wallet is currently scanning; wait until the scan is complete")

def ensure_wallet_alive(rpc: RpcClient) -> None:
	info = rpc.call("getwalletinfo")
	if not isinstance(info, dict):
		raise ToolError("Wallet liveness check returned an invalid getwalletinfo result")

def single_line_text(value: object) -> str:
	return " ".join(str(value).split())

def error_log_line(*parts: object) -> str:
	identifiers = [single_line_text(part) for part in parts[:-1]]
	message = redact_error(str(parts[-1]))
	return " | ".join((*identifiers, message))

def load_private_descriptors(rpc: RpcClient) -> tuple[Any, list[dict[str, Any]]]:
	try:
		private_data = rpc.call("listdescriptors", True)
	except RpcTransportError:
		raise
	except ToolError as exc:
		raise ToolError(
			f"Could not read private descriptors. Unlock an encrypted wallet first. {exc}"
		) from exc

	descriptors = private_data.get("descriptors") if isinstance(private_data, dict) else None
	if not isinstance(descriptors, list) or not all(isinstance(entry, dict) for entry in descriptors):
		clear_private_descriptor_data(private_data)
		raise ToolError("listdescriptors true returned no valid descriptor list")
	return private_data, descriptors

def valid_block_hash(value: Any) -> bool:
	return (
		isinstance(value, str)
		and len(value) == 64
		and all(character in "0123456789abcdefABCDEF" for character in value)
	)

def active_chain_tip(rpc: RpcClient, expected_chain: str) -> int:
	info = rpc.call("getblockchaininfo")
	if not isinstance(info, dict) or info.get("chain") != expected_chain:
		raise ToolError("getblockchaininfo returned an inconsistent chain")
	tip_height = info.get("blocks")
	if not isinstance(tip_height, int) or isinstance(tip_height, bool) or tip_height < 0:
		raise ToolError("getblockchaininfo returned an invalid block height")
	return tip_height

def collect_utxo_inventory(rpc: RpcClient) -> tuple[list[str], list[str], list[int], int]:
	utxos = rpc.call("listunspent", 0)
	if not isinstance(utxos, list):
		raise ToolError("listunspent returned an invalid result")

	addresses: set[str] = set()
	txids: set[str] = set()
	errors: list[str] = []
	for entry in utxos:
		if not isinstance(entry, dict):
			raise ToolError("listunspent returned an invalid UTXO entry")
		if entry.get("spendable") is not True or entry.get("solvable") is not True:
			continue
		txid = entry.get("txid")
		vout = entry.get("vout")
		if (
			not isinstance(txid, str)
			or len(txid) != 64
			or any(character not in "0123456789abcdef" for character in txid)
			or not isinstance(vout, int)
			or isinstance(vout, bool)
			or vout < 0
		):
			raise ToolError("listunspent returned an invalid spendable and solvable outpoint")
		txids.add(txid)
		address = entry.get("address")
		if isinstance(address, str) and address:
			addresses.add(address)
			continue
		errors.append(
			error_log_line(
				f"{txid}:{vout}",
				"listunspent returned no address for a spendable and solvable UTXO",
			)
		)

	funding_heights: list[int] = []
	unconfirmed_count = 0
	for txid in sorted(txids):
		transaction = rpc.call("gettransaction", txid)
		if not isinstance(transaction, dict):
			raise ToolError(f"gettransaction returned an invalid result for UTXO transaction {txid}")
		returned_txid = transaction.get("txid")
		if not valid_block_hash(returned_txid) or returned_txid.lower() != txid:
			raise ToolError(f"gettransaction returned the wrong UTXO transaction for {txid}")
		confirmations = transaction.get("confirmations")
		if not isinstance(confirmations, int) or isinstance(confirmations, bool):
			raise ToolError(f"gettransaction returned invalid confirmations for UTXO transaction {txid}")
		if confirmations < 0:
			raise ToolError(f"A conflicted transaction was returned as a current UTXO: {txid}")
		if confirmations == 0:
			if "blockheight" in transaction:
				raise ToolError(f"gettransaction returned inconsistent block data for {txid}")
			unconfirmed_count += 1
			continue
		block_height = transaction.get("blockheight")
		if (
			not isinstance(block_height, int)
			or isinstance(block_height, bool)
			or block_height < 0
		):
			raise ToolError(f"gettransaction returned an invalid blockheight for UTXO transaction {txid}")
		funding_heights.append(block_height)
	return sorted(addresses), errors, funding_heights, unconfirmed_count

def build_rescan_manifest(
	rpc: RpcClient,
	chain: str,
	initial_tip_height: int,
	final_tip_height: int,
	funding_heights: list[int],
) -> dict[str, Any]:
	if any(height > final_tip_height for height in funding_heights):
		raise ToolError("A current UTXO has a block height above the active chain tip")
	base_height = min(initial_tip_height, final_tip_height, *funding_heights)
	start_height = max(0, base_height - RESCAN_REORG_MARGIN)
	start_blockhash = rpc.call("getblockhash", start_height)
	if not valid_block_hash(start_blockhash):
		raise ToolError(f"getblockhash {start_height} returned an invalid block hash")
	return {
		"format": RESCAN_MANIFEST_FORMAT,
		"chain": chain,
		"start_height": start_height,
		"start_blockhash": start_blockhash.lower(),
	}

def valid_timestamp(value: Any) -> bool:
	return value == "now" or (
		isinstance(value, int)
		and not isinstance(value, bool)
		and value >= 0
	)

def normalize_range(value: Any) -> list[int] | None:
	if not isinstance(value, list) or len(value) != 2:
		return None
	if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
		return None
	start, end = value
	return [start, end] if 0 <= start <= end else None

def build_hd_import_requests(
	rpc: RpcClient,
	descriptors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
	requests: list[dict[str, Any]] = []
	seen: set[bytes] = set()
	for entry in descriptors:
		descriptor = entry.get("desc")
		range_value = normalize_range(entry.get("range"))
		if not isinstance(descriptor, str) or range_value is None:
			continue

		info = rpc.call("getdescriptorinfo", descriptor)
		if not isinstance(info, dict) or info.get("isrange") is not True:
			raise ToolError("A ranged wallet descriptor failed descriptor validation")
		if info.get("hasprivatekeys") is not True:
			raise ToolError("A ranged wallet descriptor does not contain private keys")

		digest = hashlib.sha256(descriptor.encode("utf-8")).digest()
		if digest in seen:
			raise ToolError("listdescriptors returned a duplicate ranged descriptor")
		seen.add(digest)

		timestamp = entry.get("timestamp")
		if not valid_timestamp(timestamp):
			raise ToolError("A ranged wallet descriptor has an invalid timestamp")
		request: dict[str, Any] = {
			"desc": descriptor,
			"timestamp": timestamp,
			"range": range_value,
		}

		active = entry.get("active")
		internal = entry.get("internal")
		if not isinstance(active, bool):
			raise ToolError("A ranged wallet descriptor has no valid active state")
		if active and not isinstance(internal, bool):
			raise ToolError("An active ranged wallet descriptor has no valid internal state")
		request["active"] = active
		if isinstance(internal, bool):
			request["internal"] = internal

		next_index = entry.get("next_index", entry.get("next"))
		if not isinstance(next_index, int) or isinstance(next_index, bool) or next_index < 0:
			raise ToolError("A ranged wallet descriptor has an invalid next index")
		if not range_value[0] <= next_index <= range_value[1]:
			raise ToolError("A ranged wallet descriptor next index is outside its range")
		request["next_index"] = next_index
		requests.append(request)
	return requests

def build_descriptor_search_index(
	rpc: RpcClient,
	descriptors: list[dict[str, Any]],
	wif_prefix: int,
) -> tuple[
	list[dict[str, Any]],
	dict[str, list[dict[str, Any]]],
	dict[str, list[dict[str, Any]]],
]:
	ranged_descriptors: list[dict[str, Any]] = []
	ranged_by_parent: dict[str, list[dict[str, Any]]] = {}
	imported_by_pubkey: dict[str, list[dict[str, Any]]] = {}
	public_by_private_id: dict[int, str] = {}
	public_data = rpc.call("listdescriptors", False)
	try:
		public_descriptors = public_data.get("descriptors") if isinstance(public_data, dict) else None
		if isinstance(public_descriptors, list) and len(public_descriptors) == len(descriptors):
			for private_entry, public_entry in zip(descriptors, public_descriptors):
				public_descriptor = public_entry.get("desc") if isinstance(public_entry, dict) else None
				private_descriptor = parse_single_key_descriptor(private_entry.get("desc"))
				public_parsed = parse_single_key_descriptor(public_descriptor)
				if (
					isinstance(public_descriptor, str)
					and descriptor_range(private_entry) == descriptor_range(public_entry)
					and private_entry.get("active") == public_entry.get("active")
					and private_entry.get("internal") == public_entry.get("internal")
					and private_entry.get("next_index", private_entry.get("next"))
					== public_entry.get("next_index", public_entry.get("next"))
					and private_descriptor is not None
					and public_parsed is not None
					and private_descriptor.kind == public_parsed.kind
				):
					public_by_private_id[id(private_entry)] = public_descriptor
	finally:
		clear_private_descriptor_data(public_data)

	for entry in descriptors:
		parsed = parse_single_key_descriptor(entry.get("desc"))
		if descriptor_range(entry) is not None or (
			parsed is not None and parse_extended_private_key(parsed.key_expression) is not None
		):
			ranged_descriptors.append(entry)
			parent = public_by_private_id.get(id(entry))
			if isinstance(parent, str):
				ranged_by_parent.setdefault(parent, []).append(entry)
			continue
		if parsed is None:
			continue
		try:
			without_origin, _origin = strip_key_origin(parsed.key_expression)
			if "/" in without_origin:
				continue
			private_key, compressed_wif, _prefix = decode_wif(without_origin, wif_prefix)
		except ValueError:
			continue
		compressed, uncompressed = public_keys_from_private(private_key)
		pubkeys = [compressed if compressed_wif else uncompressed]
		if compressed_wif:
			pubkeys.append(compressed[2:])
		for pubkey in pubkeys:
			imported_by_pubkey.setdefault(pubkey, []).append(entry)
	return ranged_descriptors, ranged_by_parent, imported_by_pubkey

def imported_candidates(
	address_info: dict[str, Any],
	imported_by_pubkey: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
	candidates: list[dict[str, Any]] = []
	seen: set[int] = set()
	for pubkey in collect_target_pubkeys(address_info):
		for entry in imported_by_pubkey.get(pubkey, []):
			identity = id(entry)
			if identity not in seen:
				seen.add(identity)
				candidates.append(entry)
	return candidates

def extract_address_request(
	rpc: RpcClient,
	ranged_descriptors: list[dict[str, Any]],
	ranged_by_parent: dict[str, list[dict[str, Any]]],
	imported_by_pubkey: dict[str, list[dict[str, Any]]],
	address: str,
	wif_prefix: int,
) -> dict[str, Any]:
	address_info = rpc.call("getaddressinfo", address)
	if not isinstance(address_info, dict):
		raise ToolError("getaddressinfo returned an invalid result")
	if address_info.get("ismine") is not True:
		raise ToolError("The UTXO address is not owned by the loaded wallet")
	if address_info.get("solvable") is not True:
		raise ToolError("The loaded wallet cannot solve the UTXO address")

	canonical_address = address_info.get("address")
	if isinstance(canonical_address, str):
		address = canonical_address

	result: ExtractionResult | None = None
	try:
		embedded = address_info.get("embedded")
		parent = address_info.get("parent_desc")
		if not isinstance(parent, str) and isinstance(embedded, dict):
			parent = embedded.get("parent_desc")
		hd_candidates = (
			ranged_by_parent.get(parent, ranged_descriptors)
			if isinstance(parent, str)
			else ranged_descriptors
		)
		result = find_hd_result(rpc, hd_candidates, address_info, address, wif_prefix)
		if result is None and hd_candidates is not ranged_descriptors:
			result = find_hd_result(rpc, ranged_descriptors, address_info, address, wif_prefix)
		if result is None:
			candidates = imported_candidates(address_info, imported_by_pubkey)
			result = find_imported_result(rpc, candidates, address_info, address, wif_prefix)
		if result is None:
			raise ToolError("No matching private single-key descriptor was found")

		timestamp = address_info.get("timestamp", 0)
		if not valid_timestamp(timestamp):
			raise ToolError("The UTXO address has an invalid timestamp")
		request: dict[str, Any] = {
			"desc": result.private_descriptor,
			"timestamp": timestamp,
		}

		internal = address_info.get("ischange")
		labels = address_info.get("labels")
		label = None
		if isinstance(labels, list):
			label = next((item for item in labels if isinstance(item, str) and item), None)
		if internal is True:
			request["internal"] = True
		elif label is not None:
			request["label"] = label
		elif internal is False:
			request["internal"] = False
		return request
	finally:
		if result is not None:
			result.wif = ""
			result.private_descriptor = ""

def build_utxo_import_requests(
	rpc: RpcClient,
	ranged_descriptors: list[dict[str, Any]],
	ranged_by_parent: dict[str, list[dict[str, Any]]],
	imported_by_pubkey: dict[str, list[dict[str, Any]]],
	addresses: list[str],
	wif_prefix: int,
) -> tuple[list[dict[str, Any]], list[str]]:
	requests: list[dict[str, Any]] = []
	seen: set[bytes] = set()
	errors: list[str] = []
	for index, address in enumerate(addresses, 1):
		try:
			request = extract_address_request(
				rpc,
				ranged_descriptors,
				ranged_by_parent,
				imported_by_pubkey,
				address,
				wif_prefix,
			)
		except RpcTransportError:
			raise
		except (ToolError, ValueError) as exc:
			ensure_wallet_alive(rpc)
			errors.append(error_log_line(address, exc))
			continue

		descriptor = request["desc"]
		digest = hashlib.sha256(descriptor.encode("utf-8")).digest()
		if digest not in seen:
			seen.add(digest)
			requests.append(request)
		else:
			clear_private_descriptor_data(request)

		if index % 500 == 0 or index == len(addresses):
			print(f"  {index:,}/{len(addresses):,} UTXO addresses processed ...")
	return requests, errors

def stage_lines(path: Path, lines: Iterable[str]) -> Path:
	iterator = iter(lines)
	try:
		first_line = next(iterator)
	except StopIteration as exc:
		raise ToolError(f"Refusing to create an empty export file: {path}") from exc

	file_descriptor, temporary_path = create_exclusive_file(
		path.parent,
		f".{path.name}.",
		".tmp",
	)
	try:
		with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
			file_descriptor = -1
			handle.write(first_line + "\n")
			for line in iterator:
				handle.write(line + "\n")
			handle.flush()
			os.fsync(handle.fileno())
		return temporary_path
	except BaseException:
		if file_descriptor >= 0:
			try:
				os.close(file_descriptor)
			except OSError:
				pass
		remove_private_temporary_file(temporary_path)
		raise

def stage_json_lines(path: Path, records: list[dict[str, Any]]) -> Path:
	lines = (
		json.dumps(record, separators=(",", ":"), ensure_ascii=False)
		for record in records
	)
	return stage_lines(path, lines)

def stage_json_object(path: Path, record: dict[str, Any]) -> Path:
	return stage_lines(
		path,
		(json.dumps(record, separators=(",", ":"), ensure_ascii=False),),
	)

def stage_text_lines(path: Path, lines: list[str]) -> Path:
	return stage_lines(path, (single_line_text(line) for line in lines))

def reserve_backup_path(path: Path) -> Path:
	file_descriptor, backup_path = create_exclusive_file(
		path.parent,
		f".{path.name}.",
		".bak",
	)
	os.close(file_descriptor)
	return backup_path

def commit_staged_files(
	staged: list[tuple[Path, Path]],
	removed: tuple[Path, ...] = (),
) -> None:
	staged_targets = [final_path for _temporary_path, final_path in staged]
	targets = staged_targets + list(removed)
	if len(set(targets)) != len(targets):
		raise ToolError("Each export target may only be changed once per commit")

	backups: list[tuple[Path, Path | None]] = []
	committed: set[Path] = set()
	try:
		for final_path in targets:
			if final_path.exists():
				backup_path = reserve_backup_path(final_path)
				try:
					os.replace(final_path, backup_path)
				except BaseException:
					try:
						backup_path.unlink(missing_ok=True)
					except OSError:
						pass
					raise
				backups.append((final_path, backup_path))
			else:
				backups.append((final_path, None))

		for temporary_path, final_path in staged:
			os.replace(temporary_path, final_path)
			committed.add(final_path)
			try:
				os.chmod(final_path, 0o600)
			except OSError:
				pass
	except BaseException as exc:
		rollback_failed = False
		for final_path, backup_path in reversed(backups):
			try:
				if backup_path is not None:
					os.replace(backup_path, final_path)
				elif backup_path is None and final_path in committed:
					final_path.unlink(missing_ok=True)
			except OSError:
				rollback_failed = True
		if rollback_failed:
			raise ToolError(
				"The export-file commit failed and rollback was incomplete; preserve any .bak files"
			) from exc
		raise
	else:
		for _final_path, backup_path in backups:
			if backup_path is not None:
				try:
					backup_path.unlink(missing_ok=True)
				except OSError:
					print(
						f"[WARNING] Could not remove private rollback backup: {backup_path}",
						file=sys.stderr,
					)

def run_export() -> None:
	output_files = (
		HD_OUTPUT_FILE,
		UTXO_OUTPUT_FILE,
		UNEXTRACTED_OUTPUT_FILE,
		RESCAN_OUTPUT_FILE,
	)
	validate_output_directory(output_files)
	print(f"Data directory: {HD_OUTPUT_FILE.parent}")
	rpc: RpcClient | None = None
	private_data: Any = None
	rescan_manifest: dict[str, Any] = {}
	hd_requests: list[dict[str, Any]] = []
	utxo_requests: list[dict[str, Any]] = []
	ranged_descriptors: list[dict[str, Any]] = []
	ranged_by_parent: dict[str, list[dict[str, Any]]] = {}
	imported_by_pubkey: dict[str, list[dict[str, Any]]] = {}
	errors: list[str] = []
	staged: list[tuple[Path, Path]] = []
	try:
		rpc = RpcClient()
		chain, wif_prefix = network_wif_prefix(rpc)
		validate_wallet(rpc)
		initial_tip_height = active_chain_tip(rpc, chain)
		addresses, inventory_errors, funding_heights, unconfirmed_count = collect_utxo_inventory(rpc)
		final_tip_height = active_chain_tip(rpc, chain)
		rescan_manifest = build_rescan_manifest(
			rpc,
			chain,
			initial_tip_height,
			final_tip_height,
			funding_heights,
		)
		errors.extend(inventory_errors)
		print(f"Chain: {chain}; spendable UTXO addresses: {len(addresses):,}")
		print(
			f"Confirmed UTXO funding transactions: {len(funding_heights):,}; "
			f"unconfirmed: {unconfirmed_count:,}"
		)
		print(
			f"Rescan start: block {rescan_manifest['start_height']:,} "
			f"({RESCAN_REORG_MARGIN}-block reorganization margin)"
		)

		private_data, descriptors = load_private_descriptors(rpc)
		print(f"Private wallet descriptors loaded: {len(descriptors):,}")

		hd_requests = build_hd_import_requests(rpc, descriptors)
		ranged_descriptors, ranged_by_parent, imported_by_pubkey = build_descriptor_search_index(
			rpc,
			descriptors,
			wif_prefix,
		)
		utxo_requests, extraction_errors = build_utxo_import_requests(
			rpc,
			ranged_descriptors,
			ranged_by_parent,
			imported_by_pubkey,
			addresses,
			wif_prefix,
		)
		errors.extend(extraction_errors)

		output_existed = {path: path.exists() for path in output_files}
		removed: list[Path] = []
		if hd_requests:
			staged.append((stage_json_lines(HD_OUTPUT_FILE, hd_requests), HD_OUTPUT_FILE))
		else:
			removed.append(HD_OUTPUT_FILE)
		if utxo_requests:
			staged.append((stage_json_lines(UTXO_OUTPUT_FILE, utxo_requests), UTXO_OUTPUT_FILE))
		else:
			removed.append(UTXO_OUTPUT_FILE)
		if errors:
			staged.append((stage_text_lines(UNEXTRACTED_OUTPUT_FILE, errors), UNEXTRACTED_OUTPUT_FILE))
		else:
			removed.append(UNEXTRACTED_OUTPUT_FILE)
		staged.append((stage_json_object(RESCAN_OUTPUT_FILE, rescan_manifest), RESCAN_OUTPUT_FILE))
		commit_staged_files(staged, tuple(removed))
		staged.clear()

		if hd_requests:
			print(f"HD private descriptor records written: {len(hd_requests):,} ({HD_OUTPUT_FILE})")
		elif output_existed[HD_OUTPUT_FILE]:
			print(f"HD private descriptor records written: 0 (stale file removed: {HD_OUTPUT_FILE})")
		else:
			print("HD private descriptor records written: 0 (no file present)")
		if utxo_requests:
			print(f"UTXO private descriptor records written: {len(utxo_requests):,} ({UTXO_OUTPUT_FILE})")
		elif output_existed[UTXO_OUTPUT_FILE]:
			print(f"UTXO private descriptor records written: 0 (stale file removed: {UTXO_OUTPUT_FILE})")
		else:
			print("UTXO private descriptor records written: 0 (no file present)")
		if errors:
			print(
				f"[WARNING] UTXO entries not extracted: {len(errors):,} ({UNEXTRACTED_OUTPUT_FILE})",
				file=sys.stderr,
			)
			print("Export completed with warnings; all successfully extracted records were written.")
		else:
			if output_existed[UNEXTRACTED_OUTPUT_FILE]:
				print(
					f"UTXO extraction error log: 0 records (stale file removed: {UNEXTRACTED_OUTPUT_FILE})"
				)
			else:
				print("UTXO extraction error log: 0 records (no file present)")
			print("All spendable UTXO addresses were extracted successfully.")
		print(f"Rescan manifest written: {RESCAN_OUTPUT_FILE}")
	finally:
		try:
			for temporary_path, _final_path in staged:
				remove_private_temporary_file(temporary_path)
			clear_private_descriptor_data(hd_requests)
			clear_private_descriptor_data(utxo_requests)
			ranged_descriptors.clear()
			ranged_by_parent.clear()
			imported_by_pubkey.clear()
			rescan_manifest.clear()
			had_private_data = isinstance(private_data, (dict, list))
			clear_private_descriptor_data(private_data)
			if had_private_data:
				print("Temporary private descriptor data released (best-effort).")
		finally:
			if rpc is not None:
				rpc.close()

def main() -> int:
	remove_bytecode_cache()
	try:
		run_export()
	except (ToolError, ValueError, OSError) as exc:
		print(f"ERROR: {exc}", file=sys.stderr)
		return 1
	print("Done!")
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
