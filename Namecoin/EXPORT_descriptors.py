################################################################################################################

# Copyright (C) 2025 by Uwe Martens * www.namecoin.pro  * https://dotbit.app

################################################################################################################

import requests
import re
import hashlib
import hmac
import struct
import binascii
from ecdsa import SigningKey, SECP256k1
from collections import defaultdict

# ---------------- CONFIG ----------------
rpc_user = "XXXXXXX"  # rpcuser from namecoin.conf
rpc_pass = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # rpcpassword from namecoin.conf
url = "http://127.0.0.1:8336/"

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=4, max_retries=3, pool_block=False)
session.mount(url, adapter)
session.auth = (rpc_user, rpc_pass)
session.headers.update({"Content-Type": "application/json"})
session.timeout = 30

NAMECOIN_WIF_PREFIX = b'\xb4'
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# ---------------- util: base58 ----------------
def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n != 0 else b''
    leading = 0
    for ch in s:
        if ch == B58_ALPHABET[0]:
            leading += 1
        else:
            break
    return b'\x00' * leading + full

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(ord(B58_ALPHABET[r]))
    leading = 0
    for c in b:
        if c == 0:
            leading += 1
        else:
            break
    if res:
        return B58_ALPHABET[0] * leading + bytes(reversed(res)).decode()
    else:
        return B58_ALPHABET[0] * leading

def base58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5:
        raise ValueError("Too short for base58check")
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        raise ValueError("Invalid checksum")
    return payload

def base58check_encode(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

def priv_to_wif(priv_bytes: bytes, compressed=True) -> str:
    payload = NAMECOIN_WIF_PREFIX + priv_bytes
    if compressed:
        payload += b'\x01'
    return base58check_encode(payload)

# ---------------- util: pubkey from priv / wif ----------------
def compute_pubkey_from_priv(priv: bytes, compressed=True):
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.verifying_key
    if compressed:
        prefix = b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03'
        return (prefix + vk.to_string()[:32]).hex()
    else:
        return '04' + vk.to_string().hex()

def compute_pubkey_from_wif(wif: str):
    dec = base58check_decode(wif)
    priv = dec[1:]
    compressed = False
    if len(priv) == 33 and priv[-1] == 1:
        priv = priv[:-1]
        compressed = True
    return compute_pubkey_from_priv(priv, compressed)

# ---------------- util: BIP32 parse/derive ----------------
def parse_path(path_str: str):
    if not path_str:
        return []
    if path_str.startswith('m'):
        path_str = path_str[1:]
        if path_str.startswith('/'):
            path_str = path_str[1:]
    parts = path_str.split('/') if path_str else []
    path = []
    for p in parts:
        if not p:
            continue
        hardened = p.endswith('h') or p.endswith("'") or p.endswith("H")
        if hardened:
            p = p[:-1]
        try:
            idx = int(p)
        except Exception:
            continue
        if hardened:
            idx += 2**31
        path.append(idx)
    return path

def base58check_decode_quiet(s: str):
    try:
        return base58check_decode(s)
    except Exception:
        return None

def compute_fingerprint_from_xprv(xprv: str):
    dec = base58check_decode_quiet(xprv)
    if not dec or len(dec) != 78:
        return None
    key = dec[45:]
    if key[0] != 0:
        return None
    priv = key[1:]
    pub = compute_pubkey_from_priv(priv)
    h = hashlib.sha256(bytes.fromhex(pub)).digest()
    rip = hashlib.new('ripemd160', h).digest()
    return rip[:4].hex()

def derive_priv(xpriv: str, relative_path: list):
    dec = base58check_decode_quiet(xpriv)
    if not dec or len(dec) != 78:
        return None
    chaincode = dec[13:45]
    key = dec[45:]
    if key[0] != 0:
        return None
    current_priv = key[1:]
    current_chaincode = chaincode
    for idx in relative_path:
        hardened = idx >= 2**31
        if hardened:
            data = b'\x00' + current_priv + struct.pack(">I", idx)
        else:
            sk = SigningKey.from_string(current_priv, curve=SECP256k1)
            vk = sk.verifying_key
            prefix = b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03'
            pub = prefix + vk.to_string()[:32]
            data = pub + struct.pack(">I", idx)
        I = hmac.new(current_chaincode, data, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        il_int = int.from_bytes(Il, 'big')
        if il_int >= SECP256k1.order:
            return None
        child_int = (il_int + int.from_bytes(current_priv, 'big')) % SECP256k1.order
        if child_int == 0:
            return None
        current_priv = child_int.to_bytes(32, 'big')
        current_chaincode = Ir
    return current_priv

# ---------------- RPC helper ----------------
def rpc_call(method, params=None):
    if params is None:
        params = []
    payload = {"jsonrpc": "1.0", "id": "script", "method": method, "params": params}
    r = session.post(url, json=payload)
    r.raise_for_status()
    return r.json()

# ---------------- Build private descriptor from public and WIF ----------------
def build_priv_desc(public_desc, wif):
    if not public_desc:
        return None
    base = public_desc.split('#')[0]
    # Determine the type and replace the key part with WIF
    if base.startswith('pkh(') and base.endswith(')'):
        new_base = 'pkh(' + wif + ')'
    elif base.startswith('wpkh(') and base.endswith(')'):
        new_base = 'wpkh(' + wif + ')'
    elif base.startswith('sh(wpkh(') and base.endswith('))'):
        new_base = 'sh(wpkh(' + wif + '))'
    # More types possible if needed, e.g., 'wsh(', etc.
    else:
        return None
    # Get checksum
    try:
        res = rpc_call("getdescriptorinfo", [new_base])
        if 'result' in res and 'checksum' in res['result']:
            checksum = res['result']['checksum']
            return new_base + '#' + checksum
        else:
            return None
    except Exception as e:
        return None

# ---------------- gather relevant addresses ----------------
print("Loading names (name_list) and filtering ismine==true ...")
names = []
try:
    res = rpc_call("name_list", [])
    all_names = res.get("result", []) or []
    names = [n for n in all_names if n.get("ismine") is True]
    print(f"→ {len(names):,} ismine names found")
except Exception as e:
    print("Error with name_list:", e)

name_addresses = set()
for n in names:
    try:
        nm = n.get("name")
        r = rpc_call("name_show", [nm])
        rr = r.get("result", {}) or {}
        addr = rr.get("address")
        if addr:
            name_addresses.add(addr)
    except Exception:
        continue

utxo_addresses = set()
try:
    r = rpc_call("listunspent", [])
    utxos = r.get("result", []) or []
    for u in utxos:
        addr = u.get("address")
        if addr:
            utxo_addresses.add(addr)
    print(f"→ {len(utxo_addresses):,} UTXO addresses loaded")
except Exception as e:
    print("Error with listunspent:", e)
    utxos = []

addresses_to_check = name_addresses | utxo_addresses
print(f"→ Total {len(addresses_to_check):,} relevant addresses (names+UTXOs)")

# ---------------- listdescriptors true ----------------
print("Calling listdescriptors true (searching for private xprvs/WIFs) ...")
hd_dict = defaultdict(list)  # fp -> [{'xprv':..., 'origin_len':..., 'matching_path':...}, ...]
pubkey_to_wif = {}
unextracted_names = []
unextracted_utxos = []
hd_descriptors = []

try:
    ld = rpc_call("listdescriptors", [True])
    descriptors_all = ld.get("result", {}).get("descriptors", []) or []
except Exception as e:
    print("Error with listdescriptors true:", e)
    descriptors_all = []

def parse_descriptor_entry(desc_str):
    if not desc_str:
        return
    desc_n = desc_str.split('#')[0]

    # Handle nested descriptors
    nested = False
    if desc_n.startswith('sh(wpkh(') and desc_n.endswith('))'):
        key_part = desc_n[8:-2]  # remove "sh(wpkh(" and "))"
        nested = True
    elif desc_n.startswith('wpkh(') and desc_n.endswith(')'):
        key_part = desc_n[5:-1]
    elif desc_n.startswith('pkh(') and desc_n.endswith(')'):
        key_part = desc_n[4:-1]
    # More nested types possible if needed, e.g., wsh(multi(...
    else:
        key_part = desc_n  # fallback

    bracket_path_str = ''
    fingerprint = None
    ext_key = key_part

    m = re.match(r'^\[([0-9a-fA-F]{8})(/[^]]*)?\](.+)$', key_part)
    if m:
        fingerprint = m.group(1).lower()
        bracket_path_str = m.group(2) or ''
        ext_key = m.group(3)

    suffix_start = ext_key.find('/')
    extkey_root = ext_key if suffix_start == -1 else ext_key[:suffix_start]

    if extkey_root.startswith(('xprv', 'tprv', 'yprv', 'zprv', 'dprv')):
        suffix = ext_key[suffix_start:] if suffix_start != -1 else ''
        if suffix.endswith('/*'):
            suffix = suffix[:-2]
        origin = parse_path(bracket_path_str)
        suffix_fixed = parse_path(suffix)
        fp = fingerprint or compute_fingerprint_from_xprv(extkey_root)
        if fp:
            hd_dict[fp].append({
                'xprv': extkey_root,
                'origin_len': len(origin),
                'matching_path': origin + suffix_fixed,
                'nested': nested  # Add flag for nested
            })
            hd_descriptors.append(desc_str)
        return

    try:
        pub = compute_pubkey_from_wif(extkey_root)
        if pub:
            pubkey_to_wif[pub.lower()] = extkey_root
            return
    except Exception:
        pass

for d in descriptors_all:
    ds = d.get("desc")
    if ds:
        parse_descriptor_entry(ds)
    pd = d.get("parent_desc")
    if pd:
        parse_descriptor_entry(pd)

print(f"→ {len(pubkey_to_wif):,} simple keys loaded from descriptors")
print(f"→ {len(hd_dict):,} HD-xprv fingerprints loaded")

# Save HD private descriptors to file (deduplicated)
with open("descriptors_hd.txt", "w", encoding="utf-8") as fh:
    for x in set(hd_descriptors):
        fh.write(x + "\n")
print(f"→ {len(set(hd_descriptors))} HD private descriptors saved in descriptors_hd.txt (for master-key generated addresses)")

# ---------------- process addresses ----------------
errors = []

def process_address(addr, error_list):
    try:
        r = rpc_call("getaddressinfo", [addr])
        info = r.get("result", {}) or {}
    except Exception:
        error_list.append(f"Error fetching getaddressinfo for {addr}")
        return None

    pubkey = info.get("pubkey", "").lower()
    embedded = info.get("embedded", {})
    if not pubkey and embedded:
        pubkey = embedded.get("pubkey", "").lower()

    fingerprint = info.get("hdmasterfingerprint") or embedded.get("hdmasterfingerprint")
    hdkeypath = info.get("hdkeypath") or embedded.get("hdkeypath")

    public_desc = info.get("desc") or embedded.get("desc")

    if not pubkey and not fingerprint:
        error_list.append(f"Skipping legacy address without pubkey or HD info: {addr}")
        return None

    if pubkey and pubkey in pubkey_to_wif:
        wif = pubkey_to_wif[pubkey]
        return build_priv_desc(public_desc, wif)

    if pubkey and fingerprint and fingerprint in hd_dict and hdkeypath:
        full_path = parse_path(hdkeypath)
        for hd_info in hd_dict[fingerprint]:
            matching_path = hd_info['matching_path']
            if len(full_path) >= len(matching_path) and full_path[:len(matching_path)] == matching_path:
                relative = full_path[len(matching_path):]
                derive_path = hd_info['matching_path'][hd_info['origin_len']:] + relative
                priv = derive_priv(hd_info['xprv'], derive_path)
                if priv:
                    # Try compressed first
                    pubcalc = compute_pubkey_from_priv(priv, compressed=True)
                    if pubcalc.lower() == pubkey:
                        wif = priv_to_wif(priv, compressed=True)
                        return build_priv_desc(public_desc, wif)
                    # Try uncompressed
                    pubcalc_uncomp = compute_pubkey_from_priv(priv, compressed=False)
                    if pubcalc_uncomp.lower() == pubkey:
                        wif = priv_to_wif(priv, compressed=False)
                        return build_priv_desc(public_desc, wif)
        # Additional try: relative from origin_len
        for hd_info in hd_dict[fingerprint]:
            relative = full_path[hd_info['origin_len']:]
            priv = derive_priv(hd_info['xprv'], relative)
            if priv:
                pubcalc = compute_pubkey_from_priv(priv, compressed=True)
                if pubcalc.lower() == pubkey:
                    wif = priv_to_wif(priv, compressed=True)
                    return build_priv_desc(public_desc, wif)
                pubcalc_uncomp = compute_pubkey_from_priv(priv, compressed=False)
                if pubcalc_uncomp.lower() == pubkey:
                    wif = priv_to_wif(priv, compressed=False)
                    return build_priv_desc(public_desc, wif)
        # Fallback if origin_len == 0 or additional
        for hd_info in hd_dict[fingerprint]:
            if hd_info['origin_len'] == 0:
                priv = derive_priv(hd_info['xprv'], full_path)
                if priv:
                    # Try compressed
                    pubcalc = compute_pubkey_from_priv(priv, compressed=True)
                    if pubcalc.lower() == pubkey:
                        wif = priv_to_wif(priv, compressed=True)
                        return build_priv_desc(public_desc, wif)
                    # Try uncompressed
                    pubcalc_uncomp = compute_pubkey_from_priv(priv, compressed=False)
                    if pubcalc_uncomp.lower() == pubkey:
                        wif = priv_to_wif(priv, compressed=False)
                        return build_priv_desc(public_desc, wif)
    else:
        error_list.append(f"No HD info or pubkey for {addr}: pubkey len={len(pubkey) if pubkey else 'None'}, fingerprint={fingerprint}, path={hdkeypath}")

    return None

# ---- Names ----
print("Processing names (only ismine=true)...")
found_names = 0
with open("descriptors_names.txt", "w", encoding="utf-8") as out_names:
    for idx, n in enumerate(names, 1):
        nm = n.get("name")
        try:
            r = rpc_call("name_show", [nm])
            res = r.get("result", {}) or {}
            addr = res.get("address")
            if not addr:
                continue
            priv_desc = process_address(addr, errors)
            if priv_desc:
                out_names.write(priv_desc + "\n")
                found_names += 1
            else:
                unextracted_names.append(f"{nm} | no priv key extracted | addr={addr}")
        except Exception:
            unextracted_names.append(f"{nm} | error_fetching")
        if idx % 1000 == 0 or idx == len(names):
            print(f"→ {idx}/{len(names)} names processed...")
print(f"→ {found_names} name private descriptors extracted")

if unextracted_names:
    print(f"→ {len(unextracted_names)} names could not be extracted (check logs)")
    with open("unextracted_names.txt", "w", encoding="utf-8") as fh:
        for x in unextracted_names:
            fh.write(x + "\n")

# ---- UTXOs ----
print("Processing UTXOs (current listunspent addresses)...")
found_utxos = 0
with open("descriptors_utxos.txt", "w", encoding="utf-8") as out_utxos:
    for idx, u in enumerate(utxos, 1):
        addr = u.get("address")
        if not addr:
            continue
        priv_desc = process_address(addr, errors)
        if priv_desc:
            out_utxos.write(priv_desc + "\n")
            found_utxos += 1
        else:
            unextracted_utxos.append(f"{addr} | no priv key extracted")
        if idx % 500 == 0 or idx == len(utxos):
            print(f"→ {idx}/{len(utxos)} UTXOs processed...")
print(f"→ {found_utxos} UTXO private descriptors extracted")

if unextracted_utxos:
    print(f"→ {len(unextracted_utxos)} UTXOs could not be extracted (check logs)")
    with open("unextracted_utxos.txt", "w", encoding="utf-8") as fh:
        for x in unextracted_utxos:
            fh.write(x + "\n")

# ---- Cleanup ----
for fp in list(hd_dict.keys()):
    for entry in hd_dict[fp]:
        entry['xprv'] = None
hd_dict.clear()
print("Temporary xprv strings deleted (best-effort).")

# ---- Error log ----
if errors:
    print("\nError log:")
    for err in errors:
        print(err)

print("Done!")

