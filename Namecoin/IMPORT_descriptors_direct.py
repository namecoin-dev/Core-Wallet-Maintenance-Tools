################################################################################################################

# Copyright (C) 2025 by Uwe Martens * www.namecoin.pro  * https://dotbit.app

################################################################################################################

import requests
import json
import os
import time

rpc_user = "XXXXXXX"  # rpcuser from namecoin.conf
rpc_pass = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # rpcpassword from namecoin.conf
url = "http://127.0.0.1:8336/"

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=4, max_retries=3, pool_block=False)
session.mount(url, adapter)
session.auth = (rpc_user, rpc_pass)
session.headers.update({"Content-Type": "application/json"})
session.timeout = 30

DESCRIPTOR_FILES = ["descriptors_names.txt", "descriptors_utxos.txt", "descriptors_hd.txt"]
RESCAN_TIMESTAMP = 0
BATCH_SIZE = 1000

def rpc_call(method, params=None):
    if params is None:
        params = []
    payload = {"jsonrpc": "1.0", "id": "script", "method": method, "params": params}
    r = session.post(url, json=payload)
    try:
        res = r.json()
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON response: {r.text}")
    if 'error' in res and res['error'] is not None:
        raise ValueError(f"RPC error: {res['error']}")
    return res

def is_scanning():
    try:
        res = rpc_call("getwalletinfo")
        info = res.get("result", {})
        scanning = info.get("scanning", False)
        return scanning != False
    except Exception as e:
        print(f"Error checking wallet info: {e}")
        return True

def wait_for_rescan_complete():
    while is_scanning():
        print("Wallet is scanning; waiting 5 seconds...")
        time.sleep(5)

def main():
    last_file = None
    for desc_file in reversed(DESCRIPTOR_FILES):
        if os.path.exists(desc_file):
            with open(desc_file, "r") as f:
                descriptors = [line.strip() for line in f if line.strip()]
            if len(descriptors) > 0:
                last_file = desc_file
                break

    for desc_file in DESCRIPTOR_FILES:
        if not os.path.exists(desc_file):
            print(f"[INFO] {desc_file} not found, skipping.")
            continue

        with open(desc_file, "r") as f:
            descriptors = [line.strip() for line in f if line.strip()]

        total_desc = len(descriptors)
        if total_desc == 0:
            print(f"[INFO] No descriptors found in {desc_file}, skipping.")
            continue

        print(f"\nProcessing {desc_file} with {total_desc} descriptors...")

        is_last_file = (desc_file == last_file)

        current_batch = []
        for i, desc in enumerate(descriptors):
            timestamp = RESCAN_TIMESTAMP if is_last_file and i == total_desc - 1 else "now"
            current_batch.append({
                "desc": desc,
                "timestamp": timestamp
            })

            if len(current_batch) == BATCH_SIZE or i == total_desc - 1:
                print(f"→ {i + 1}/{total_desc} descriptors processed...")
                wait_for_rescan_complete()
                try:
                    res = rpc_call("importdescriptors", [current_batch])
                except Exception as e:
                    print(f"Error importing batch: {e}")
                current_batch = []

    print("\n[INFO] All descriptors imported successfully.\n\n")
    input("Press Enter to exit...")

if __name__ == "__main__":

    main()
