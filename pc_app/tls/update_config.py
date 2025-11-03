import json
import os
from typing import Any, Dict

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def write_sender_pubkey(new_pubkey: str) -> None:
    cfg_path = os.path.abspath(CONFIG_PATH)
    cfg: Dict[str, Any] = {}

    # load existing file if present, otherwise start fresh
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            try:
                cfg = json.load(f)
            except json.JSONDecodeError:
                cfg = {}

    # update or insert values
    cfg["sender_public_key"] = new_pubkey
    cfg.setdefault("rpc_url", "https://api.devnet.solana.com")
    cfg.setdefault("recipient_public_key", "")
    cfg.setdefault("lamports", 1_000_000)
    cfg.setdefault("esp32_host", "0.0.0.0")
    cfg.setdefault("esp32_port", 8443)

    # write safely
    tmp_path = cfg_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp_path, cfg_path)

    print(f"[✔] config.json updated successfully at {cfg_path}")

# Example usage:
# write_sender_pubkey("A1B2C3D4E5F6...")
