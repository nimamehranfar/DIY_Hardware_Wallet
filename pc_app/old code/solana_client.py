import json, base64
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.message import MessageV0, to_bytes_versioned
from solders.transaction import VersionedTransaction
from solders.hash import Hash
from solders.null_signer import NullSigner
from solders.signature import Signature
from esp32_client import send_request_over_tls

def build_unsigned_tx(rpc_url, sender_pubkey_str, recipient_pubkey_str, lamports):
    client = Client(rpc_url)
    sender = Pubkey.from_string(sender_pubkey_str)
    recipient = Pubkey.from_string(recipient_pubkey_str)
    ix = transfer(TransferParams(from_pubkey=sender, to_pubkey=recipient, lamports=lamports))
    blockhash = client.get_latest_blockhash()["result"]["value"]["blockhash"]
    recent = Hash.from_string(blockhash)
    msg = MessageV0.try_compile(payer=sender, instructions=[ix], address_lookup_table_accounts=[], recent_blockhash=recent)
    message_bytes = to_bytes_versioned(msg)
    return client, msg, sender, message_bytes

def attach_signature_and_broadcast(client, msg, sender, signature_bytes):
    tx = VersionedTransaction(msg, [NullSigner(sender)])
    sig_obj = Signature.from_bytes(signature_bytes)
    sigs = tx.signatures
    sigs[0] = sig_obj
    tx.signatures = sigs
    res = client.send_raw_transaction(bytes(tx))
    print("✅ Broadcast result:", res)
    return res

def main():
    with open("../config.json", "r") as f:
        cfg = json.load(f)
    rpc_url = cfg["rpc_url"]
    sender = cfg["sender_public_key"]
    recipient = cfg["recipient_public_key"]
    lamports = int(cfg.get("lamports", 1_000_000))
    host = cfg["esp32_host"]
    port = int(cfg["esp32_port"])

    client, msg, sender_pk, message_bytes = build_unsigned_tx(rpc_url, sender, recipient, lamports)
    payload = {
        "action":"sign_solana_message",
        "message_b64": base64.b64encode(message_bytes).decode(),
        "sender_pubkey": sender,
        "recipient": recipient,
        "amount": lamports
    }
    resp = send_request_over_tls(host, port, payload, "tls/server_cert.pem")
    if resp.get("status") != "ok":
        print("❌ ESP32 error:", resp); return
    sig = bytes.fromhex(resp["signature_hex"])
    attach_signature_and_broadcast(client, msg, sender_pk, sig)

if __name__ == "__main__":
    main()
