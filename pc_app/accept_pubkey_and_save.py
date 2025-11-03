import socket, ssl, json, os

HOST = "0.0.0.0"
PORT = 8443

CERTFILE = "server.crt"
KEYFILE = "server.key"
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
ctx.verify_mode = ssl.CERT_NONE

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Listening on {HOST}:{PORT} (TLS)")
    with ctx.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print("ESP32 connected:", addr)
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        line, _, _ = data.partition(b"\n")
                        try:
                            obj = json.loads(line.decode("utf-8"))
                        except Exception as e:
                            print("Invalid JSON:", e)
                            conn.sendall(b'{"status":"error","reason":"invalid_json"}\n')
                            break
                        if obj.get("action") == "announce_pubkey" and "pubkey" in obj:
                            pubkey = obj["pubkey"]
                            print("Received pubkey:", pubkey)
                            try:
                                cfg = {}
                                if os.path.exists(CONFIG_PATH):
                                    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                                        cfg = json.load(f)
                                cfg["sender_public_key"] = pubkey
                                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                                    json.dump(cfg, f, indent=2)
                                conn.sendall(b'{"status":"ok","message":"pubkey_saved"}\n')
                                print("Saved pubkey to config.json")
                            except Exception as e:
                                print("Error writing config:", e)
                                conn.sendall(b'{"status":"error","reason":"save_failed"}\n')
                        else:
                            conn.sendall(b'{"status":"error","reason":"unknown_action"}\n')
                        break
