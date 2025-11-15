import socket, ssl, json, os, sys, traceback
from pc_app.tls.update_config import write_sender_pubkey

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(HERE)

HOST, PORT = "0.0.0.0", 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile=os.path.join(HERE, "server.crt"),
    keyfile=os.path.join(HERE, "server.key")
)
context.verify_mode = ssl.CERT_NONE  # server-only TLS


def recv_line(conn, timeout=5):
    """Read one line (terminated by \\n) with a timeout."""
    conn.settimeout(timeout)
    buf = b""
    while True:
        try:
            bch = conn.recv(1)
        except socket.timeout:
            return None
        if not bch:
            return None
        buf += bch
        if bch == b"\n":
            break
    try:
        msg = buf.decode().strip()
        return json.loads(msg)
    except json.JSONDecodeError:
        return msg


def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    try:
        # ---- 1. Expect handshake ----
        first = recv_line(conn)
        if not first:
            print("[-] Empty handshake")
            return
        if (isinstance(first, str) and "ping" in first) or \
                (isinstance(first, dict) and first.get("action") == "ping"):
            conn.sendall(b'{"status":"pong"}\n')
            print("[Handshake] pong sent")
        else:
            print("[-] Unexpected first message:", first)
            return

        # ---- 2. Wait for next message (pubkey etc.) ----
        print("[*] Waiting for next payload...")
        second = recv_line(conn, timeout=10)
        if not second:
            print("[-] No second message received")
            return

        print("[>] Received:", second)
        if isinstance(second, dict) and second.get("action") == "pubkey":
            pub = second.get("pubkey", "")
            if not pub:
                conn.sendall(b'{"status":"error","reason":"missing pubkey"}\n')
                return
            write_sender_pubkey(pub)
            conn.sendall(b'{"status":"ok","saved":true}\n')
            print(f"[✔] Saved pubkey {pub[:12]}...")
        else:
            conn.sendall(b'{"status":"error","reason":"unknown action"}\n')

    except Exception as e:
        print("[!] Client error:", e)
        traceback.print_exc()
    finally:
        conn.close()
        print("[x] Connection closed:", addr)


def main():
    print(f"[*] Listening on {HOST}:{PORT} (TLS)")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        while True:
            raw_conn, addr = sock.accept()
            try:
                conn = context.wrap_socket(raw_conn, server_side=True)
                handle_client(conn, addr)
            except ssl.SSLError as e:
                print("[SSL]", e)
            except Exception as e:
                print("[!] General:", e)
                traceback.print_exc()

def run_wifi():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    raw_conn, addr = sock.accept()
    conn = context.wrap_socket(raw_conn, server_side=True)
    print(f"[+] TLS client {addr} connected")
    return conn

if __name__ == "__main__":
    main()
