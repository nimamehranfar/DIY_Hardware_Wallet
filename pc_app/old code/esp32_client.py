import json, ssl, socket
from typing import Dict, Any

def send_request_over_tls(host: str, port: int, payload: Dict[str, Any], cafile: str) -> Dict[str, Any]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cafile, keyfile=cafile.replace("server_cert.pem", "server_key.pem"))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        print(f"Waiting for ESP32 TLS client on {host}:{port} ...")
        with ctx.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            print("ESP32 connected from", addr)
            with conn:
                conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))
                buff = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    buff += chunk
                    if b"\n" in buff:
                        line, _, _ = buff.partition(b"\n")
                        return json.loads(line.decode("utf-8"))
    return {"status":"error","message":"no response"}
