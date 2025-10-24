import socket
import ssl

HOST = "0.0.0.0"
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Load only server certificate & key
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# IMPORTANT: Do NOT require client certificate
context.verify_mode = ssl.CERT_NONE  # This avoids SSLV3_ALERT_BAD_CERTIFICATE

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Listening on {HOST}:{PORT} (TLS enabled)")

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print("ESP32 connected:", addr)

            data = conn.recv(1024).decode()
            print("Received:", data)

            conn.sendall(b"world\n")
            conn.close()
