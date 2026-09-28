#!/usr/bin/env python3
"""Exercise the installer's shared staging boundary without executing payloads."""
import http.server
import os
import pathlib
import ssl
import subprocess
import tempfile
import threading


root = pathlib.Path(__file__).resolve().parents[2]
script = (root / "scripts/installer/ziro-install.sh").read_text()
start = script.index("stage_user_data() {")
function = script[start:script.index("\n}\n", start) + 3]

with tempfile.TemporaryDirectory() as directory:
    directory = pathlib.Path(directory)
    config = directory / "openssl.cnf"
    config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=CA:TRUE\n")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1", "-config", str(config), "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    contacted = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/downgrade":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{plain.server_port}/payload")
                self.end_headers()
            else:
                contacted.append(self.server is plain)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"# authenticated bootstrap fixture\n")

        def log_message(self, *args):
            pass

    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    secure = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    for server in (plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def stage(source):
        env = dict(os.environ, CURL_CA_BUNDLE=str(cert), NO_PROXY="localhost,127.0.0.1")
        return subprocess.run(["sh", "-c", function + '\nstage_user_data "$1" "$2"', "stage", source, str(directory / "payload")], env=env, capture_output=True)

    try:
        assert stage(f"http://localhost:{plain.server_port}/payload").returncode != 0
        assert stage(f"https://localhost:{secure.server_port}/downgrade").returncode != 0
        assert True not in contacted, "unauthenticated destination contacted"
        assert stage(f"https://localhost:{secure.server_port}/payload").returncode == 0
        local = directory / "local.sh"
        local.write_text("# local bootstrap fixture\n")
        assert stage(str(local)).returncode == 0
        assert (directory / "payload").read_text() == local.read_text()
        assert stage(str(directory / "missing")).returncode != 0
        print("PASS installer HTTP/downgrade rejection, HTTPS, local file, and fetch failure")
    finally:
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
