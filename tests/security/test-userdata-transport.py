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
    # A strictly valid self-signed server certificate: newer curl/OpenSSL builds check more than older ones.
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n"
        "[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
        "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1", "-config", str(config), "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    contacted = []   # True for every request the plain-HTTP server answered with a payload
    served = []      # (plain?, path) for every request either server received
    tls_errors = []  # TLS handshakes the secure server refused (otherwise silent)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # explicit framing: no body that ends only when the connection closes

        def reply(self, status, body=b"", location=None):
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            served.append((self.server is plain, self.path))
            if self.path == "/downgrade":
                self.reply(302, location=f"http://127.0.0.1:{plain.server_port}/payload")
            else:
                contacted.append(self.server is plain)
                self.reply(200, b"# authenticated bootstrap fixture\n")

        def log_message(self, *args):
            pass

    class SecureServer(http.server.ThreadingHTTPServer):
        def get_request(self):  # the TLS handshake happens inside accept()
            try:
                return super().get_request()
            except OSError as error:
                tls_errors.append(repr(error))
                raise

        def shutdown_request(self, request):  # end the TLS session with close_notify, as a real server does
            try:
                request.settimeout(2)
                request = request.unwrap()
            except (OSError, ValueError):
                pass
            super().shutdown_request(request)

    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    secure = SecureServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    for server in (plain, secure):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def stage(source):
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        env.update(CURL_CA_BUNDLE=str(cert), NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        return subprocess.run(["sh", "-c", function + '\nstage_user_data "$1" "$2"', "stage", source, str(directory / "payload")],
                              env=env, capture_output=True, text=True)

    def explain(result, source):
        return (f"stage({source}) exit {result.returncode}\ncurl/installer stderr: {result.stderr.strip()}\n"
                f"TLS handshake errors: {tls_errors}\nrequests served (plain?, path): {served}")

    plain_url = f"http://127.0.0.1:{plain.server_port}/payload"
    downgrade_url = f"https://127.0.0.1:{secure.server_port}/downgrade"
    secure_url = f"https://127.0.0.1:{secure.server_port}/payload"

    try:
        result = stage(plain_url)
        assert result.returncode != 0 and "must use https" in result.stderr, explain(result, plain_url)
        result = stage(downgrade_url)
        assert result.returncode != 0, explain(result, downgrade_url)
        # The redirect must really have been served over TLS and refused, or this check proves nothing.
        assert (False, "/downgrade") in served, "the TLS server was never reached, so the downgrade guard was not tested: " + explain(result, downgrade_url)
        assert True not in contacted, "unauthenticated destination contacted"
        result = stage(secure_url)
        assert result.returncode == 0, explain(result, secure_url)
        local = directory / "local.sh"
        local.write_text("# local bootstrap fixture\n")
        result = stage(str(local))
        assert result.returncode == 0, explain(result, str(local))
        assert (directory / "payload").read_text() == local.read_text()
        result = stage(str(directory / "missing"))
        assert result.returncode != 0, explain(result, "missing file")
        print("PASS installer HTTP/downgrade rejection, HTTPS, local file, and fetch failure")
    finally:
        for server in (plain, secure):
            server.shutdown()
            server.server_close()
