"""Loopback-only browser homologation fixture; never use real data or credentials."""
import base64
import hashlib
import http.server
import json
import struct

PAGE = b"""<!doctype html><meta charset=utf-8><title>Secure Gateway Lab</title>
<h1>Secure Gateway: laboratorio</h1><p>Somente dados ficticios.</p>
<button onclick="run('/status')">GET / API</button>
<button onclick="run('/upload',{method:'POST',body:'fixture-upload'})">Upload</button>
<button onclick="ws()">WebSocket</button>
<a href=/download download=fixture.bin>Download</a> <a href=/redirect>Redirecionamento</a>
<pre id=out></pre><script>
async function run(path, options) {
 try {const r=await fetch(path,options);out.textContent=r.status+' '+await r.text();}
 catch(e){out.textContent=String(e);}
}
function ws(){const s=new WebSocket('ws://'+location.host+'/ws');
 s.onopen=()=>s.send('fixture-websocket');
 s.onmessage=e=>{out.textContent='WebSocket: '+e.data;s.close();};
 s.onerror=()=>out.textContent='WebSocket falhou';}
</script>"""
DOWNLOAD = bytes(range(256)) * 256


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass  # Do not log headers, bodies, credentials or query strings.

    def response(self, status, body=b'', content_type='application/json', headers=()):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
        self.close_connection = True

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.connection.settimeout(15)
        if self.path == '/':
            self.response(200, PAGE, 'text/html; charset=utf-8')
        elif self.path == '/status':
            self.response(200, b'{"status":"ok","source":"restricted-windows-lab"}')
        elif self.path == '/download':
            self.response(200, DOWNLOAD, 'application/octet-stream')
        elif self.path == '/redirect':
            self.response(302, headers=(('Location', '/'),))
        elif self.path == '/ws' and self.headers.get('Upgrade', '').lower() == 'websocket':
            self.websocket()
        else:
            self.response(404)

    def do_POST(self):
        self.connection.settimeout(15)
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if self.path != '/upload' or not 0 <= length <= 1024 * 1024 or self.headers.get('Transfer-Encoding'):
                self.response(400)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self.response(400)
                return
            self.response(200, json.dumps({'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}).encode())
        except (ValueError, OSError):
            self.close_connection = True

    def exact(self, length):
        value = self.rfile.read(length)
        if len(value) != length:
            raise OSError('truncated fixture frame')
        return value

    def websocket(self):
        key = self.headers.get('Sec-WebSocket-Key', '')
        try:
            if len(base64.b64decode(key, validate=True)) != 16:
                raise ValueError()
        except ValueError:
            self.response(400)
            return
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        try:
            while True:
                first, second = self.exact(2)
                size = second & 127
                if size == 126:
                    size = struct.unpack('!H', self.exact(2))[0]
                if size == 127 or not second & 128 or size > 65535 or not first & 128:
                    break
                mask = self.exact(4)
                data = bytes(value ^ mask[i % 4] for i, value in enumerate(self.exact(size)))
                opcode = first & 15
                if opcode not in (1, 2, 8, 9):
                    break
                reply_opcode = 10 if opcode == 9 else opcode
                header = bytes([128 | reply_opcode])
                header += bytes([len(data)]) if len(data) < 126 else b'\x7e' + struct.pack('!H', len(data))
                self.wfile.write(header + data)
                self.wfile.flush()
                if opcode == 8:
                    break
        except OSError:
            pass
        self.close_connection = True


if __name__ == '__main__':
    with http.server.ThreadingHTTPServer(('127.0.0.1', 18765), Handler) as server:
        print('Laboratorio em http://localhost:18765/ (somente loopback)', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
