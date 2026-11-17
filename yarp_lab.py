"""Prepare and serve synthetic HTTPS fixture for the isolated YARP POC."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import ssl
import web_lab

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('mode', choices=['prepare', 'serve'])
parser.add_argument('--cert-dir', default='certs-yarp')
parser.add_argument('--out', default='yarp-poc/lab.user.json')
args = parser.parse_args()
certs = Path(args.cert_dir).resolve()
if args.mode == 'prepare':
    ca = certs / 'ca.crt'
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text(encoding='ascii'))).hexdigest()
    output = Path(args.out).resolve()
    output.write_text(json.dumps({'ListenPort': 18766, 'Destination': 'https://localhost:18765/',
        'LabOnly': True, 'TrustedRootFile': str(ca), 'TrustedRootSha256': fingerprint}, indent=2) + '\n')
    print('Configuracao publica do laboratorio criada:', output)
else:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certs / 'gateway.crt', certs / 'gateway.key')
    with http.server.ThreadingHTTPServer(('127.0.0.1', 18765), web_lab.Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print('Fixture HTTPS em https://localhost:18765/; Ctrl+C encerra.', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
