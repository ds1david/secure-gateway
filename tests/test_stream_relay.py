"""Transport regressions: exclusive socket ownership, backpressure and half-close."""
import socket
import threading
import time
import unittest
from unittest import mock
import stream

class RelayTests(unittest.TestCase):
    def test_response_is_not_written_during_a_read_on_same_socket(self):
        left, client = socket.socketpair()
        right, service = socket.socketpair()
        class ExclusiveSocket:
            active = False
            overlap = False
            def fileno(self): return left.fileno()
            def settimeout(self, value): left.settimeout(value)
            def shutdown(self, how): left.shutdown(how)
            def recv(self, size):
                self.active = True
                try: return left.recv(size)
                finally: self.active = False
            def sendall(self, data):
                if self.active:
                    self.overlap = True
                    raise OSError('concurrent access')
                left.sendall(data)
        guarded = ExclusiveSocket()
        results = []
        worker = threading.Thread(target=lambda: results.append(stream.relay(
            guarded, right, max_seconds=4, idle_seconds=2)))
        try:
            client.sendall(b'request')
            worker.start()
            service.settimeout(2)
            self.assertEqual(b'request', service.recv(7))
            time.sleep(.1)
            service.sendall(b'final-response')
            service.shutdown(socket.SHUT_WR)
            client.settimeout(2)
            self.assertEqual(b'final-response', client.recv(14))
            client.shutdown(socket.SHUT_WR)
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertFalse(guarded.overlap)
            self.assertEqual([('closed', 21)], results)
        finally:
            for peer in (left, right, client, service): peer.close()
            if worker.is_alive(): worker.join(5)
    def test_raw_half_close_preserves_delayed_response(self):
        left, client = socket.socketpair()
        right, service = socket.socketpair()
        results = []
        worker = threading.Thread(target=lambda: results.append(stream.relay(
            left, right, max_seconds=4, idle_seconds=2)))
        try:
            worker.start()
            client.sendall(b'upload')
            client.shutdown(socket.SHUT_WR)
            service.settimeout(2)
            received = b''
            while True:
                data = service.recv(1024)
                if not data: break
                received += data
            self.assertEqual(b'upload', received)
            service.sendall(b'accepted')
            service.shutdown(socket.SHUT_WR)
            client.settimeout(2)
            self.assertEqual(b'accepted', client.recv(1024))
            worker.join(5)
            self.assertEqual([('closed', 14)], results)
        finally:
            for peer in (left, right, client, service): peer.close()
            if worker.is_alive(): worker.join(5)
    def test_error_diagnostic_contains_no_exception_text(self):
        left, client = socket.socketpair()
        right, service = socket.socketpair()
        fields = []
        try:
            with mock.patch.object(stream.select, 'select', side_effect=OSError(10054, 'secret payload')):
                self.assertEqual(('disconnected', 0), stream.relay(left, right, on_error=fields.append))
            self.assertEqual(10054, fields[0]['errno'])
            self.assertNotIn('secret', str(fields))
        finally:
            for peer in (left, right, client, service): peer.close()
