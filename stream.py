"""Bounded bidirectional transport with a single owner for each TLS socket."""
import select
import socket
import ssl
import time

MAX_BYTES = 1024 * 1024
MAX_SECONDS = 60
IDLE_SECONDS = 10


def relay(left, right, max_bytes=MAX_BYTES, max_seconds=MAX_SECONDS,
          idle_seconds=IDLE_SECONDS, on_error=None):
    # SSLSocket read/write must not run concurrently in separate threads.
    # In particular TLS 1.3 reads may also write protocol records internally.
    # Forward synchronously so EOF cannot cancel another worker's queued write.
    count, activity = 0, time.monotonic()
    deadline = activity + max_seconds
    readers = [left, right]
    destinations = {left: right, right: left}
    while readers:
        now = time.monotonic()
        remaining = min(deadline - now, idle_seconds - (now - activity))
        if remaining <= 0:
            return 'timeout', count
        source = None
        stage = 'relay_wait'
        try:
            pending = [peer for peer in readers
                       if isinstance(peer, ssl.SSLSocket) and peer.pending()]
            ready = pending or select.select(readers, [], [], min(.05, remaining))[0]
            for source in ready:
                destination = destinations[source]
                stage = 'relay_read'
                source.settimeout(min(.05, remaining))
                try:
                    data = source.recv(16384)
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                if not data:
                    readers.remove(source)
                    # Raw TCP half-close supports request-then-response protocols.
                    # Do not call raw shutdown on a TLS destination: it would cut
                    # encrypted records without a TLS close-notify exchange.
                    if isinstance(destination, ssl.SSLSocket):
                        return 'closed', count
                    destination.shutdown(socket.SHUT_WR)
                    continue
                if count + len(data) > max_bytes:
                    return 'byte_limit', count
                stage = 'relay_write'
                remaining = min(deadline - time.monotonic(), idle_seconds)
                if remaining <= 0:
                    return 'timeout', count
                destination.settimeout(min(5, remaining))
                destination.sendall(data)
                count += len(data)
                activity = time.monotonic()
        except OSError as error:
            if on_error is not None:
                fields = {'stage': stage,
                          'direction': 'client_to_service' if source is left else 'service_to_client'}
                if type(error.errno) is int:
                    fields['errno'] = error.errno
                reason = getattr(error, 'reason', None)
                if isinstance(reason, str) and len(reason) <= 80 and reason.replace('_', '').isalnum():
                    fields['tls_reason'] = reason
                on_error(fields)
            return 'disconnected', count
    return 'closed', count
