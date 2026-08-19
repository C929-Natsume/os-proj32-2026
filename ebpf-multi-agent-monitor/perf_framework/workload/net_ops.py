import socket
import time
import random
import threading


def _ensure_echo_server(port: int = 19999):
    """Start a simple TCP echo server if not already running."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(("127.0.0.1", port))
        s.close()
        return
    except Exception:
        pass

    def _serve():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(5)
        server.settimeout(0.5)
        while _serving:
            try:
                conn, _addr = server.accept()
                conn.settimeout(0.2)
                try:
                    data = conn.recv(4096)
                    if data:
                        conn.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception:
                break
        try:
            server.close()
        except Exception:
            pass

    global _serving
    _serving = True
    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    time.sleep(0.3)


def _stop_echo_server():
    global _serving
    _serving = False


_serving = False


def network_workload(messages: int = 50, port: int = 19999,
                     message_size: int = 256):
    _ensure_echo_server(port)
    payload = b"A" * message_size
    for _ in range(messages):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(("127.0.0.1", port))
            s.sendall(payload)
            _ = s.recv(len(payload))
            s.close()
        except Exception:
            pass
