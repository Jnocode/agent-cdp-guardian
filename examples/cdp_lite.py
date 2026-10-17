"""
examples/cdp_lite.py
~~~~~~~~~~~~~~~~~~~~
示範用、非套件 API (Minimal RFC6455 WebSocket & CDP Client for tests & examples)

A minimal, zero-dependency RFC6455 WebSocket client and CDP controller
built purely on Python's standard library (socket, base64, os, struct, json, hashlib, urllib).
NOT part of agent_cdp_guardian package exports.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


class CDPLiteWebSocketError(Exception):
    """Raised when RFC6455 handshake or framing fails."""
    pass


class CDPLiteClient:
    """
    Minimal synchronous WebSocket client implementing RFC6455 text frames.
    Dedicated exclusively to localhost DevTools Protocol debugging in tests and examples.
    """

    def __init__(self, ws_url: str, timeout: float = 10.0):
        self.ws_url = ws_url
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._next_id = 1
        self._connect()

    def _connect(self):
        # Parse ws://127.0.0.1:port/path
        parsed = urllib.parse.urlparse(self.ws_url)
        if parsed.scheme != "ws":
            raise CDPLiteWebSocketError(f"Unsupported scheme: {parsed.scheme}")

        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
        if not path:
            path = "/"

        self.sock = socket.create_connection((host, port), timeout=self.timeout)
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode("utf-8"))

        # Read handshake response header
        resp_buf = bytearray()
        while b"\r\n\r\n" not in resp_buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CDPLiteWebSocketError("Connection closed during WebSocket handshake")
            resp_buf.extend(chunk)

        header_str = resp_buf.decode("latin1", errors="replace")
        status_line = header_str.split("\r\n")[0]
        if " 101 " not in status_line:
            raise CDPLiteWebSocketError(f"Handshake failed with status: {status_line}")

    def send_command(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a CDP JSON-RPC command and synchronously wait for its response."""
        cmd_id = self._next_id
        self._next_id += 1
        payload = {
            "id": cmd_id,
            "method": method,
            "params": params or {}
        }
        raw_msg = json.dumps(payload).encode("utf-8")

        # RFC6455 Client-to-Server Masked Text Frame (0x81)
        mask = os.urandom(4)
        masked_payload = bytearray([b ^ mask[i % 4] for i, b in enumerate(raw_msg)])
        length = len(raw_msg)

        if length < 126:
            frame_hdr = bytes([0x81, 0x80 | length]) + mask
        elif length < 65536:
            frame_hdr = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length) + mask
        else:
            frame_hdr = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length) + mask

        self.sock.sendall(frame_hdr + bytes(masked_payload))

        # Wait for matching response ID
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            resp_data = self._read_frame()
            if not resp_data:
                continue
            try:
                parsed_json = json.loads(resp_data.decode("utf-8"))
                if parsed_json.get("id") == cmd_id:
                    if "error" in parsed_json:
                        raise CDPLiteWebSocketError(f"CDP command {method} failed: {parsed_json['error']}")
                    return parsed_json.get("result", {})
            except json.JSONDecodeError:
                continue

        raise TimeoutError(f"Timed out waiting for CDP response for method {method} (id={cmd_id})")

    def _read_frame(self) -> bytes:
        """Reads a single unmasked/masked incoming WebSocket frame."""
        hdr = self._recv_exact(2)
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0f
        is_masked = bool(b2 & 0x80)
        payload_len = b2 & 0x7f

        if payload_len == 126:
            payload_len = struct.unpack("!H", self._recv_exact(2))[0]
        elif payload_len == 127:
            payload_len = struct.unpack("!Q", self._recv_exact(8))[0]

        mask_key = self._recv_exact(4) if is_masked else None
        data = self._recv_exact(payload_len)

        if is_masked and mask_key:
            data = bytes([b ^ mask_key[i % 4] for i, b in enumerate(data)])

        if opcode == 0x8:  # Close frame
            self.close()
            return b""
        elif opcode in (0x1, 0x2):  # Text or Binary
            return data
        elif opcode == 0x9:  # Ping -> reply Pong (0x8a)
            self._send_pong(data)
            return b""
        return b""

    def _recv_exact(self, num_bytes: int) -> bytes:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = self.sock.recv(num_bytes - len(buf))
            if not chunk:
                raise CDPLiteWebSocketError("Unexpected connection drop while reading frame")
            buf.extend(chunk)
        return bytes(buf)

    def _send_pong(self, data: bytes):
        mask = os.urandom(4)
        masked_data = bytearray([b ^ mask[i % 4] for i, b in enumerate(data)])
        length = len(data)
        hdr = bytes([0x8a, 0x80 | length]) + mask
        self.sock.sendall(hdr + bytes(masked_data))

    def evaluate(self, expression: str) -> Any:
        """Helper to run Runtime.evaluate and extract value directly."""
        res = self.send_command("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        val = res.get("result", {}).get("value")
        return val

    def close(self):
        """Close connection."""
        if self.sock:
            try:
                # Send close frame
                self.sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
                self.sock.close()
            except Exception:
                pass
            finally:
                self.sock = None
