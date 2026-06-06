import ctypes
import hashlib
import os
import socket
import struct
from typing import Tuple

MAGIC = b"ISS1"
CIPHER_AES128GCM = 1
CIPHER_AES256GCM = 2
CIPHER_CHACHA20 = 3

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0
ICMP_HEADER_FMT = "!BBHHH"
ICMP_HEADER_SIZE = struct.calcsize(ICMP_HEADER_FMT)

SO_ATTACH_FILTER = getattr(socket, "SO_ATTACH_FILTER", 26)
SOL_RAW = getattr(socket, "SOL_RAW", 255)
ICMP_FILTER = 1


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def normalize_cipher_name(name: str) -> str:
    c = (name or "").lower().strip()
    if c in ("aes-128-gcm", "aes128", "aes128gcm"):
        return "aes-128-gcm"
    if c in ("aes", "aesgcm", "aes-gcm", "aes-256-gcm", "aes256", "aes256gcm"):
        return "aes-256-gcm"
    return "chacha20"


def _kdf(psk: str | bytes) -> bytes:
    if isinstance(psk, bytes):
        return hashlib.sha256(psk).digest()
    return hashlib.sha256(psk.encode("utf-8")).digest()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class AEADICMPSocket:
    def __init__(self, sock: socket.socket, psk: str | bytes | None = None, cipher_name: str = "chacha20", icmp_type: int = ICMP_ECHO_REQUEST, icmp_id: int | None = None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        self.sock = sock
        self.icmp_type = icmp_type
        self.icmp_id = icmp_id if icmp_id is not None else (os.getpid() & 0xFFFF)
        self._icmp_seq = 1

        base_key = os.urandom(32) if psk is None else _kdf(psk)
        c = normalize_cipher_name(cipher_name)
        self.cipher_name = c
        if c == "aes-128-gcm":
            self.cipher_id = CIPHER_AES128GCM
            self.key = base_key[:16]
        elif c == "aes-256-gcm":
            self.cipher_id = CIPHER_AES256GCM
            self.key = base_key
        else:
            self.cipher_id = CIPHER_CHACHA20
            self.key = base_key

        self._aead_by_id = {
            CIPHER_AES128GCM: AESGCM(base_key[:16]),
            CIPHER_AES256GCM: AESGCM(base_key),
            CIPHER_CHACHA20: ChaCha20Poly1305(base_key),
        }
        self._cipher_id_by_name = {
            "aes-128-gcm": CIPHER_AES128GCM,
            "aes-256-gcm": CIPHER_AES256GCM,
            "chacha20": CIPHER_CHACHA20,
        }
        self._peer_cipher: dict[Tuple[str, int], int] = {}
        self._peer_aeads: dict[Tuple[str, int], dict[int, object]] = {}
        self._local_ip = "0.0.0.0"

    def bind(self, addr: Tuple[str, int]):
        self._local_ip = addr[0]
        try:
            self.sock.bind((addr[0], 0))
        except OSError:
            pass
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self._install_filters()
        if addr[1]:
            self.icmp_id = addr[1] & 0xFFFF

    def _install_filters(self):
        self._install_icmp_filter()
        self._install_bpf_filter()

    def _install_icmp_filter(self):
        # Raw ICMP sockets still see a lot of unrelated traffic on busy hosts.
        # Filter out everything except echo request/reply as early as possible.
        try:
            allowed_mask = (1 << ICMP_ECHO_REQUEST) | (1 << ICMP_ECHO_REPLY)
            block_mask = (~allowed_mask) & 0xFFFFFFFF
            self.sock.setsockopt(SOL_RAW, ICMP_FILTER, struct.pack('I', block_mask))
        except OSError:
            pass
        except AttributeError:
            pass

    def _install_bpf_filter(self):
        # Classic BPF: accept only ICMP echo request/reply. This reduces userspace
        # wakeups on noisy hosts while keeping the transport raw-ICMP based.
        try:
            extended = (SockFilter * 8)(
                SockFilter(0x30, 0, 0, 0),                    # ld  b [0]   -> IP version/IHL
                SockFilter(0x54, 0, 0, 0x0F),                 # and #0x0f   -> IHL in 32-bit words
                SockFilter(0x64, 0, 0, 2),                    # lsh #2      -> IHL bytes
                SockFilter(0x50, 0, 0, 0),                    # ldb [x+0]   -> ICMP type
                SockFilter(0x15, 1, 0, ICMP_ECHO_REQUEST),    # if echo-request -> accept
                SockFilter(0x15, 0, 1, ICMP_ECHO_REPLY),      # if echo-reply   -> accept else drop
                SockFilter(0x06, 0, 0, 0x00040000),           # ret #262144
                SockFilter(0x06, 0, 0, 0),                    # ret #0
            )
            prog = SockFprog(len=8, filter=ctypes.cast(extended, ctypes.POINTER(SockFilter)))
            self._bpf_program = extended
            self._bpf_prog = prog
            self.sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(prog))
        except OSError:
            pass
        except AttributeError:
            pass

    def _make_packet(self, icmp_type: int, ident: int, payload: bytes) -> bytes:
        seq = self._icmp_seq & 0xFFFF
        self._icmp_seq = (self._icmp_seq + 1) & 0xFFFF
        header = struct.pack(ICMP_HEADER_FMT, icmp_type, ICMP_CODE, 0, ident & 0xFFFF, seq)
        checksum = _checksum(header + payload)
        header = struct.pack(ICMP_HEADER_FMT, icmp_type, ICMP_CODE, checksum, ident & 0xFFFF, seq)
        return header + payload

    def _parse_icmp(self, raw: bytes) -> tuple[int, int, bytes] | None:
        if len(raw) < ICMP_HEADER_SIZE:
            return None
        version = raw[0] >> 4
        if version == 4 and len(raw) >= 20:
            ihl = (raw[0] & 0x0F) * 4
            if len(raw) < ihl + ICMP_HEADER_SIZE:
                return None
            raw = raw[ihl:]
        icmp_type, icmp_code, _checksum_val, ident, _seq = struct.unpack(ICMP_HEADER_FMT, raw[:ICMP_HEADER_SIZE])
        if icmp_code != ICMP_CODE:
            return None
        if icmp_type not in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY):
            return None
        return icmp_type, ident, raw[ICMP_HEADER_SIZE:]

    def sendto(self, data: bytes, addr: Tuple[str, int]):
        ident = addr[1] & 0xFFFF
        cid = self._peer_cipher.get(addr, self.cipher_id)
        aead = self._peer_aeads.get(addr, self._aead_by_id)[cid]
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, None)
        payload = MAGIC + bytes([cid]) + nonce + ct
        pkt = self._make_packet(self.icmp_type, ident, payload)
        return self.sock.sendto(pkt, (addr[0], 0))

    def sendto_many(self, packets: list[bytes], addr: Tuple[str, int]):
        if not packets:
            return 0
        sent = 0
        for data in packets:
            self.sendto(data, addr)
            sent += 1
        return sent

    def send_plain(self, data: bytes, addr: Tuple[str, int]):
        ident = addr[1] & 0xFFFF
        pkt = self._make_packet(self.icmp_type, ident, data)
        return self.sock.sendto(pkt, (addr[0], 0))

    def set_peer_cipher(self, addr: Tuple[str, int], cipher_name: str) -> str:
        c = normalize_cipher_name(cipher_name)
        self._peer_cipher[addr] = self._cipher_id_by_name[c]
        return c

    def set_peer_psk(self, addr: Tuple[str, int], psk: str | bytes, cipher_name: str | None = None) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        key = _kdf(psk)
        self._peer_aeads[addr] = {
            CIPHER_AES128GCM: AESGCM(key[:16]),
            CIPHER_AES256GCM: AESGCM(key),
            CIPHER_CHACHA20: ChaCha20Poly1305(key),
        }
        if cipher_name is not None:
            return self.set_peer_cipher(addr, cipher_name)
        return normalize_cipher_name(self.cipher_name)

    def clear_peer(self, addr: Tuple[str, int]) -> None:
        self._peer_cipher.pop(addr, None)
        self._peer_aeads.pop(addr, None)

    def recvfrom(self, bufsize: int):
        while True:
            raw, addr = self.sock.recvfrom(max(bufsize, 65535))
            parsed = self._decode_message(raw, addr)
            if parsed is not None:
                return parsed

    def recvfrom_many(self, max_messages: int, bufsize: int):
        out = []
        try:
            first = self.recvfrom(bufsize)
        except Exception:
            return out
        out.append(first)
        old_timeout = self.sock.gettimeout()
        try:
            self.sock.settimeout(0.0)
            while len(out) < max_messages:
                try:
                    raw, addr = self.sock.recvfrom(max(bufsize, 65535))
                except (BlockingIOError, InterruptedError, TimeoutError, socket.timeout):
                    break
                parsed = self._decode_message(raw, addr)
                if parsed is not None:
                    out.append(parsed)
        finally:
            self.sock.settimeout(old_timeout)
        return out

    def _decode_message(self, raw: bytes, addr: Tuple[str, int]):
        parsed = self._parse_icmp(raw)
        if parsed is None:
            return None
        _icmp_type, ident, payload = parsed
        peer = (addr[0], ident)
        if payload[:4] == b"IDT1":
            return payload, peer
        if len(payload) < 4 + 1 + 12 + 16:
            return None
        if payload[:4] != MAGIC:
            return None
        cid = payload[4]
        nonce = payload[5:17]
        ct = payload[17:]
        peer_aeads = self._peer_aeads.get(peer)
        aead_sets = [peer_aeads] if peer_aeads is not None else [self._aead_by_id]
        for aead_by_id in aead_sets:
            aead = aead_by_id.get(cid)
            if aead is None:
                continue
            try:
                return aead.decrypt(nonce, ct, None), peer
            except Exception:
                pass
        return None

    def setsockopt(self, *args, **kwargs):
        return self.sock.setsockopt(*args, **kwargs)

    def getsockname(self):
        return self._local_ip, self.icmp_id
