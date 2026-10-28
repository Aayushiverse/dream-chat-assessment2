"""
DREAM-CHAT Server (Assessment 2 - Improved Version)
A secure multi-client chat server using AES encryption.
Python 3 compatible.
"""

import configparser
import base64
import socket
import select
import hashlib
import signal
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ============================================================
# UTILITY FUNCTIONS (Hasher, Encrypt, Decrypt)
# ============================================================

def hasher(key: str) -> bytes:
    """
    Derive a 32-byte AES key from a plaintext password.
    Uses SHA-512 followed by MD5 (as per original DREAM-CHAT),
    then truncates to 32 bytes for AES-256.
    """
    hash_object = hashlib.sha512(key.encode('utf-8'))
    hexd = hash_object.hexdigest()
    hash_object = hashlib.md5(hexd.encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    # AES-256 needs 32 bytes; MD5 hexdigest is 32 chars -> 32 bytes
    return hex_dig.encode('utf-8')


def encrypt(secret: bytes, data: str) -> bytes:
    """
    Encrypt a string using AES-CBC with a random IV.
    Returns base64-encoded IV + ciphertext.
    """
    data_bytes = data.encode('utf-8')
    cipher = AES.new(secret, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
    # Prepend IV to ciphertext
    iv_and_ct = cipher.iv + ct_bytes
    return base64.b64encode(iv_and_ct)


def decrypt(secret: bytes, data: bytes) -> str:
    """
    Decrypt a base64-encoded IV + ciphertext using AES-CBC.
    Returns the plaintext string.
    """
    try:
        decoded = base64.b64decode(data)
        iv = decoded[:AES.block_size]
        ct = decoded[AES.block_size:]
        cipher = AES.new(secret, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError) as e:
        return f"[decryption error: {e}]"


# ============================================================
# SERVER CLASS
# ============================================================

class ChatServer:
    """Central server that manages client connections and broadcasts messages."""

    def __init__(self, host: str, port: int, password: str, view: bool = False):
        self.host = host
        self.port = port
        self.key = hasher(password)
        self.view = view
        self.socket_list = []
        self.recv_buffer = 4096
        self.server_socket = None

    def start(self):
        """Initialize the server socket and enter the main loop."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        self.socket_list.append(self.server_socket)

        print(f"[Server] Started on {self.host}:{self.port}")
        print("[Server] Waiting for connections...\n")

        try:
            self._main_loop()
        except KeyboardInterrupt:
            print("\n[Server] Shutting down...")
        finally:
            self.server_socket.close()

    def _main_loop(self):
        """Main event loop using select() for I/O multiplexing."""
        while True:
            ready_to_read, _, _ = select.select(self.socket_list, [], [], 0)

            for sock in ready_to_read:
                if sock == self.server_socket:
                    self._accept_new_client(sock)
                else:
                    self._handle_client_data(sock)

    def _accept_new_client(self, server_socket):
        """Accept a new client connection."""
        sockfd, addr = server_socket.accept()
        self.socket_list.append(sockfd)
        print(f"[Server] User {addr} connected")

    def _handle_client_data(self, sock):
        """Receive, decrypt, and broadcast data from a client."""
        try:
            data = sock.recv(self.recv_buffer)
            if data:
                decrypted = decrypt(self.key, data)
                if self.view:
                    print(decrypted)
                # Re-encrypt and broadcast to all other clients
                self.broadcast(sock, encrypt(self.key, "\r" + decrypted))
            else:
                # Client disconnected
                self._remove_client(sock)
        except Exception as e:
            print(f"[Server] Error handling client: {e}")
            self._remove_client(sock)

    def _remove_client(self, sock):
        """Remove a client from the socket list."""
        if sock in self.socket_list:
            self.socket_list.remove(sock)
            sock.close()
            print("[Server] A user disconnected")

    def broadcast(self, sender_socket, message: bytes):
        """Send a message to all clients except the sender."""
        for sock in self.socket_list:
            if sock != self.server_socket and sock != sender_socket:
                try:
                    sock.send(message)
                except Exception:
                    sock.close()
                    if sock in self.socket_list:
                        self.socket_list.remove(sock)


# ============================================================
# MAIN
# ============================================================

def main():
    config = configparser.RawConfigParser()
    config.read('config.ini')

    host = config.get('config', 'HOST')
    port = int(config.get('config', 'PORT'))
    password = config.get('config', 'PASSWORD')
    view = config.get('config', 'VIEW') == '1'

    server = ChatServer(host, port, password, view)
    server.start()


if __name__ == "__main__":
    main()