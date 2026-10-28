"""
DREAM-CHAT Client (Assessment 2 - Improved Version)
A secure chat client that connects to the server.
Python 3 compatible.
Windows-compatible with proper input handling.
"""

import socket
import sys
import hashlib
import base64
import threading
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def hasher(key: str) -> bytes:
    """Derive a 32-byte AES key from a plaintext password."""
    hash_object = hashlib.sha512(key.encode('utf-8'))
    hexd = hash_object.hexdigest()
    hash_object = hashlib.md5(hexd.encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    return hex_dig.encode('utf-8')


def encrypt(secret: bytes, data: str) -> bytes:
    """Encrypt a string using AES-CBC with a random IV."""
    data_bytes = data.encode('utf-8')
    cipher = AES.new(secret, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
    iv_and_ct = cipher.iv + ct_bytes
    return base64.b64encode(iv_and_ct)


def decrypt(secret: bytes, data: bytes) -> str:
    """Decrypt a base64-encoded IV + ciphertext."""
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
# CLIENT CLASS
# ============================================================

class ChatClient:
    """Client that connects to the chat server and exchanges messages."""

    def __init__(self, host: str, port: int, password: str, username: str):
        self.host = host
        self.port = port
        self.key = hasher(password)
        self.username = username
        self.socket = None
        self.running = True
        self.print_lock = threading.Lock()

    def connect(self) -> bool:
        """Connect to the server. Returns True on success."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        try:
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)
            print("Connected to remote host. Your messages will be securely transmitted.")
            return True
        except Exception:
            print("Unable to connect to server.")
            return False

    def run(self):
        """Main chat loop. Receive thread + input in main thread."""
        # Start the receiving thread
        recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        recv_thread.start()

        # Main thread handles input
        try:
            self._input_loop()
        except KeyboardInterrupt:
            print("\n[Client] Shutting down...")
            self.running = False
            try:
                self.socket.close()
            except Exception:
                pass
            sys.exit(0)

    def _receive_loop(self):
        """Continuously receive messages from the server."""
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    with self.print_lock:
                        print("\nDisconnected from server.")
                    self.running = False
                    break
                message = decrypt(self.key, data)
                with self.print_lock:
                    # Clear the current input line, print message, then reprint prompt
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    print(message)
                    sys.stdout.write(f"[{self.username}] # ")
                    sys.stdout.flush()
            except Exception as e:
                if self.running:
                    with self.print_lock:
                        print(f"\n[Client] Error receiving: {e}")
                self.running = False
                break

    def _input_loop(self):
        """Read user input and send encrypted messages."""
        while self.running:
            try:
                prompt = f"[{self.username}] # "
                msg = input(prompt)
                if not msg.strip():
                    continue
                full_msg = f"[{self.username}]: {msg}\n"
                encrypted = encrypt(self.key, full_msg)
                self.socket.send(encrypted)
            except EOFError:
                break
            except Exception as e:
                print(f"\n[Client] Error sending: {e}")
                self.running = False
                break


# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 5:
        print("Usage: python client.py [hostname] [port] [password] [username]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    password = sys.argv[3]
    username = sys.argv[4]

    client = ChatClient(host, port, password, username)
    if client.connect():
        client.run()


if __name__ == "__main__":
    main()