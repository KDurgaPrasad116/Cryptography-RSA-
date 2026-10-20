# bob.py
"""
Bob CLI Sender & TCP Client
Usage:
    python bob.py [--host HOST] [--port PORT] [--message MESSAGE]
"""

import sys
import argparse
import socket
from Crypto.PublicKey import RSA
import crypto_utils

def main():
    parser = argparse.ArgumentParser(description="Bob - Encrypted TCP Sender")
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=65432, help="Target port (default: 65432)")
    parser.add_argument("--message", default=None, help="Message to encrypt and send (prompts if omitted)")
    args = parser.parse_args()

    message_str = args.message
    if not message_str:
        if sys.stdin.isatty():
            message_str = input("Enter message for Alice: ").strip()
        if not message_str:
            message_str = "This is a secured message from Bob, encrypted with AES-256-GCM."

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((args.host, args.port))
        print(f"[Bob] Connected to Alice on {args.host}:{args.port}.")

        # Step 1: Receive Alice's public RSA key via framing
        public_key_pem = crypto_utils.recv_framed_msg(client_socket)
        if not public_key_pem:
            print("[Bob] Error: Connection closed before receiving public key.")
            return

        alice_public_key = RSA.import_key(public_key_pem)
        print(f"[Bob] Received Alice's public key ({alice_public_key.size_in_bits()} bits).")

        # Step 2: Generate fresh AES key and encrypt message
        aes_key = crypto_utils.generate_aes_key()
        aes_ciphertext = crypto_utils.aes_encrypt(aes_key, message_str.encode("utf-8"))

        # Step 3: Encrypt AES key with Alice's RSA public key
        encrypted_aes_key = crypto_utils.rsa_encrypt(alice_public_key, aes_key)

        # Step 4: Transmit framed packet
        packet = encrypted_aes_key + b"---SPLIT---" + aes_ciphertext
        crypto_utils.send_framed_msg(client_socket, packet)
        print(f"[Bob] Sent {len(packet)} bytes encrypted payload to Alice.")

    except Exception as e:
        print(f"[Bob] Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
