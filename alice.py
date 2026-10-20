# alice.py
"""
Alice CLI Receiver & TCP Server
Usage:
    python alice.py [--host HOST] [--port PORT] [--bits BITS]
"""

import sys
import argparse
import socket
import crypto_utils

def main():
    parser = argparse.ArgumentParser(description="Alice - Encrypted TCP Receiver")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=65432, help="Port to bind (default: 65432)")
    parser.add_argument("--bits", type=int, default=1024, choices=[1024, 2048, 3072, 4096], help="RSA key bits (default: 1024)")
    args = parser.parse_args()

    print(f"[Alice] Generating RSA {args.bits}-bit keypair...")
    private_key, public_key = crypto_utils.generate_rsa_keypair(bits=args.bits)
    public_key_pem = public_key.export_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((args.host, args.port))
    server_socket.listen(1)

    print(f"[Alice] Listening on {args.host}:{args.port}... Waiting for Bob.")
    conn, addr = server_socket.accept()
    print(f"[Alice] Connected with {addr}.")

    try:
        # Step 1: Send Alice's public key using length-prefixed framing
        crypto_utils.send_framed_msg(conn, public_key_pem)
        print("[Alice] Public key sent.")

        # Step 2: Receive framed payload
        wire_packet = crypto_utils.recv_framed_msg(conn)
        if not wire_packet or b"---SPLIT---" not in wire_packet:
            print("[Alice] Error: Invalid packet structure received.")
            return

        encrypted_aes_key, aes_ciphertext = wire_packet.split(b"---SPLIT---", 1)
        print(f"[Alice] Received encrypted payload ({len(wire_packet)} bytes).")

        # Step 3: Decrypt AES key with RSA private key
        aes_key = crypto_utils.rsa_decrypt(private_key, encrypted_aes_key)

        # Step 4: Decrypt message with AES key
        plaintext = crypto_utils.aes_decrypt(aes_key, aes_ciphertext)
        print("[Alice] Final decrypted message from Bob:", plaintext.decode("utf-8", errors="replace"))

    except Exception as e:
        print(f"[Alice] Processing error: {e}")
    finally:
        conn.close()
        server_socket.close()
        print("[Alice] Connection closed.")

if __name__ == "__main__":
    main()
