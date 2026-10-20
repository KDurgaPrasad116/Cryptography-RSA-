import socket
import threading
import os
import argparse
import tkinter as tk
from tkinter import scrolledtext, ttk
from datetime import datetime
import crypto_utils

class AliceGUI:
    def __init__(self, root, host="127.0.0.1", port=65432, bits=1024):
        self.root = root
        self.host = host
        self.port = port
        self.bits = bits
        self.root.title("Alice - Encrypted TCP Chat (Receiver / Server)")
        self.root.geometry("680x580")
        self.root.configure(bg="#1a1d24")

        # Header
        header = tk.Label(
            root,
            text="Alice's Terminal (Receiver / RSA Key Authority)",
            font=("Segoe UI", 13, "bold"),
            fg="#61afef",
            bg="#1a1d24",
            pady=8
        )
        header.pack()

        # Config / Controls bar (no hardcoded ports/keys)
        ctrl_frame = tk.Frame(root, bg="#1a1d24")
        ctrl_frame.pack(fill=tk.X, padx=15, pady=3)

        tk.Label(ctrl_frame, text="Host:", fg="#abb2bf", bg="#1a1d24", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.host_entry = tk.Entry(ctrl_frame, width=12, bg="#21252b", fg="#abb2bf", font=("Consolas", 9), insertbackground="white")
        self.host_entry.insert(0, str(self.host))
        self.host_entry.pack(side=tk.LEFT, padx=(3, 8))

        tk.Label(ctrl_frame, text="Port:", fg="#abb2bf", bg="#1a1d24", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.port_entry = tk.Entry(ctrl_frame, width=7, bg="#21252b", fg="#abb2bf", font=("Consolas", 9), insertbackground="white")
        self.port_entry.insert(0, str(self.port))
        self.port_entry.pack(side=tk.LEFT, padx=(3, 8))

        tk.Label(ctrl_frame, text="RSA Bits:", fg="#abb2bf", bg="#1a1d24", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.bits_var = tk.StringVar(value=str(self.bits))
        self.bits_menu = ttk.Combobox(ctrl_frame, textvariable=self.bits_var, values=["1024", "2048", "3072"], width=6, state="readonly")
        self.bits_menu.pack(side=tk.LEFT, padx=(3, 8))

        self.server_btn = tk.Button(
            ctrl_frame,
            text="Restart Server",
            command=self.restart_server,
            bg="#61afef",
            fg="#1a1d24",
            font=("Segoe UI", 8, "bold"),
            padx=6,
            relief=tk.FLAT
        )
        self.server_btn.pack(side=tk.LEFT, padx=3)

        self.regen_btn = tk.Button(
            ctrl_frame,
            text="Regen Keys",
            command=self.regenerate_keys,
            bg="#98c379",
            fg="#1a1d24",
            font=("Segoe UI", 8, "bold"),
            padx=6,
            relief=tk.FLAT
        )
        self.regen_btn.pack(side=tk.LEFT, padx=3)

        # Status Label
        self.status_var = tk.StringVar(value="Status: Initializing...")
        self.status_lbl = tk.Label(
            root,
            textvariable=self.status_var,
            font=("Segoe UI", 9, "italic"),
            fg="#98c379",
            bg="#1a1d24"
        )
        self.status_lbl.pack(pady=2)

        # Message display
        self.msg_display = scrolledtext.ScrolledText(
            root,
            height=18,
            bg="#21252b",
            fg="#abb2bf",
            insertbackground="white",
            font=("Consolas", 9),
            padx=10,
            pady=10
        )
        self.msg_display.pack(fill=tk.BOTH, expand=True, padx=15, pady=8)

        # Directory for received files
        self.received_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_files")
        os.makedirs(self.received_dir, exist_ok=True)

        # Server state
        self.is_running = True
        self.server_socket = None
        self.server_thread = None

        # Keys
        self.private_key = None
        self.public_key = None
        self.public_key_pem = None
        self.regenerate_keys(initial=True)

        # Start server
        self.start_server_thread()

        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log(self, text):
        def _append():
            self.msg_display.insert(tk.END, text + "\n")
            self.msg_display.see(tk.END)
        self.root.after(0, _append)

    def set_status(self, text, color="#98c379"):
        def _update():
            self.status_var.set(text)
            self.status_lbl.config(fg=color)
        self.root.after(0, _update)

    def regenerate_keys(self, initial=False):
        try:
            bits = int(self.bits_var.get()) if hasattr(self, "bits_var") else self.bits
        except Exception:
            bits = 1024
        self.bits = bits
        self.log(f"[System] Generating fresh RSA {bits}-bit keypair...")
        self.private_key, self.public_key = crypto_utils.generate_rsa_keypair(bits=bits)
        self.public_key_pem = self.public_key.export_key()
        self.log(f"[System] RSA {bits}-bit Keypair generated successfully.")
        if not initial:
            self.log("[System] Note: Connected clients will receive the new public key on next handshake.")

    def restart_server(self):
        try:
            self.host = self.host_entry.get().strip()
            self.port = int(self.port_entry.get().strip())
        except ValueError:
            self.log("[Error] Invalid port number.")
            return

        self.log(f"[System] Restarting server on {self.host}:{self.port}...")
        self.stop_server()
        self.is_running = True
        self.start_server_thread()

    def start_server_thread(self):
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()

    def stop_server(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.log(f"[Alice Server] Listening on {self.host}:{self.port} (Waiting for Bob)...")
            self.set_status(f"Listening on {self.host}:{self.port}")

            while self.is_running:
                try:
                    conn, addr = self.server_socket.accept()
                except OSError:
                    break
                self.log(f"\n[Alice] Bob connected from {addr}!")
                self.set_status(f"Connected to {addr[0]}:{addr[1]}")
                client_handler = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_handler.start()
        except Exception as e:
            if self.is_running:
                self.log(f"[Error] Server socket error: {e}")
                self.set_status(f"Error: {e}", color="#e06c75")

    def handle_client(self, conn, addr):
        try:
            # Step 1: Send current Public Key framed
            crypto_utils.send_framed_msg(conn, self.public_key_pem)
            self.log(f"[Alice -> Bob] Sent Alice's RSA-{self.bits} Public Key.")

            # Keep reading framed messages from this client until disconnect
            while self.is_running:
                data = crypto_utils.recv_framed_msg(conn)
                if not data:
                    break

                if b"---SPLIT---" not in data:
                    self.log("[Alice] Warning: Malformed packet received (missing separator).")
                    continue

                encrypted_aes_key, payload = data.split(b"---SPLIT---", 1)

                # Decrypt AES Key using Alice's RSA Private Key
                try:
                    aes_key = crypto_utils.rsa_decrypt(self.private_key, encrypted_aes_key)
                    self.log(f"[Alice Security] Decrypted {len(aes_key)*8}-bit AES session key using RSA private key.")
                except Exception as e:
                    self.log(f"[Decryption Error] Failed to decrypt AES key: {e}")
                    continue

                # Parse Payload
                payload_parts = payload.split(b"---FILE---", 1)

                # Text Message Decryption
                msg_part = payload_parts[0]
                if msg_part:
                    try:
                        plaintext_msg = crypto_utils.aes_decrypt(aes_key, msg_part).decode("utf-8")
                        self.log(f"[Alice Received Message] >> {plaintext_msg}")
                    except Exception as e:
                        self.log(f"[Security Alert] Message AES-GCM verification failed (Tampered/Corrupt): {e}")

                # File Decryption
                if len(payload_parts) > 1 and payload_parts[1]:
                    try:
                        file_bytes = crypto_utils.aes_decrypt(aes_key, payload_parts[1])
                        filename = f"received_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                        save_path = os.path.join(self.received_dir, filename)
                        with open(save_path, "wb") as f:
                            f.write(file_bytes)
                        self.log(f"[Alice Received File] Saved {len(file_bytes)} bytes to {filename}")
                    except Exception as e:
                        self.log(f"[Security Alert] File AES-GCM verification failed (Tampered/Corrupt): {e}")

        except ConnectionResetError:
            self.log("[Alice] Bob disconnected.")
        except Exception as e:
            if self.is_running:
                self.log(f"[Alice Error] Client handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.log(f"[Alice] Connection with {addr} closed.")
            if self.is_running:
                self.set_status(f"Listening on {self.host}:{self.port}")

    def on_close(self):
        self.stop_server()
        self.root.destroy()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alice GUI Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=65432, help="Port to bind")
    parser.add_argument("--bits", type=int, default=1024, choices=[1024, 2048, 3072], help="RSA key bits")
    args = parser.parse_args()

    root = tk.Tk()
    app = AliceGUI(root, host=args.host, port=args.port, bits=args.bits)
    root.mainloop()
