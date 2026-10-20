import socket
import threading
import argparse
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import crypto_utils
from Crypto.PublicKey import RSA

class BobGUI:
    def __init__(self, root, host="127.0.0.1", port=65432):
        self.root = root
        self.host = host
        self.port = port
        self.root.title("Bob - Encrypted TCP Chat (Sender / Client)")
        self.root.geometry("680x620")
        self.root.configure(bg="#1e1e2e")

        self.client_socket = None
        self.alice_public_key = None
        self.is_connected = False

        # Header
        header = tk.Label(
            root,
            text="Bob's Terminal (Sender / AES-256 Encryptor)",
            font=("Segoe UI", 13, "bold"),
            fg="#89b4fa",
            bg="#1e1e2e",
            pady=6
        )
        header.pack()

        # Connection & Endpoint Configuration Bar (Dynamic, not hardcoded)
        conn_frame = tk.Frame(root, bg="#1e1e2e")
        conn_frame.pack(fill=tk.X, padx=15, pady=4)

        tk.Label(conn_frame, text="Host:", fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.host_entry = tk.Entry(conn_frame, width=12, bg="#313244", fg="#cdd6f4", font=("Consolas", 9), insertbackground="white")
        self.host_entry.insert(0, str(self.host))
        self.host_entry.pack(side=tk.LEFT, padx=(3, 8))

        tk.Label(conn_frame, text="Port:", fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.port_entry = tk.Entry(conn_frame, width=7, bg="#313244", fg="#cdd6f4", font=("Consolas", 9), insertbackground="white")
        self.port_entry.insert(0, str(self.port))
        self.port_entry.pack(side=tk.LEFT, padx=(3, 8))

        self.connect_btn = tk.Button(
            conn_frame,
            text="Connect",
            command=self.toggle_connection,
            font=("Segoe UI", 9, "bold"),
            bg="#a6e3a1",
            fg="#11111b",
            padx=10,
            pady=2,
            relief=tk.FLAT
        )
        self.connect_btn.pack(side=tk.LEFT)

        self.status_lbl = tk.Label(
            conn_frame,
            text="Status: Disconnected",
            font=("Segoe UI", 9, "italic"),
            fg="#f38ba8",
            bg="#1e1e2e",
            padx=10
        )
        self.status_lbl.pack(side=tk.LEFT)

        # Log Display
        self.msg_display = scrolledtext.ScrolledText(
            root,
            height=13,
            bg="#181825",
            fg="#cdd6f4",
            insertbackground="white",
            font=("Consolas", 9),
            padx=10,
            pady=10
        )
        self.msg_display.pack(fill=tk.BOTH, expand=True, padx=15, pady=6)

        # Message Input Area
        input_frame = tk.Frame(root, bg="#1e1e2e")
        input_frame.pack(fill=tk.X, padx=15, pady=4)

        tk.Label(input_frame, text="Message to encrypt:", fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 9)).pack(anchor=tk.W)
        self.entry = tk.Entry(input_frame, bg="#313244", fg="#cdd6f4", font=("Segoe UI", 10), insertbackground="white")
        self.entry.pack(fill=tk.X, pady=3)
        self.entry.bind("<Return>", lambda e: self.send_message())

        # Tampering Experiment Options (Interactive Testing)
        tamper_frame = tk.Frame(root, bg="#1e1e2e")
        tamper_frame.pack(fill=tk.X, padx=15, pady=2)
        tk.Label(tamper_frame, text="Tamper Simulation:", fg="#fab387", bg="#1e1e2e", font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        self.tamper_var = tk.StringVar(value="none")
        tk.Radiobutton(tamper_frame, text="None (Normal)", variable=self.tamper_var, value="none", bg="#1e1e2e", fg="#cdd6f4", selectcolor="#313244", activebackground="#1e1e2e", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(tamper_frame, text="Flip Ciphertext Byte", variable=self.tamper_var, value="ciphertext", bg="#1e1e2e", fg="#f38ba8", selectcolor="#313244", activebackground="#1e1e2e", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(tamper_frame, text="Corrupt Auth Tag", variable=self.tamper_var, value="tag", bg="#1e1e2e", fg="#f38ba8", selectcolor="#313244", activebackground="#1e1e2e", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        # Buttons
        btn_frame = tk.Frame(root, bg="#1e1e2e")
        btn_frame.pack(fill=tk.X, padx=15, pady=8)

        self.send_msg_btn = tk.Button(
            btn_frame,
            text="Send Encrypted Message",
            command=self.send_message,
            bg="#89b4fa",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=5,
            relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.send_msg_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.send_file_btn = tk.Button(
            btn_frame,
            text="Send Encrypted File",
            command=self.send_file,
            bg="#f9e2af",
            fg="#11111b",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=5,
            relief=tk.FLAT,
            state=tk.DISABLED
        )
        self.send_file_btn.pack(side=tk.LEFT)

        self.log("[System] Set Alice's Host:Port and click 'Connect'.")

        # Auto-connect background attempt
        threading.Thread(target=self.attempt_connect, daemon=True).start()

    def log(self, text):
        def _append():
            self.msg_display.insert(tk.END, text + "\n")
            self.msg_display.see(tk.END)
        self.root.after(0, _append)

    def toggle_connection(self):
        if not self.is_connected:
            threading.Thread(target=self.attempt_connect, daemon=True).start()
        else:
            self.disconnect()

    def attempt_connect(self):
        target_host = self.host_entry.get().strip() if hasattr(self, "host_entry") else self.host
        try:
            target_port = int(self.port_entry.get().strip()) if hasattr(self, "port_entry") else self.port
        except ValueError:
            self.log("[Error] Invalid port specified.")
            return

        self.log(f"[Bob] Connecting to Alice on {target_host}:{target_port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_host, target_port))
            self.client_socket = sock

            # Step 1: Receive Alice's public key framed
            public_key_pem = crypto_utils.recv_framed_msg(self.client_socket)
            if not public_key_pem:
                raise ConnectionError("Server disconnected before sending public key.")

            self.alice_public_key = RSA.import_key(public_key_pem)
            key_bits = self.alice_public_key.size_in_bits()

            self.is_connected = True
            self.log(f"[Handshake] Received Alice's RSA-{key_bits} Public Key successfully!")
            self.log("[Ready] Bob can now securely transmit AES-256 encrypted messages and files.")

            self.root.after(0, self._on_connected)
        except ConnectionRefusedError:
            self.log(f"[Bob] Connection failed: No listener at {target_host}:{target_port}.")
            self.root.after(0, lambda: self.status_lbl.config(text="Status: Server offline", fg="#f38ba8"))
        except Exception as e:
            self.log(f"[Bob] Connection error: {e}")
            self.root.after(0, lambda: self.status_lbl.config(text="Status: Error", fg="#f38ba8"))

    def _on_connected(self):
        self.status_lbl.config(text="Status: Connected to Alice", fg="#a6e3a1")
        self.connect_btn.config(text="Disconnect", bg="#f38ba8")
        self.send_msg_btn.config(state=tk.NORMAL)
        self.send_file_btn.config(state=tk.NORMAL)

    def disconnect(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        self.client_socket = None
        self.alice_public_key = None
        self.is_connected = False
        self.status_lbl.config(text="Status: Disconnected", fg="#f38ba8")
        self.connect_btn.config(text="Connect", bg="#a6e3a1")
        self.send_msg_btn.config(state=tk.DISABLED)
        self.send_file_btn.config(state=tk.DISABLED)
        self.log("[Bob] Disconnected from Alice.")

    def send_message(self):
        if not self.is_connected or not self.alice_public_key:
            messagebox.showwarning("Warning", "Please connect to Alice first.")
            return

        plaintext = self.entry.get().strip()
        if not plaintext:
            return

        try:
            # 1. Generate fresh AES-256 session key
            aes_key = crypto_utils.generate_aes_key()

            # 2. Encrypt message with AES-256 GCM
            encrypted_data = crypto_utils.aes_encrypt(aes_key, plaintext.encode("utf-8"))

            # Tamper mode simulation if chosen
            mode = self.tamper_var.get()
            if mode == "ciphertext":
                # Invert first ciphertext byte
                nonce = encrypted_data[:16]
                tag = encrypted_data[16:32]
                ct = bytearray(encrypted_data[32:])
                if ct:
                    ct[0] ^= 0xFF
                encrypted_data = nonce + tag + bytes(ct)
                self.log("[Tamper Alert] Inverted first byte of ciphertext before transmission!")
            elif mode == "tag":
                # Invert first tag byte
                nonce = encrypted_data[:16]
                tag = bytearray(encrypted_data[16:32])
                ct = encrypted_data[32:]
                tag[0] ^= 0xAA
                encrypted_data = nonce + bytes(tag) + ct
                self.log("[Tamper Alert] Corrupted AES-GCM authentication tag before transmission!")

            # 3. Encrypt AES key with Alice's RSA Public Key
            encrypted_aes_key = crypto_utils.rsa_encrypt(self.alice_public_key, aes_key)

            # 4. Payload: msg + '---FILE---' + empty file part
            payload = encrypted_data + b"---FILE---"
            full_data = encrypted_aes_key + b"---SPLIT---" + payload

            # 5. Transmit using length-prefixed framing
            crypto_utils.send_framed_msg(self.client_socket, full_data)

            self.log(f"[Bob -> Alice] Sent: \"{plaintext}\"")
            self.log(f"   AES-256 Session Key: {aes_key.hex()[:16]}... (RSA Encrypted)")
            self.log(f"   Transmitted wire payload: {len(full_data)} bytes")
            self.entry.delete(0, tk.END)
        except Exception as e:
            self.log(f"[Error] Failed to send message: {e}")
            self.disconnect()

    def send_file(self):
        if not self.is_connected or not self.alice_public_key:
            messagebox.showwarning("Warning", "Please connect to Alice first.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            aes_key = crypto_utils.generate_aes_key()
            encrypted_file = crypto_utils.aes_encrypt(aes_key, file_bytes)

            mode = self.tamper_var.get()
            if mode == "ciphertext":
                nonce = encrypted_file[:16]
                tag = encrypted_file[16:32]
                ct = bytearray(encrypted_file[32:])
                if ct:
                    ct[0] ^= 0xFF
                encrypted_file = nonce + tag + bytes(ct)
                self.log("[Tamper Alert] Inverted ciphertext byte in file!")
            elif mode == "tag":
                nonce = encrypted_file[:16]
                tag = bytearray(encrypted_file[16:32])
                ct = encrypted_file[32:]
                tag[0] ^= 0xAA
                encrypted_file = nonce + bytes(tag) + ct
                self.log("[Tamper Alert] Corrupted file authentication tag!")

            encrypted_aes_key = crypto_utils.rsa_encrypt(self.alice_public_key, aes_key)

            payload = b"---FILE---" + encrypted_file
            full_data = encrypted_aes_key + b"---SPLIT---" + payload

            crypto_utils.send_framed_msg(self.client_socket, full_data)
            self.log(f"[Bob -> Alice] Sent file: {file_path} ({len(file_bytes)} bytes unencrypted, {len(full_data)} bytes wire)")
        except Exception as e:
            self.log(f"[Error] Failed to send file: {e}")
            self.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bob GUI Client")
    parser.add_argument("--host", default="127.0.0.1", help="Alice server host")
    parser.add_argument("--port", type=int, default=65432, help="Alice server port")
    args = parser.parse_args()

    root = tk.Tk()
    app = BobGUI(root, host=args.host, port=args.port)
    root.mainloop()
