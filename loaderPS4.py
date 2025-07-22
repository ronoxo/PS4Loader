import socket
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import json

CONFIG_FILE = "ps4loader_config.json"

class PS4LoaderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PS4 Stage2 Loader - Python")
        self.geometry("450x450")
        self.configure(bg="#1e1e1e")

        self.style = ttk.Style(self)
        self.style.theme_use('clam')  # Thème ttk sympa
        self.style.configure('.', background='#1e1e1e', foreground='lime', font=("Segoe UI", 11))
        self.style.configure('TButton', background='lime', foreground='black')
        self.style.map('TButton', background=[('active', '#76c043')])

        # Variables
        self.payload_path = None

        # Chargement config
        self.config_data = self.load_config()

        # IP Entry
        ttk.Label(self, text="Adresse IP PS4 :").pack(pady=(10,0))
        self.ip_var = tk.StringVar(value=self.config_data.get("ip", "192.168.0.10"))
        self.ip_entry = ttk.Entry(self, textvariable=self.ip_var)
        self.ip_entry.pack(pady=5, fill='x', padx=20)

        # Firmware combobox
        ttk.Label(self, text="Firmware :").pack(pady=(10,0))
        self.firmware_var = tk.StringVar()
        self.firmware_cb = ttk.Combobox(self, textvariable=self.firmware_var, values=["9.00", "10.00", "11.00"], state="readonly")
        self.firmware_cb.pack(pady=5, fill='x', padx=20)
        self.firmware_cb.set(self.config_data.get("firmware", "11.00"))

        # Payload file chooser
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10, fill='x', padx=20)

        self.btn_choose_file = ttk.Button(btn_frame, text="Choisir Payload", command=self.choose_payload)
        self.btn_choose_file.pack(side='left')

        self.lbl_file = ttk.Label(btn_frame, text="Aucun fichier sélectionné", foreground="yellow")
        self.lbl_file.pack(side='left', padx=10)

        # Buttons
        btn_jailbreak = ttk.Button(self, text="JAILBREAK", command=self.send_payload)
        btn_jailbreak.pack(pady=10, ipadx=10, ipady=5, fill='x', padx=20)

        btn_clear = ttk.Button(self, text="Clear Log", command=self.clear_log)
        btn_clear.pack(pady=5, ipadx=10, ipady=5, fill='x', padx=20)

        btn_quit = ttk.Button(self, text="Quitter", command=self.destroy)
        btn_quit.pack(pady=5, ipadx=10, ipady=5, fill='x', padx=20)

        # Log box
        self.log_box = scrolledtext.ScrolledText(self, bg="#121212", fg="lime", font=("Consolas", 10), state='disabled', height=10)
        self.log_box.pack(fill="both", padx=10, pady=10, expand=True)

        # Load default payload if exists
        self.set_default_payload()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_config(self):
        data = {
            "ip": self.ip_var.get(),
            "firmware": self.firmware_var.get()
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f)

    def set_default_payload(self):
        fw = self.firmware_var.get()
        default_path = f"{fw}_stage2.bin"
        if os.path.exists(default_path):
            self.payload_path = default_path
            self.lbl_file.config(text=default_path, foreground="lime")
        else:
            self.lbl_file.config(text="Aucun fichier sélectionné", foreground="yellow")

    def choose_payload(self):
        file = filedialog.askopenfilename(title="Choisir payload stage2 .bin",
                                          filetypes=[("BIN files","*.bin"), ("All files","*.*")])
        if file:
            self.payload_path = file
            self.lbl_file.config(text=os.path.basename(file), foreground="lime")
            self.log(f"[INFO] Payload sélectionné : {file}")

    def log(self, message):
        self.log_box.config(state='normal')
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)
        self.log_box.config(state='disabled')

    def clear_log(self):
        self.log_box.config(state='normal')
        self.log_box.delete('1.0', tk.END)
        self.log_box.config(state='disabled')

    def send_payload(self):
        ip = self.ip_var.get().strip()
        firmware = self.firmware_var.get()

        if not ip:
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP valide.")
            return

        if not self.payload_path or not os.path.exists(self.payload_path):
            self.set_default_payload()
            if not self.payload_path or not os.path.exists(self.payload_path):
                messagebox.showerror("Erreur", "Aucun payload valide sélectionné.")
                self.log("[ERROR] Aucun payload valide sélectionné.")
                return

        self.log(f"[INFO] Chargement du payload : {self.payload_path}")

        try:
            with open(self.payload_path, "rb") as f:
                payload = f.read()
        except Exception as e:
            self.log(f"[ERROR] Impossible de lire le fichier payload: {e}")
            messagebox.showerror("Erreur", f"Impossible de lire le fichier payload:\n{e}")
            return

        self.log(f"[INFO] Connexion à {ip} sur le port 9020...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 9020))
            sock.sendall(payload)
            sock.close()
            self.log("[SUCCESS] Payload envoyé avec succès !")
            messagebox.showinfo("Succès", "Payload envoyé avec succès !")
            self.save_config()
        except Exception as e:
            self.log(f"[ERROR] Erreur lors de l'envoi du payload : {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'envoi du payload :\n{e}")

if __name__ == "__main__":
    app = PS4LoaderApp()
    app.mainloop()
