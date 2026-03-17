import customtkinter as ctk
import tkinter.messagebox as messagebox
import json
import os
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import sys

# --- КОНФИГУРАЦИЯ И ПУТИ ---
SYSTEM = platform.system()
if SYSTEM == "Windows":
    DATA_DIR = os.path.dirname(os.path.abspath(__file__))
elif SYSTEM == "Darwin":
    DATA_DIR = os.path.expanduser("~/Library/Application Support/PassHere")
    os.makedirs(DATA_DIR, exist_ok=True)
else:
    DATA_DIR = os.path.expanduser("~/.local/share/PassHere")
    os.makedirs(DATA_DIR, exist_ok=True)

DATA_FILE = os.path.join(DATA_DIR, "vault.enc")
SALT_FILE = os.path.join(DATA_DIR, "salt.key")

# --- КРИПТОГРАФИЯ ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_or_create_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f: f.write(salt)
        return salt
    with open(SALT_FILE, 'rb') as f: return f.read()

def get_fernet_instance(password: str, salt: bytes = None):
    if salt is None: salt = load_or_create_salt()
    key = derive_key(password, salt)
    return Fernet(key), salt

def save_vault(vault, fernet):
    data_json = json.dumps(vault, ensure_ascii=False).encode('utf-8')
    encrypted_data = fernet.encrypt(data_json)
    with open(DATA_FILE, 'wb') as f: f.write(encrypted_data)

def load_vault(fernet):
    if not os.path.exists(DATA_FILE): return []
    try:
        with open(DATA_FILE, 'rb') as f: encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        return None

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def toggle_visibility(entry_widget, button_widget):
    if entry_widget.cget("show") == "*":
        entry_widget.configure(show="")
        button_widget.configure(text="🙈")
    else:
        entry_widget.configure(show="*")
        button_widget.configure(text="👁️")

# --- GUI ПРИЛОЖЕНИЕ ---
class PassHereApp(ctk.CTk):
    def __init__(self, fernet):
        super().__init__()
        self.fernet = fernet
        self.vault = load_vault(fernet)
        
        self.title("PassHere v2.3")
        self.geometry("950x650")
        self.minsize(800, 600)
        
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        self.colors = {
            "bg_dark": "#2b2b2b",
            "card_bg": "#333333",
            "accent": "#2980b9",
            "accent_hover": "#3498db",
            "danger": "#c0392b",
            "success": "#27ae60",
            "text_main": "#ecf0f1",
            "text_sec": "#bdc3c7",
            "btn_gray": "#7f8c8d",
            "btn_gray_hover": "#95a5a6"
        }

        self.master_corner_radius = 15
        self.btn_corner_radius = 12
        self.entry_corner_radius = 10

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=self.colors["bg_dark"])
        self.sidebar.grid(row=0, column=0, sticky="ns")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="PassHere", font=ctk.CTkFont(size=28, weight="bold"), text_color=self.colors["text_main"])
        self.logo.grid(row=0, column=0, padx=20, pady=(50, 30))

        self.btn_list = ctk.CTkButton(self.sidebar, text="All Passwords", command=self.show_list_view, 
                                      corner_radius=self.btn_corner_radius, height=45,
                                      fg_color="#444444", hover_color="#555555", text_color=self.colors["text_main"])
        self.btn_list.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_add = ctk.CTkButton(self.sidebar, text="Add New", command=self.show_add_view, 
                                     corner_radius=self.btn_corner_radius, height=45,
                                     fg_color="#444444", hover_color="#555555", text_color=self.colors["text_main"])
        self.btn_add.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_exit = ctk.CTkButton(self.sidebar, text="Exit", fg_color=self.colors["danger"], hover_color="#a93226", 
                                      command=self.quit, corner_radius=self.btn_corner_radius, height=45)
        self.btn_exit.grid(row=9, column=0, padx=20, pady=(250, 20), sticky="ew")

        # Main Area: Стандартный скроллфрейм (скроллбар появляется сам при необходимости)
        self.main_area = ctk.CTkScrollableFrame(self, corner_radius=0, fg_color="transparent")
        self.main_area.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)

        # Контейнер для уведомлений
        self.toast_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.toast_frame.place(relx=1.0, rely=0.0, anchor="ne", x=-20, y=20)

        if self.vault is None:
            self.show_toast("Error: Wrong master password!", type="error")
            self.after(1000, self.quit)
            return

        self.show_list_view()

    def clear_main(self):
        for widget in self.main_area.winfo_children():
            widget.destroy()

    def show_toast(self, message, type="info"):
        toast = ctk.CTkFrame(self.toast_frame, corner_radius=12, fg_color="transparent")
        toast.pack(anchor="e", pady=5, padx=5)
        
        if type == "success": bg_color = self.colors["success"]; icon = "✅"
        elif type == "error": bg_color = self.colors["danger"]; icon = "❌"
        else: bg_color = self.colors["accent"]; icon = "ℹ️"
            
        content_frame = ctk.CTkFrame(toast, corner_radius=12, fg_color=bg_color)
        content_frame.pack(fill="both", expand=True)
        
        label = ctk.CTkLabel(content_frame, text=f"{icon}  {message}", 
                             text_color="#ffffff", font=ctk.CTkFont(size=14, weight="bold"),
                             padx=20, pady=15)
        label.pack()
        
        def destroy_toast():
            try: toast.destroy()
            except: pass
        
        self.after(3000, destroy_toast)

    def show_list_view(self):
        self.clear_main()
        header = ctk.CTkLabel(self.main_area, text="Your Vault", font=ctk.CTkFont(size=24, weight="bold"), text_color=self.colors["text_main"])
        header.pack(anchor="w", pady=(0, 25))
        
        if not self.vault:
            empty_label = ctk.CTkLabel(self.main_area, text="Vault is empty. Add some passwords!", 
                                       text_color=self.colors["text_sec"], font=ctk.CTkFont(size=16))
            empty_label.pack(pady=40)
            return

        for i, acc in enumerate(self.vault):
            frame = ctk.CTkFrame(self.main_area, corner_radius=self.master_corner_radius, fg_color=self.colors["card_bg"])
            frame.pack(fill="x", pady=8)
            
            ctk.CTkLabel(frame, text=f"{acc['service']}", font=ctk.CTkFont(size=16, weight="bold"), 
                         width=200, anchor="w", text_color=self.colors["text_main"]).pack(side="left", padx=20, pady=15)
            ctk.CTkLabel(frame, text=f"{acc['login']}", width=200, anchor="w", 
                         text_color=self.colors["text_sec"]).pack(side="left", padx=10, pady=15)
            
            btn_copy = ctk.CTkButton(frame, text="Copy", width=90, height=35, corner_radius=self.btn_corner_radius,
                                     command=lambda p=acc['password']: self.copy_to_clipboard(p),
                                     fg_color=self.colors["accent"], hover_color=self.colors["accent_hover"])
            btn_copy.pack(side="right", padx=10, pady=10)
            
            btn_del = ctk.CTkButton(frame, text="Delete", width=80, height=35, 
                                    fg_color=self.colors["btn_gray"], hover_color=self.colors["btn_gray_hover"],
                                    corner_radius=self.btn_corner_radius,
                                    command=lambda idx=i: self.delete_item(idx))
            btn_del.pack(side="right", padx=5, pady=10)

    def copy_to_clipboard(self, password):
        self.clipboard_clear()
        self.clipboard_append(password)
        self.show_toast("Password copied!", type="success")

    def delete_item(self, idx):
        if messagebox.askyesno("Confirm Delete", "Are you sure?", icon='warning'):
            self.vault.pop(idx)
            save_vault(self.vault, self.fernet)
            self.show_toast("Item deleted", type="success")
            self.show_list_view()

    def show_add_view(self):
        self.clear_main()
        header = ctk.CTkLabel(self.main_area, text="Add New Account", font=ctk.CTkFont(size=24, weight="bold"), text_color=self.colors["text_main"])
        header.pack(anchor="w", pady=(0, 25))
        
        form_frame = ctk.CTkFrame(self.main_area, corner_radius=self.master_corner_radius, fg_color=self.colors["card_bg"])
        form_frame.pack(fill="x", pady=10, padx=20)
        
        pad_y = 15
        pad_x = 20
        
        ctk.CTkLabel(form_frame, text="Service:", font=ctk.CTkFont(size=14), text_color=self.colors["text_sec"]).grid(row=0, column=0, padx=pad_x, pady=pad_y, sticky="e")
        self.entry_service = ctk.CTkEntry(form_frame, width=350, corner_radius=self.entry_corner_radius, height=35,
                                          fg_color="#222222", border_color="#444444", text_color=self.colors["text_main"])
        self.entry_service.grid(row=0, column=1, padx=pad_x, pady=pad_y)
        
        ctk.CTkLabel(form_frame, text="Login:", text_color=self.colors["text_sec"]).grid(row=1, column=0, padx=pad_x, pady=pad_y, sticky="e")
        self.entry_login = ctk.CTkEntry(form_frame, width=350, corner_radius=self.entry_corner_radius, height=35,
                                        fg_color="#222222", border_color="#444444", text_color=self.colors["text_main"])
        self.entry_login.grid(row=1, column=1, padx=pad_x, pady=pad_y)
        
        ctk.CTkLabel(form_frame, text="Password:", text_color=self.colors["text_sec"]).grid(row=2, column=0, padx=pad_x, pady=pad_y, sticky="e")
        
        pass_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        pass_frame.grid(row=2, column=1, padx=pad_x, pady=pad_y, sticky="w")
        
        self.entry_pass = ctk.CTkEntry(pass_frame, width=300, show="*", corner_radius=self.entry_corner_radius, height=35,
                                       fg_color="#222222", border_color="#444444", text_color=self.colors["text_main"])
        self.entry_pass.pack(side="left")
        
        self.btn_toggle_pass = ctk.CTkButton(pass_frame, text="👁️", width=45, height=35, corner_radius=self.entry_corner_radius,
                                             command=self.toggle_password_visibility,
                                             fg_color="#444444", hover_color="#555555", text_color="#fff")
        self.btn_toggle_pass.pack(side="left", padx=(5, 0))

        btn_save = ctk.CTkButton(form_frame, text="Save Account", command=self.save_new_account, 
                                 height=40, corner_radius=self.btn_corner_radius, font=ctk.CTkFont(weight="bold"),
                                 fg_color=self.colors["success"], hover_color="#2ecc71")
        btn_save.grid(row=3, column=1, padx=pad_x, pady=(10, 30), sticky="e")

    def toggle_password_visibility(self):
        if self.entry_pass.cget("show") == "*":
            self.entry_pass.configure(show="")
            self.btn_toggle_pass.configure(text="🙈")
        else:
            self.entry_pass.configure(show="*")
            self.btn_toggle_pass.configure(text="👁️")

    def save_new_account(self):
        s = self.entry_service.get()
        l = self.entry_login.get()
        p = self.entry_pass.get()
        if s and p:
            self.vault.append({"service": s, "login": l, "password": p})
            save_vault(self.vault, self.fernet)
            self.show_toast("Account saved!", type="success")
            self.show_list_view()
        else:
            self.show_toast("Service and Password required!", type="error")

# --- ЭКРАН ВХОДА ---
class LoginApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PassHere Login")
        self.geometry("450x400")
        self.resizable(False, False)
        
        ctk.set_appearance_mode("Dark")
        
        main_frame = ctk.CTkFrame(self, corner_radius=20, fg_color="#2b2b2b")
        main_frame.pack(expand=True, fill="both", padx=40, pady=40)
        
        ctk.CTkLabel(main_frame, text="Welcome Back", font=ctk.CTkFont(size=24, weight="bold"), text_color="#ecf0f1").pack(pady=(30, 10))
        ctk.CTkLabel(main_frame, text="Enter your Master Password", text_color="#bdc3c7", font=ctk.CTkFont(size=14)).pack(pady=(0, 25))
        
        login_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        login_frame.pack(pady=10)

        self.entry_pass = ctk.CTkEntry(login_frame, show="*", width=220, height=45, corner_radius=12, font=ctk.CTkFont(size=15),
                                       fg_color="#222222", border_color="#444444", text_color="#ecf0f1")
        self.entry_pass.pack(side="left", padx=(20, 5))
        
        btn_toggle = ctk.CTkButton(login_frame, text="👁️", width=55, height=45, corner_radius=12, font=ctk.CTkFont(size=18),
                                   command=lambda: toggle_visibility(self.entry_pass, btn_toggle),
                                   fg_color="#444444", hover_color="#555555")
        btn_toggle.pack(side="left", padx=(0, 20))

        self.lbl_error = ctk.CTkLabel(main_frame, text="", text_color="#e74c3c", font=ctk.CTkFont(size=12))
        self.lbl_error.pack(pady=(5, 0))

        btn_unlock = ctk.CTkButton(
            main_frame, 
            text="UNLOCK VAULT",       
            command=self.attempt_login, 
            height=70,
            corner_radius=12, 
            font=ctk.CTkFont(size=20, weight="bold"),
            fg_color="#2980b9", 
            hover_color="#3498db"
        )
        btn_unlock.pack(pady=(20, 30), padx=40, fill="x") 
    
    def attempt_login(self):
        pwd = self.entry_pass.get()
        try:
            fernet, _ = get_fernet_instance(pwd)
            if not os.path.exists(DATA_FILE) or load_vault(fernet) is not None:
                self.destroy()
                # Запускаем главное приложение
                app = PassHereApp(fernet)
                app.mainloop()
            else:
                self.lbl_error.configure(text="Wrong password!")
        except Exception as e:
            # Ловим любую ошибку и показываем её текстом, чтобы не было краша
            self.lbl_error.configure(text="Error: Invalid credentials")
            print(f"Login error: {e}") # Для отладки в консоль

if __name__ == "__main__":
    try:
        app = LoginApp()
        app.mainloop()
    except Exception as e:
        print(f"Critical startup error: {e}")
        sys.exit(1)