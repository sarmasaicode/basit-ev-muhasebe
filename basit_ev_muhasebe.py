from __future__ import annotations

import hashlib
import hmac
import html
import calendar
import base64
import ctypes
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import urllib.parse
import webbrowser
import zipfile
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

APP_VERSION = "2.0.0-portable-clean-secure"
DATA_SCHEMA = 1
PBKDF2_ROUNDS = 310_000

# When packaged as an EXE, keep all files beside the EXE (for USB portability).
APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "veriler"
IMAGE_DIR = APP_DIR / "gorseller"
ACCOUNT_FILE = DATA_DIR / "kullanici.json"
BOOKS_FILE = DATA_DIR / "muhasebe_verileri.json"
SETTINGS_FILE = DATA_DIR / "ayarlar.json"


ACTIVE_DATA_KEY: bytes | None = None
ENCRYPTED_DATA_FILES = {"muhasebe_verileri.json", "ayarlar.json"}
DATA_FILE_AAD_PREFIX = b"muhasebe-data-file-v1:"


def atomic_json_write(path: Path, value: dict) -> None:
    """Atomically save account metadata plainly and encrypt accounting/settings JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    plain = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    if path.name in ENCRYPTED_DATA_FILES:
        if ACTIVE_DATA_KEY is None:
            raise RuntimeError("Kayıtları şifrelemek için önce program şifresiyle giriş yap.")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(ACTIVE_DATA_KEY).encrypt(
            nonce, plain, DATA_FILE_AAD_PREFIX + path.name.encode("utf-8"))
        plain = json.dumps({
            "_encrypted": "AES-256-GCM-v1",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }, indent=2).encode("utf-8")
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(plain)
    os.replace(temp, path)


def decode_json_bytes(payload: bytes, filename: str, data_key: bytes | None = None) -> dict:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Veri dosyası bozuk veya okunamıyor.") from exc
    if not isinstance(value, dict):
        raise ValueError("Veri dosyasının biçimi geçersiz.")
    if value.get("_encrypted") != "AES-256-GCM-v1":
        return value
    key = data_key if data_key is not None else ACTIVE_DATA_KEY
    if key is None:
        raise ValueError("Şifreli kayıtları açmak için geçerli bir kurtarma anahtarı gerekiyor.")
    try:
        nonce = base64.b64decode(value["nonce"], validate=True)
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        clear = AESGCM(key).decrypt(nonce, ciphertext, DATA_FILE_AAD_PREFIX + filename.encode("utf-8"))
        result = json.loads(clear.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Veri içeriğinin biçimi geçersiz.")
        return result
    except (KeyError, ValueError, InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Şifreli kayıt açılamadı. Şifre veya kurtarma kodu yanlış olabilir.") from exc


def read_json_file(path: Path, data_key: bytes | None = None) -> dict:
    return decode_json_bytes(path.read_bytes(), path.name, data_key)


def is_encrypted_json(payload: bytes) -> bool:
    try:
        return json.loads(payload.decode("utf-8")).get("_encrypted") == "AES-256-GCM-v1"
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return False


def empty_store() -> dict:
    return {
        "schema_version": DATA_SCHEMA,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "transactions": [],
        "categories": ["Bağış", "Aidat", "Kira", "Elektrik", "Su", "Maaş", "Diğer"],
        "donors": [], "fixed_donors": [], "people": [], "important_contacts": [],
    }


def derive_wrapping_key(secret: str, salt: bytes, rounds: int = PBKDF2_ROUNDS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, rounds, dklen=32)


def wrap_data_key(data_key: bytes, secret: str, purpose: str) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    context = f"muhasebe-data-key-v1:{purpose}".encode("ascii")
    encrypted = AESGCM(derive_wrapping_key(secret, salt)).encrypt(nonce, data_key, context)
    return {
        "salt": salt.hex(), "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted).decode("ascii"), "rounds": PBKDF2_ROUNDS,
    }


def unwrap_data_key(wrapper: dict, secret: str, purpose: str) -> bytes:
    try:
        key = derive_wrapping_key(secret, bytes.fromhex(wrapper["salt"]), int(wrapper["rounds"]))
        nonce = base64.b64decode(wrapper["nonce"], validate=True)
        ciphertext = base64.b64decode(wrapper["ciphertext"], validate=True)
        result = AESGCM(key).decrypt(
            nonce, ciphertext, f"muhasebe-data-key-v1:{purpose}".encode("ascii"))
        if len(result) != 32:
            raise ValueError("Anahtar uzunluğu geçersiz.")
        return result
    except (KeyError, ValueError, InvalidTag) as exc:
        raise ValueError("Anahtar doğrulanamadı.") from exc


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[^0-9A-F]", "", code.upper())


def make_recovery_credentials(data_key: bytes) -> tuple[str, dict]:
    raw = secrets.token_hex(16).upper()
    code = "-".join(raw[index:index+4] for index in range(0, len(raw), 4))
    normalized = normalize_recovery_code(code)
    credential = password_record(normalized)
    credential["data_key_wrap"] = wrap_data_key(data_key, normalized, "recovery")
    return code, credential


def unlock_with_recovery(account: dict, code: str) -> bytes:
    normalized = normalize_recovery_code(code)
    recovery = account.get("recovery", {})
    if len(normalized) != 32 or not password_matches(normalized, recovery):
        raise ValueError("Kurtarma kodu hatalı.")
    return unwrap_data_key(recovery["data_key_wrap"], normalized, "recovery")


def copy_text_to_windows_clipboard(value: str) -> None:
    """Write Unicode text directly to the Windows clipboard and report failure."""
    if os.name != "nt":
        raise OSError("Windows panosu bu işletim sisteminde kullanılamıyor.")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_bool
    user32.EmptyClipboard.restype = ctypes.c_bool
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.CloseClipboard.restype = ctypes.c_bool
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    for attempt in range(6):
        if user32.OpenClipboard(None):
            break
        if attempt == 5:
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.05)

    handle = None
    try:
        if not user32.EmptyClipboard():
            raise ctypes.WinError(ctypes.get_last_error())
        payload = (value + "\0").encode("utf-16-le")
        handle = kernel32.GlobalAlloc(0x0002, len(payload))  # GMEM_MOVEABLE
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            raise ctypes.WinError(ctypes.get_last_error())
        ctypes.memmove(pointer, payload, len(payload))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(13, handle):  # CF_UNICODETEXT
            raise ctypes.WinError(ctypes.get_last_error())
        handle = None  # Windows owns the memory after SetClipboardData succeeds.
    finally:
        if handle:
            kernel32.GlobalFree(handle)
        user32.CloseClipboard()


def password_record(password: str, salt: bytes | None = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return {"salt": salt.hex(), "hash": digest.hex(), "rounds": PBKDF2_ROUNDS}


def password_matches(password: str, record: dict) -> bool:
    try:
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(record["salt"]), int(record["rounds"])
        ).hex()
        return hmac.compare_digest(digest, record["hash"])
    except (KeyError, ValueError, TypeError):
        return False


def ensure_data_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not BOOKS_FILE.exists():
        atomic_json_write(BOOKS_FILE, empty_store())
        return
    data = read_json_file(BOOKS_FILE)
    schema = int(data.get("schema_version", 0))
    if schema > DATA_SCHEMA:
        raise RuntimeError("Bu veri dosyası daha yeni bir program sürümüne ait. Dosyayı açmadım.")
    if schema < DATA_SCHEMA:
        data["schema_version"] = DATA_SCHEMA
        data.setdefault("transactions", [])
    if not is_encrypted_json(BOOKS_FILE.read_bytes()) or schema < DATA_SCHEMA:
        atomic_json_write(BOOKS_FILE, data)


class AccountingDemo:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Basit Ev Muhasebe Programı")
        self.root.configure(bg="#ffffff")
        self.cover_photo = None
        self.store: dict = empty_store()
        self.settings: dict = {}
        self.data_key: bytes | None = None
        self.authenticated = False
        self._idle_after_id = None
        self.selected_email_person_ids: set[str] = set()
        self._settings_scroll_canvas = None
        if ACCOUNT_FILE.exists():
            try:
                account_meta = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
                self.settings["cover_image"] = str(account_meta.get("cover_image", ""))
            except (OSError, json.JSONDecodeError):
                pass
        self.root.bind_all("<Any-KeyPress>", self._on_user_activity, add="+")
        self.root.bind_all("<Any-ButtonPress>", self._on_user_activity, add="+")
        self.root.bind_all("<MouseWheel>", self._scroll_settings_with_wheel, add="+")
        self.show_login()

    def _load_user_data(self) -> None:
        global ACTIVE_DATA_KEY
        if self.data_key is None:
            raise RuntimeError("Giriş anahtarı bulunamadı; kayıtlar açılmadı.")
        ACTIVE_DATA_KEY = self.data_key
        ensure_data_file()
        self.store = read_json_file(BOOKS_FILE, self.data_key)
        self.store.setdefault("categories", ["Bağış", "Aidat", "Kira", "Elektrik", "Su", "Maaş", "Diğer"])
        self.store.setdefault("donors", [])
        self.store.setdefault("fixed_donors", [])
        self.store.setdefault("people", [])
        self.store.setdefault("important_contacts", [])
        self.selected_email_person_ids = set()
        if SETTINGS_FILE.exists():
            settings_bytes = SETTINGS_FILE.read_bytes()
            saved_settings = decode_json_bytes(settings_bytes, SETTINGS_FILE.name, self.data_key)
            if isinstance(saved_settings, dict):
                self.settings.update(saved_settings)
            if not is_encrypted_json(settings_bytes):
                atomic_json_write(SETTINGS_FILE, self.settings)
        else:
            self.settings = {"cover_image": str(self.settings.get("cover_image", ""))}
            atomic_json_write(SETTINGS_FILE, self.settings)
        self.prepare_people_pool()

    def _on_user_activity(self, _event=None) -> None:
        if self.authenticated:
            self._schedule_idle_lock()

    def _schedule_idle_lock(self) -> None:
        if not self.authenticated:
            return
        if self._idle_after_id is not None:
            try:
                self.root.after_cancel(self._idle_after_id)
            except tk.TclError:
                pass
        self._idle_after_id = self.root.after(5 * 60 * 1000, lambda: self.lock_app(idle=True))

    def lock_app(self, *, idle: bool = False) -> None:
        global ACTIVE_DATA_KEY
        if self._idle_after_id is not None:
            try:
                self.root.after_cancel(self._idle_after_id)
            except tk.TclError:
                pass
            self._idle_after_id = None
        self.authenticated = False
        for child in list(self.root.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except tk.TclError:
                    pass
        self.data_key = None
        ACTIVE_DATA_KEY = None
        self.store = empty_store()
        cover_image = ""
        if ACCOUNT_FILE.exists():
            try:
                cover_image = str(json.loads(ACCOUNT_FILE.read_text(encoding="utf-8")).get("cover_image", ""))
            except (OSError, json.JSONDecodeError):
                pass
        self.settings = {"cover_image": cover_image}
        self.selected_email_person_ids.clear()
        self.show_login()
        if idle:
            messagebox.showinfo("Oturum kilitlendi", "Beş dakika işlem yapılmadığı için program kilitlendi.", parent=self.root)

    def prepare_people_pool(self) -> None:
        """Link existing donor records to a shared contact pool without dropping legacy fields."""
        people = self.store.setdefault("people", [])
        by_id = {str(person.get("id")): person for person in people if person.get("id")}

        def normalized(value) -> str:
            return " ".join(str(value or "").casefold().split())

        def identity_key(record: dict) -> tuple[str, ...] | None:
            name = normalized(record.get("name"))
            email = normalized(record.get("email"))
            phone = normalized(record.get("phone"))
            address = normalized(record.get("address"))
            if not name:
                return None
            if email:
                return ("email", email)
            if phone:
                return ("phone", phone)
            if address:
                return ("name-address", name, address)
            return None

        by_identity = {}
        for person in people:
            key = identity_key(person)
            if key:
                by_identity.setdefault(key, person)

        changed = "people" not in read_json_file(BOOKS_FILE, self.data_key)
        for collection_name in ("donors", "fixed_donors"):
            for donor in self.store.get(collection_name, []):
                person_id = str(donor.get("person_id", ""))
                person = by_id.get(person_id) if person_id else None
                key = identity_key(donor)
                if person is None and key:
                    person = by_identity.get(key)
                if person is None:
                    person = {field: donor.get(field, "") for field in ("name", "address", "phone", "email")}
                    person["id"] = person_id or uuid.uuid4().hex
                    person["created_at"] = donor.get("created_at", datetime.now().isoformat(timespec="seconds"))
                    people.append(person)
                    by_id[str(person["id"])] = person
                    if key:
                        by_identity[key] = person
                    person_id = str(person["id"])
                    changed = True
                else:
                    person_id = str(person.get("id", person_id or uuid.uuid4().hex))
                    if not person.get("id"):
                        person["id"] = person_id
                        by_id[person_id] = person
                        changed = True
                    for field in ("name", "address", "phone", "email"):
                        if not person.get(field) and donor.get(field):
                            person[field] = donor[field]
                            changed = True
                if donor.get("person_id") != person_id:
                    donor["person_id"] = person_id
                    changed = True

        if changed:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            migration_backup = DATA_DIR / f"muhasebe_verileri-kisi-havuzu-oncesi-{stamp}.json"
            if BOOKS_FILE.exists():
                migration_backup.write_bytes(BOOKS_FILE.read_bytes())
            atomic_json_write(BOOKS_FILE, self.store)

    def make_cover(self) -> tk.Canvas:
        self.cover_photo = None
        cover_name = Path(str(self.settings.get("cover_image", ""))).name
        cover_path = IMAGE_DIR / cover_name if cover_name else None
        if cover_path and cover_path.is_file():
            try:
                with Image.open(cover_path) as source:
                    self.cover_photo = ImageTk.PhotoImage(source.convert("RGB"))
            except (OSError, tk.TclError):
                self.cover_photo = None
        self.root.state("zoomed")
        self.root.resizable(True, True)
        self.root.update_idletasks()
        width, height = self.root.winfo_width(), self.root.winfo_height()
        canvas = tk.Canvas(self.root, highlightthickness=0, bg="#17233d")
        canvas.pack(fill="both", expand=True)
        if self.cover_photo:
            self.cover_image_id = canvas.create_image(width // 2, height // 2, image=self.cover_photo, anchor="center")
            def reposition(event):
                canvas.coords(self.cover_image_id, event.width // 2, event.height // 2)
            canvas.bind("<Configure>", reposition)
        return canvas

    def show_login(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()
        canvas = self.make_cover()
        card = ttk.Frame(canvas, padding=(24, 20), style="Login.TFrame")
        style = ttk.Style()
        style.configure("Login.TFrame", background="#ffffff")
        style.configure("LoginOrg.TLabel", background="#ffffff", foreground="#17233d", font=("Segoe UI", 20, "bold"))
        style.configure("LoginTitle.TLabel", background="#ffffff", foreground="#17233d", font=("Segoe UI", 16, "bold"))
        style.configure("LoginText.TLabel", background="#ffffff", foreground="#596579", font=("Segoe UI", 9))
        style.configure("Login.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 8))

        def add_login_entry(show_char: str = "") -> tk.Entry:
            frame = tk.Canvas(card, width=320, height=50, bg="#ffffff", highlightthickness=0, bd=0)
            frame.pack(fill="x", pady=(3, 9))
            outline = frame.create_polygon(0, 0, 0, 0, 0, 0, fill="#f5f9ff", outline="#496a8d",
                                           width=2, smooth=True, splinesteps=24)
            entry = tk.Entry(frame, font=("Segoe UI", 12), fg="#102b46", insertbackground="#0b67ad",
                             bg="#f5f9ff", bd=0, relief="flat", highlightthickness=0,
                             show=show_char, selectbackground="#b9dcff", selectforeground="#102944")
            item = frame.create_window(18, 25, window=entry, anchor="w", height=34, width=280)

            def redraw(_event=None, focused=False):
                width = max(frame.winfo_width(), 320)
                height = 48
                radius = 14
                points = (radius, 2, width-radius, 2, width-2, 2, width-2, radius,
                          width-2, height-radius, width-2, height-2, width-radius, height-2,
                          radius, height-2, 2, height-2, 2, height-radius, 2, radius, 2, 2)
                frame.coords(outline, *points)
                frame.itemconfigure(outline, fill="#ffffff" if focused else "#f5f9ff",
                                    outline="#087fce" if focused else "#496a8d", width=2)
                frame.coords(item, 17, height // 2)
                frame.itemconfigure(item, width=max(100, width-36))

            entry.bind("<FocusIn>", lambda _event: redraw(focused=True), add="+")
            entry.bind("<FocusOut>", lambda _event: redraw(focused=False), add="+")
            frame.bind("<Configure>", redraw, add="+")
            frame.after_idle(lambda: redraw(focused=False))
            return entry

        is_setup = not ACCOUNT_FILE.exists()
        title = "İlk Kullanım" if is_setup else "Güvenli Giriş"
        ttk.Label(card, text="Basit Ev Muhasebe Programı", style="LoginOrg.TLabel").pack(anchor="center", pady=(0, 14))
        ttk.Label(card, text=title, style="LoginTitle.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(card, text="Güvenli kayıt yönetimi", style="LoginText.TLabel").pack(anchor="w", pady=(0, 12))
        ttk.Label(card, text="Kullanıcı adı", style="LoginText.TLabel").pack(anchor="w")
        self.username_entry = add_login_entry()
        ttk.Label(card, text="Şifre", style="LoginText.TLabel").pack(anchor="w")
        self.password_entry = add_login_entry(show_char="•")
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card, text="Şifreyi göster", variable=self.show_password_var, command=self.toggle_password).pack(anchor="w", pady=(0, 6))
        if is_setup:
            ttk.Label(card, text="Şifreyi tekrar gir", style="LoginText.TLabel").pack(anchor="w")
            self.confirm_entry = add_login_entry(show_char="•")
            action = self.create_account
            button_text = "Hesap oluştur"
        else:
            self.confirm_entry = None
            action = self.login
            button_text = "Giriş yap"
        tk.Button(card, text=button_text, command=action, bg="#dff3ff", fg="#174a72",
                  activebackground="#c4e8fa", activeforeground="#174a72", relief="raised", bd=2,
                  padx=12, pady=8, font=("Segoe UI", 10, "bold"), cursor="hand2").pack(fill="x", pady=(5, 4))
        if not is_setup:
            self.ice_button(card, "Şifremi unuttum?", self.forgot_password,
                            bg="#f3f8ff", fg="#174a72", padx=12, pady=6).pack(anchor="center", pady=(7, 0))
        ttk.Label(card, text="Şifreli kayıtlar bu program klasöründe saklanır.", style="LoginText.TLabel", wraplength=300).pack(anchor="w", pady=(7, 0))
        card_window = canvas.create_window(0, 0, window=card, anchor="center")
        canvas.bind("<Configure>", lambda event: canvas.coords(card_window, event.width // 2, event.height // 2), add="+")
        self.username_entry.focus_set()
        self.root.bind("<Return>", lambda _event: action())
        self.enhance_controls(self.root)

    def toggle_password(self) -> None:
        show_char = "" if self.show_password_var.get() else "•"
        self.password_entry.configure(show=show_char)
        if self.confirm_entry is not None:
            self.confirm_entry.configure(show=show_char)

    def show_recovery_code(self, code: str, title: str = "Kurtarma kodun") -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.configure(bg="white", padx=22, pady=18)
        tk.Label(dialog, text="Bu kod bu pencerede yalnızca şimdi gösteriliyor.", bg="white",
                 fg="#17233d", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        tk.Label(dialog, text="Kodu güvenli bir yere yaz veya kopyala. Şifre unutulursa yeni şifre belirlemek için gerekir.",
                 bg="white", fg="#52627a", wraplength=470, justify="left").pack(anchor="w", pady=(7, 12))
        code_entry = ttk.Entry(dialog, width=44, font=("Consolas", 15, "bold"), justify="center")
        code_entry.insert(0, code)
        code_entry.configure(state="readonly")
        code_entry.pack(fill="x", pady=(0, 12))
        buttons = tk.Frame(dialog, bg="white")
        buttons.pack(fill="x")
        def copy_code() -> None:
            try:
                copy_text_to_windows_clipboard(code)
                messagebox.showinfo("Kopyalandı", "Kurtarma kodu panoya kopyalandı.", parent=dialog)
            except OSError as exc:
                messagebox.showerror("Kopyalanamadı", str(exc), parent=dialog)
        self.ice_button(buttons, "Kodu kopyala", copy_code).pack(side="left")
        self.ice_button(buttons, "Kodu sakladım", dialog.destroy).pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        dialog.grab_set()
        code_entry.selection_range(0, "end")
        dialog.wait_window()

    def create_account(self) -> None:
        global ACTIVE_DATA_KEY
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get() if self.confirm_entry else ""
        if not username:
            messagebox.showwarning("Eksik bilgi", "Bir kullanıcı adı yaz.", parent=self.root)
            return
        if len(password) < 8:
            messagebox.showwarning("Şifre kısa", "En az 8 karakterli bir şifre belirle.", parent=self.root)
            return
        if password != confirm:
            messagebox.showwarning("Şifre eşleşmiyor", "İki şifre alanı aynı değil.", parent=self.root)
            return
        previous = {path: path.read_bytes() if path.exists() else None
                    for path in (ACCOUNT_FILE, BOOKS_FILE, SETTINGS_FILE)}
        data_key = AESGCM.generate_key(bit_length=256)
        recovery_code, recovery = make_recovery_credentials(data_key)
        credentials = password_record(password)
        account = {
            "username": username, **credentials,
            "data_key_wrap": wrap_data_key(data_key, password, "password"),
            "recovery": recovery,
            "cover_image": str(self.settings.get("cover_image", "")),
        }
        self.data_key = data_key
        ACTIVE_DATA_KEY = data_key
        self.store = empty_store()
        self.settings = {"cover_image": account["cover_image"]}
        try:
            atomic_json_write(ACCOUNT_FILE, account)
            atomic_json_write(BOOKS_FILE, self.store)
            atomic_json_write(SETTINGS_FILE, self.settings)
        except (OSError, RuntimeError) as exc:
            for path, content in previous.items():
                try:
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_bytes(content)
                except OSError:
                    pass
            self.data_key = None
            ACTIVE_DATA_KEY = None
            messagebox.showerror("Hesap oluşturulamadı", f"Hiçbir mevcut kayıt değiştirilmedi.\n{exc}", parent=self.root)
            return
        self.show_recovery_code(recovery_code, "İlk kurulum — kurtarma kodu")
        messagebox.showinfo("Hesap oluşturuldu", "Kurtarma kodunu sakla. Şimdi kullanıcı adı ve yeni şifrenle giriş yap.", parent=self.root)
        self.data_key = None
        ACTIVE_DATA_KEY = None
        self.show_login()

    def login(self) -> None:
        global ACTIVE_DATA_KEY
        try:
            record = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            messagebox.showerror("Giriş", "Kullanıcı dosyası okunamadı.", parent=self.root)
            return
        username_ok = self.username_entry.get().strip().casefold() == str(record.get("username", "")).casefold()
        password = self.password_entry.get()
        if not username_ok or not password_matches(password, record):
            messagebox.showerror("Giriş başarısız", "Kullanıcı adı veya şifre hatalı.", parent=self.root)
            self.password_entry.delete(0, "end")
            return
        try:
            data_key = unwrap_data_key(record["data_key_wrap"], password, "password")
            self.data_key = data_key
            ACTIVE_DATA_KEY = data_key
            self._load_user_data()
        except (KeyError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            self.data_key = None
            ACTIVE_DATA_KEY = None
            messagebox.showerror("Giriş yapılamadı", f"Şifreli kayıtlar açılamadı; dosyalara dokunulmadı.\n{exc}", parent=self.root)
            return
        self.authenticated = True
        self.root.unbind("<Return>")
        self.show_dashboard(record.get("username", ""))
        self._schedule_idle_lock()

    def forgot_password(self) -> None:
        global ACTIVE_DATA_KEY
        try:
            account = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            messagebox.showerror("Şifremi unuttum", "Hesap dosyası okunamadı.", parent=self.root)
            return
        code = simpledialog.askstring("Kurtarma kodu", "İlk kurulumda sakladığın kurtarma kodunu gir.", parent=self.root)
        if code is None:
            return
        try:
            data_key = unlock_with_recovery(account, code)
        except (KeyError, ValueError):
            messagebox.showerror("Kod hatalı", "Kurtarma kodu doğru değil. Kayıtlar değiştirilmedi.", parent=self.root)
            return
        new_password = simpledialog.askstring("Yeni şifre", "Yeni şifreni yaz (en az 8 karakter).", show="•", parent=self.root)
        if new_password is None:
            return
        confirmation = simpledialog.askstring("Yeni şifre", "Yeni şifreni tekrar yaz.", show="•", parent=self.root)
        if confirmation is None:
            return
        if len(new_password) < 8:
            messagebox.showwarning("Şifre kısa", "En az 8 karakterli bir şifre belirle.", parent=self.root)
            return
        if new_password != confirmation:
            messagebox.showwarning("Şifre eşleşmiyor", "İki yeni şifre aynı değil.", parent=self.root)
            return
        try:
            credentials = password_record(new_password)
            account.update(credentials)
            account["data_key_wrap"] = wrap_data_key(data_key, new_password, "password")
            new_code, account["recovery"] = make_recovery_credentials(data_key)
            atomic_json_write(ACCOUNT_FILE, account)
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("Şifre güncellenemedi", str(exc), parent=self.root)
            return
        self.settings = {"cover_image": str(account.get("cover_image", ""))}
        self.show_recovery_code(new_code, "Şifre yenilendi — yeni kurtarma kodu")
        messagebox.showinfo("Şifre yenilendi", "Eski kurtarma kodu artık geçersiz. Yeni kodu sakla; sonra yeni şifrenle giriş yap.", parent=self.root)
        self.data_key = None
        ACTIVE_DATA_KEY = None
        self.show_login()

    def confirm_account_password(self, action: str) -> bool:
        try:
            record = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            messagebox.showerror("Şifre doğrulama", "Kullanıcı bilgileri okunamadı.", parent=self.root)
            return False
        password = simpledialog.askstring("Şifre doğrulama", f"{action} için program şifreni gir.",
                                          show="•", parent=self.root)
        if password is None:
            return False
        if not password_matches(password, record):
            messagebox.showerror("Şifre hatalı", "Program şifresi doğru değil; işlem yapılmadı.", parent=self.root)
            return False
        return True

    def show_dashboard(self, username: str) -> None:
        self.current_username = username
        if not hasattr(self, "active_page"):
            self.active_page = "Genel Bakış"
        for child in self.root.winfo_children():
            child.destroy()
        self.root.title("Basit Ev Muhasebe Programı")
        self.root.geometry("1584x1000")
        self.root.minsize(1200, 760)
        self.root.resizable(True, True)
        self.root.configure(bg="#f7f9fc")
        style = ttk.Style()
        style.configure("Treeview", font=("Segoe UI", 14), rowheight=38, background="white", fieldbackground="white", foreground="#14213d", borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", font=("Segoe UI", 14, "bold"), background="#e8edf5", foreground="#14213d", padding=10, borderwidth=0, relief="flat")
        style.configure("TEntry", font=("Segoe UI", 12), padding=8)
        style.configure("TCombobox", font=("Segoe UI", 12), padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", "#ffffff"), ("focus", "#f0f7ff")],
                  bordercolor=[("focus", "#1680e8")])

        shell = tk.Frame(self.root, bg="#f7f9fc")
        shell.pack(fill="both", expand=True)
        side = tk.Frame(shell, bg="#073b7a", width=265)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="Gelir-Gider\nTakibi", bg="#073b7a", fg="white", font=("Segoe UI", 19, "bold")).pack(anchor="w", padx=26, pady=(26, 28))
        self.content = tk.Frame(shell, bg="#f7f9fc")
        self.content.pack(side="left", fill="both", expand=True, padx=20, pady=18)
        self.nav_buttons = {}
        for label in ("Genel Bakış", "Kategoriler", "Raporlar", "Sabit Bağışçılar", "Bağışçılar", "Kişilerim", "Önemli Kişiler", "Ayarlar"):
            nav_button = tk.Canvas(side, height=46, bg="#073b7a", highlightthickness=0, bd=0,
                                  cursor="hand2", takefocus=1)
            nav_button._nav_name = label
            nav_button._nav_hovered = False
            nav_button.pack(fill="x", padx=11, pady=4)
            nav_button.bind("<Configure>", lambda _event, name=label: self._draw_navigation_button(name), add="+")
            nav_button.bind("<Enter>", lambda _event, name=label: self._navigation_hover(name, True), add="+")
            nav_button.bind("<Leave>", lambda _event, name=label: self._navigation_hover(name, False), add="+")
            nav_button.bind("<Button-1>", lambda _event, name=label: self.show_page(name), add="+")
            nav_button.bind("<Return>", lambda _event, name=label: self.show_page(name), add="+")
            self.nav_buttons[label] = nav_button

        head = tk.Frame(self.content, bg="#f7f9fc")
        head.pack(fill="x", pady=(2, 15))
        tk.Label(head, text="Basit Ev Muhasebe Programı", bg="#f7f9fc", fg="#092554", font=("Segoe UI", 22, "bold")).place(relx=0.5, rely=0.5, anchor="center")
        actions = tk.Frame(head, bg="#f7f9fc")
        actions.pack(side="right")
        tk.Button(actions, text="＋ Yeni Gelir", command=lambda: self.open_transaction_form("Gelir"), bg="#08a94e", fg="white", activebackground="#078d41", relief="flat", padx=18, pady=11, font=("Segoe UI", 13, "bold")).pack(side="left", padx=5)
        tk.Button(actions, text="＋ Yeni Gider", command=lambda: self.open_transaction_form("Gider"), bg="#f04444", fg="white", activebackground="#d93434", relief="flat", padx=18, pady=11, font=("Segoe UI", 13, "bold")).pack(side="left", padx=5)
        tk.Button(actions, text="▣ PDF Yazdır", command=self.export_table_pdf, bg="white", fg="#17325b", relief="solid", bd=1, padx=18, pady=10, font=("Segoe UI", 13, "bold")).pack(side="left", padx=5)
        tk.Button(actions, text="Kilitle", command=self.lock_app, bg="white", fg="#17325b", relief="solid", bd=1, padx=12, pady=10, font=("Segoe UI", 12)).pack(side="left", padx=5)

        cards = tk.Frame(self.content, bg="#f7f9fc")
        cards.pack(fill="x", pady=(0, 17))
        self.summary_vars = {}
        for title, icon, accent, pale in (("Toplam Gelir", "💰", "#07883d", "#e7f7ee"), ("Toplam Gider", "🧾", "#e33434", "#fff0f0"), ("Bakiye", "📊", "#154384", "#e8f3ff")):
            card = tk.Frame(cards, bg=pale, highlightbackground="#d7e1ee", highlightthickness=1, padx=21, pady=15)
            card.pack(side="left", fill="x", expand=True, padx=(0, 14))
            tk.Label(card, text=f"{icon}  {title}", bg=pale, fg="#14213d", font=("Segoe UI", 15, "bold")).pack(anchor="center")
            var = tk.StringVar(value="€ 0,00")
            self.summary_vars[title] = var
            tk.Label(card, textvariable=var, bg=pale, fg=accent, font=("Segoe UI", 24, "bold")).pack(anchor="center", pady=(4, 0))

        body = tk.Frame(self.content, bg="#f7f9fc")
        body.pack(fill="both", expand=True)
        ledger = tk.Frame(body, bg="white", highlightbackground="#d7e1ee", highlightthickness=1, padx=12, pady=12)
        ledger.pack(side="left", fill="both", expand=True, padx=(0, 12))
        panel = tk.Frame(body, bg="white", width=315, highlightbackground="#d7e1ee", highlightthickness=1, padx=14, pady=14)
        panel.pack(side="right", fill="y")
        panel.pack_propagate(False)
        tk.Label(ledger, text="İşlemleri Filtrele", bg="white", fg="#122a50", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 9))
        filters = tk.Frame(ledger, bg="white")
        filters.pack(fill="x", pady=(0, 12))
        tk.Label(filters, text="Başlangıç", bg="white", fg="#52627a").pack(side="left", padx=3)
        self.start_date_entry = ttk.Entry(filters, width=12)
        self.start_date_entry.insert(0, "")
        self.start_date_entry.pack(side="left", padx=(0, 6))
        self.date_picker_button(filters, self.start_date_entry).pack(side="left", padx=(0, 6))
        tk.Label(filters, text="Bitiş", bg="white", fg="#52627a").pack(side="left", padx=3)
        self.end_date_entry = ttk.Entry(filters, width=12)
        self.end_date_entry.pack(side="left", padx=6)
        self.date_picker_button(filters, self.end_date_entry).pack(side="left", padx=(0, 6))
        self.type_filter = ttk.Combobox(filters, values=("Tüm Türler", "Gelir", "Gider"), width=14, state="readonly")
        self.type_filter.set("Tüm Türler")
        self.type_filter.pack(side="left", padx=6)
        self.category_filter = ttk.Combobox(filters, values=("Tüm Kategoriler", *self.store.get("categories", [])), width=18, state="readonly")
        self.category_filter.set("Tüm Kategoriler")
        self.category_filter.pack(side="left", padx=6)
        self.search_entry = ttk.Entry(filters, width=16)
        self.search_entry.pack(side="left", padx=6)
        tk.Button(filters, text="⌕  Sorgula", command=self.refresh_transactions, bg="#e7f1ff", fg="#0b3d79", relief="raised", bd=2, padx=18, pady=9, font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        tk.Button(filters, text="↺  Temizle", command=self.clear_filters, bg="#f3f6fa", fg="#354b68", relief="raised", bd=2, padx=16, pady=9, font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        tk.Label(ledger, text="Son İşlemler", bg="white", fg="#122a50", font=("Segoe UI", 17, "bold")).pack(anchor="w", pady=(0, 9))
        table_wrap = tk.Canvas(ledger, bg="white", highlightthickness=0, bd=0)
        table_wrap.pack(fill="both", expand=True)
        table_panel = tk.Frame(table_wrap, bg="white", bd=0, highlightthickness=0)
        table_panel_window = table_wrap.create_window((3, 3), window=table_panel, anchor="nw")

        def draw_table_outline(event=None) -> None:
            width = max(1, table_wrap.winfo_width())
            height = max(1, table_wrap.winfo_height())
            table_wrap.coords(table_panel_window, 5, 5)
            table_wrap.itemconfigure(table_panel_window, width=max(1, width - 10), height=max(1, height - 10))
            table_wrap.delete("table_outline")
            radius = 13
            points = (2 + radius, 2, width - 2 - radius, 2,
                      width - 2, 2, width - 2, 2 + radius,
                      width - 2, height - 2 - radius, width - 2, height - 2,
                      width - 2 - radius, height - 2, 2 + radius, height - 2,
                      2, height - 2, 2, height - 2 - radius,
                      2, 2 + radius, 2, 2)
            table_wrap.create_polygon(points, smooth=True, splinesteps=18, fill="", outline="#cbd9e8",
                                      width=1, tags="table_outline")
            table_wrap.tag_lower("table_outline")

        table_wrap.bind("<Configure>", draw_table_outline, add="+")
        headings = tk.Frame(table_panel, bg="#e8edf5", height=42, bd=0, highlightthickness=0)
        headings.pack(fill="x")
        headings.pack_propagate(False)
        headings.pack(fill="x")
        column_specs = (("date", "Tarih", 0.15), ("description", "Açıklama", 0.34), ("category", "Kategori", 0.19), ("type", "Tür", 0.13), ("amount", "Tutar", 0.19))
        self.table_column_specs = column_specs
        for column, title, weight in column_specs:
            x = sum(spec[2] for spec in column_specs[:len(headings.winfo_children())])
            tk.Label(headings, text=title, bg="#e8edf5", fg="#14213d", font=("Segoe UI", 12, "bold"), anchor="w", padx=10, pady=10).place(relx=x, rely=0, relwidth=weight, relheight=1)
        self.table_canvas = tk.Canvas(table_panel, bg="white", highlightthickness=0, bd=0)
        self.table_canvas.pack(side="left", fill="both", expand=True)
        self.table_scrollbar = ttk.Scrollbar(table_panel, orient="vertical", command=self.scroll_table)
        self.table_scrollbar.pack(side="right", fill="y")
        self.table_canvas.configure(yscrollcommand=self.set_table_scrollbar)
        self.table_rows_frame = tk.Frame(self.table_canvas, bg="white", bd=0, highlightthickness=0)
        self.table_canvas_window = self.table_canvas.create_window((0, 0), window=self.table_rows_frame, anchor="nw")
        self.table_rows_frame.bind("<Configure>", self.on_table_rows_configure)
        self.table_canvas.bind("<Configure>", self.on_table_canvas_configure)
        self.table_canvas.bind("<MouseWheel>", self.on_table_mousewheel, add="+")
        self.table = None
        self.selected_row_index = None
        tk.Button(ledger, text="Düzenle seçili kaydı", command=self.edit_selected_transaction, bg="#edf3fb", fg="#17325b", relief="solid", bd=1, padx=12, pady=7).pack(anchor="e", pady=(8, 0))

        tk.Label(panel, text="Aylık Toplamlar", bg="white", fg="#122a50", font=("Segoe UI", 17, "bold")).pack(anchor="w", pady=(0, 13))
        self.month_summary_vars = {}
        for label, color, pale in (("Gelir", "#07883d", "#e7f7ee"), ("Gider", "#e33434", "#fff0f0"), ("Bakiye", "#154384", "#e8f3ff")):
            row = tk.Frame(panel, bg=pale, padx=11, pady=12)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=label, bg=pale, fg=color, font=("Segoe UI", 13, "bold")).pack(side="left")
            value = tk.StringVar(value="€ 0,00")
            self.month_summary_vars[label] = value
            tk.Label(row, textvariable=value, bg=pale, fg=color, font=("Segoe UI", 13, "bold")).pack(side="right")
        tk.Label(panel, text="Kategori Dağılımı (Gider)", bg="white", fg="#122a50", font=("Segoe UI", 15, "bold")).pack(anchor="w", pady=(18, 9))
        self.category_summary = tk.Frame(panel, bg="white")
        self.category_summary.pack(fill="x")
        badge = tk.Label(panel, text="♧  Veriler USB'de", bg="#f5faff", fg="#154384", font=("Segoe UI", 12, "bold"), padx=12, pady=10)
        badge.pack(side="bottom", anchor="e", pady=(12, 0))
        self.refresh_transactions()
        self.enhance_controls(self.root)

    def _navigation_hover(self, name: str, hovered: bool) -> None:
        button = getattr(self, "nav_buttons", {}).get(name)
        if button is None or not button.winfo_exists():
            return
        button._nav_hovered = hovered
        self._draw_navigation_button(name)

    def _draw_navigation_button(self, name: str) -> None:
        button = getattr(self, "nav_buttons", {}).get(name)
        if button is None or not button.winfo_exists():
            return
        width = max(button.winfo_width(), 200)
        height = max(button.winfo_height(), 46)
        active = name == self.active_page
        hovered = bool(getattr(button, "_nav_hovered", False))
        fill = "#1680e8" if active else ("#125394" if hovered else "#0b4786")
        edge = "#b9ddff" if active else ("#5c8fbe" if hovered else "#1b568f")
        button.delete("all")
        x1, y1, x2, y2, radius = 2, 2, width - 4, height - 5, 11

        def rounded_points(left, top, right, bottom, curve):
            return (left + curve, top, right - curve, top, right, top,
                    right, top + curve, right, bottom - curve, right, bottom,
                    right - curve, bottom, left + curve, bottom, left, bottom,
                    left, bottom - curve, left, top + curve, left, top)

        points = rounded_points(x1, y1, x2, y2, radius)
        shadow_points = tuple(value + (2 if i % 2 else 0) for i, value in enumerate(points))
        button.create_polygon(shadow_points, smooth=True, splinesteps=16, fill="#052d5e", outline="")
        button.create_polygon(points, smooth=True, splinesteps=16, fill=fill, outline=edge, width=1)
        if active:
            button.create_line(13, 12, 13, height - 15, fill="#d9edff", width=3, capstyle="round")
        button.create_text(26 if active else 20, height // 2 - 1, text=name, anchor="w",
                           fill="white", font=("Segoe UI", 13, "bold"), width=width - 44)

    def _update_navigation_state(self, active_page: str) -> None:
        self.active_page = active_page
        for name, button in getattr(self, "nav_buttons", {}).items():
            if not button.winfo_exists():
                continue
            self._draw_navigation_button(name)

    @staticmethod
    def euro(value: Decimal) -> str:
        return f"€ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

    def date_picker_button(self, parent: tk.Misc, entry: ttk.Entry) -> tk.Button:
        return tk.Button(parent, text="📅", command=lambda: self.show_date_picker(entry), bg="#e8f2ff", fg="#174a83",
                         relief="raised", bd=2, padx=7, pady=4, font=("Segoe UI Emoji", 11), cursor="hand2")

    def show_date_picker(self, entry: ttk.Entry) -> None:
        try:
            self.open_date_picker(entry)
        except tk.TclError as exc:
            messagebox.showerror("Takvim açılamadı", f"Takvim penceresi açılamadı.\n{exc}", parent=self.root)

    def open_date_picker(self, entry: ttk.Entry) -> None:
        try:
            current = datetime.strptime(entry.get().strip(), "%Y-%m-%d").date()
        except ValueError:
            current = datetime.now().date()
        popup = tk.Toplevel(self.root)
        popup.withdraw()
        popup.title("Tarih seç")
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.configure(bg="white")
        popup.geometry("320x330")
        month_year = [current.year, current.month]
        header = tk.Frame(popup, bg="white", padx=10, pady=10)
        header.pack(fill="x")
        days_frame = tk.Frame(popup, bg="white", padx=10, pady=4)
        days_frame.pack(fill="both", expand=True)
        month_label = tk.Label(header, bg="white", fg="#17325b", font=("Segoe UI", 12, "bold"))
        header.grid_columnconfigure(1, weight=1)
        tk.Button(header, text="‹", command=lambda: shift_month(-1), bg="#edf4fc", fg="#174a83", relief="raised", bd=1, width=3).grid(row=0, column=0, sticky="w")
        month_label.grid(row=0, column=1, sticky="ew", padx=8)
        tk.Button(header, text="›", command=lambda: shift_month(1), bg="#edf4fc", fg="#174a83", relief="raised", bd=1, width=3).grid(row=0, column=2, sticky="e")
        month_names = ("", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık")

        def select_day(day: int) -> None:
            entry.delete(0, "end")
            entry.insert(0, f"{month_year[0]:04d}-{month_year[1]:02d}-{day:02d}")
            popup.destroy()

        def shift_month(delta: int) -> None:
            year, month = month_year[0], month_year[1] + delta
            if month < 1:
                year, month = year - 1, 12
            elif month > 12:
                year, month = year + 1, 1
            month_year[:] = [year, month]
            redraw()

        def redraw() -> None:
            for child in days_frame.winfo_children():
                child.destroy()
            month_label.configure(text=f"{month_names[month_year[1]]} {month_year[0]}")
            for col in range(7):
                days_frame.grid_columnconfigure(col, weight=1, uniform="calendar-day")
            for col, day_name in enumerate(("Pzt", "Sal", "Çar", "Per", "Cum", "Cmt", "Paz")):
                tk.Label(days_frame, text=day_name, bg="white", fg="#66758a", font=("Segoe UI", 9, "bold"), width=4).grid(row=0, column=col, sticky="nsew", pady=(0, 5))
            for row, week in enumerate(calendar.monthcalendar(month_year[0], month_year[1]), start=1):
                days_frame.grid_rowconfigure(row, weight=1, uniform="calendar-week")
                for col, day in enumerate(week):
                    if day:
                        is_selected = (month_year[0], month_year[1], day) == (current.year, current.month, current.day)
                        tk.Button(days_frame, text=str(day), command=lambda value=day: select_day(value), bg="#dcecff" if is_selected else "#f4f8fd", fg="#172b49",
                                  activebackground="#b9d6f7", relief="raised", bd=1, width=4, pady=5, font=("Segoe UI", 10)).grid(row=row, column=col, sticky="nsew", padx=2, pady=2)

        redraw()
        popup.update_idletasks()
        popup_width, popup_height = 320, 330
        screen_width, screen_height = popup.winfo_screenwidth(), popup.winfo_screenheight()
        x = min(max(0, entry.winfo_rootx()), max(0, screen_width - popup_width))
        y = entry.winfo_rooty() + entry.winfo_height() + 4
        if y + popup_height > screen_height:
            y = max(0, entry.winfo_rooty() - popup_height - 4)
        popup.geometry(f"{popup_width}x{popup_height}+{x}+{y}")
        popup.bind("<Escape>", lambda _event: popup.destroy())
        popup.deiconify()
        popup.update_idletasks()
        popup.lift()
        popup.attributes("-topmost", True)
        popup.grab_set()
        popup.focus_force()
        def release_topmost() -> None:
            try:
                popup.attributes("-topmost", False)
            except tk.TclError:
                pass
        popup.after(250, release_topmost)
        self.enhance_controls(popup)

    def set_table_scrollbar(self, first: str, last: str) -> None:
        if hasattr(self, "table_scrollbar"):
            self.table_scrollbar.set(first, last)

    def on_table_rows_configure(self, _event=None) -> None:
        self.table_canvas.configure(scrollregion=self.table_canvas.bbox("all"))
        self.root.after_idle(self.update_table_scrollbar)

    def on_table_canvas_configure(self, event) -> None:
        self.table_canvas.itemconfigure(self.table_canvas_window, width=event.width)
        self.root.after_idle(self.update_table_scrollbar)

    def update_table_scrollbar(self) -> None:
        if not hasattr(self, "table_rows_frame") or not self.table_rows_frame.winfo_exists():
            return
        needed = self.table_rows_frame.winfo_reqheight()
        available = self.table_canvas.winfo_height()
        overflow = needed > available + 2
        self.table_has_overflow = overflow
        if overflow:
            if not self.table_scrollbar.winfo_ismapped():
                self.table_scrollbar.pack(side="right", fill="y")
        else:
            if self.table_scrollbar.winfo_ismapped():
                self.table_scrollbar.pack_forget()
            self.table_canvas.yview_moveto(0)
            self.table_scrollbar.set(0, 1)

    def scroll_table(self, *args) -> None:
        if hasattr(self, "table_canvas") and getattr(self, "table_has_overflow", False):
            self.table_canvas.yview(*args)

    def on_table_mousewheel(self, event):
        if not getattr(self, "table_has_overflow", False):
            return "break"
        self.scroll_table("scroll", int(-event.delta / 120), "units")
        return "break"

    def sync_table_selection(self, event) -> None:
        return None

    def select_table_row(self, index: int, edit: bool = False) -> None:
        self.selected_row_index = index
        for row_index, row in enumerate(self.table_rows_frame.winfo_children()):
            kind = getattr(row, "transaction_type", "")
            if kind == "Gelir":
                bg, selected = "#e6f6eb", "#ccebd5"
            else:
                bg, selected = "#fff0f0", "#f8d5d5"
            row.configure(bg=selected if row_index == index else bg)
            for cell in row.winfo_children():
                cell.configure(bg=row.cget("bg"))
        if edit:
            self.edit_selected_transaction()

    def enhance_controls(self, parent: tk.Misc) -> None:
        style = ttk.Style(self.root)
        style.configure("TButton", background="#dff3ff", foreground="#174a72",
                        padding=(12, 8), relief="raised")
        style.map("TButton", background=[("pressed", "#a9d9f2"), ("active", "#c4e8fa")],
                  foreground=[("disabled", "#91a4b4"), ("!disabled", "#174a72")])
        style.configure("Login.TButton", background="#dff3ff", foreground="#174a72",
                        padding=(12, 8), relief="raised")
        style.map("Login.TButton", background=[("pressed", "#a9d9f2"), ("active", "#c4e8fa")],
                  foreground=[("disabled", "#91a4b4"), ("!disabled", "#174a72")])
        neutral_button_colors = {
            "white", "#ffffff", "#fff", "#f0f0f0", "#f3f6fa", "#f4f8fd", "#edf3fb",
            "#eef3fb", "#edf4fc", "#e7f1ff", "#e8f2ff", "systembuttonface",
        }
        for widget in parent.winfo_children():
            if isinstance(widget, (tk.Button, ttk.Button)):
                widget.configure(cursor="hand2")
                stable_button = isinstance(widget, tk.Button) and getattr(widget, "_stable_button_style", False)
                if isinstance(widget, tk.Button) and not stable_button:
                    background = str(widget.cget("bg")).lower()
                    neutral_gray = False
                    try:
                        red, green, blue = widget.winfo_rgb(background)
                        neutral_gray = max(red, green, blue) - min(red, green, blue) < 7000 and min(red, green, blue) > 39000
                    except tk.TclError:
                        pass
                    if background in neutral_button_colors or neutral_gray:
                        widget.configure(bg="#dff3ff", fg="#174a72",
                                         activebackground="#c4e8fa", activeforeground="#174a72")
                    widget.configure(relief="raised", bd=1)
                if stable_button:
                    widget._hover_effect_bound = True
                elif not getattr(widget, "_hover_effect_bound", False):
                    widget._hover_effect_bound = True
                    widget._normal_bg = str(widget.cget("bg")) if isinstance(widget, tk.Button) else None
                    widget.bind("<Enter>", lambda event: self._button_hover(event.widget, True), add="+")
                    widget.bind("<Leave>", lambda event: self._button_hover(event.widget, False), add="+")
                    widget.bind("<ButtonPress-1>", lambda event: self._button_press(event.widget, True), add="+")
                    widget.bind("<ButtonRelease-1>", lambda event: self._button_press(event.widget, False), add="+")
            elif isinstance(widget, ttk.Combobox):
                widget.configure(cursor="hand2")
            self.enhance_controls(widget)

    @staticmethod
    def _button_hover(widget: tk.Misc, hovered: bool) -> None:
        try:
            if isinstance(widget, tk.Button):
                base = getattr(widget, "_normal_bg", str(widget.cget("bg")))
                active = str(widget.cget("activebackground"))
                # A single stable color change; no border animation or geometry changes.
                widget.configure(bg=active if hovered else base, relief="raised", bd=1,
                                 highlightthickness=0)
            else:
                widget.state(("active",) if hovered else ("!active",))
        except tk.TclError:
            pass

    @staticmethod
    def _button_press(widget: tk.Misc, pressed: bool) -> None:
        try:
            if isinstance(widget, tk.Button):
                # Keep the button's dimensions fixed while indicating a press.
                widget.configure(relief="sunken" if pressed else "raised", bd=1)
        except tk.TclError:
            pass

    def export_table_pdf(self) -> None:
        rows = getattr(self, "displayed_records", [])
        if not rows:
            messagebox.showinfo("PDF raporu", "PDF’ye aktarılacak işlem bulunamadı.")
            return
        self.create_pdf(rows, "Gelir-Gider İşlem Raporu")

    def create_pdf(self, records: list[dict], title: str, period_summary: list[dict] | None = None,
                   custom_table: dict | None = None) -> None:
        if not records and not (custom_table and custom_table.get("rows")):
            messagebox.showinfo("PDF raporu", "PDF’ye aktarılacak kayıt bulunamadı.")
            return
        income = sum((Decimal(str(r.get("amount", "0"))) for r in records if r.get("type") == "Gelir"), Decimal("0"))
        expense = sum((Decimal(str(r.get("amount", "0"))) for r in records if r.get("type") == "Gider"), Decimal("0"))
        def open_preview() -> None:
            try:
                saved_pdf = self._print_pdf_with_windows(records, title, period_summary or [], income, expense, custom_table)
                if saved_pdf:
                    try:
                        self.root.after(0, lambda: messagebox.showinfo("PDF kaydedildi", f"Rapor kaydedildi:\n{saved_pdf}"))
                    except tk.TclError:
                        pass
            except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                details = "Windows yazdırma işlemi tamamlanamadı. Yazıcı, yazdırma kuyruğu veya kaydetme penceresiyle ilgili ayrıntı:\n\n" + str(exc)
                try:
                    self.root.after(0, lambda: self.show_pdf_error(details))
                except tk.TclError:
                    pass
        threading.Thread(target=open_preview, name="report-print-preview", daemon=True).start()

    def _print_pdf_with_windows(self, records: list[dict], title: str, period_summary: list[dict],
                                income: Decimal, expense: Decimal, custom_table: dict | None = None) -> Path | None:
        printer = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if not Path(printer).is_file():
            raise RuntimeError("Windows PowerShell bulunamadı.")
        if SETTINGS_FILE.exists():
            try:
                saved_settings = read_json_file(SETTINGS_FILE, self.data_key)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"PDF klasör ayarı okunamadı: {exc}") from exc
            if isinstance(saved_settings, dict):
                self.settings.update(saved_settings)
        payload = {
            "title": title,
            "created": datetime.now().strftime("%d.%m.%Y %H:%M"),
            "pdf_directory": str(self.settings.get("pdf_directory", str(Path.home()))),
            "income": self.euro(income),
            "expense": self.euro(expense),
            "balance": self.euro(income-expense),
            "summary": [{"period": str(r["period"]), "income": self.euro(r["income"]),
                         "expense": self.euro(r["expense"]), "balance": self.euro(r["balance"])} for r in period_summary],
            "table_headers": (custom_table or {}).get("headers", ["Tarih", "Tür", "Kategori", "Açıklama", "Tutar"]),
            "table_widths": (custom_table or {}).get("widths", [0.15, 0.12, 0.18, 0.35, 0.20]),
            "table_kind": (custom_table or {}).get("kind", "transactions"),
            "show_totals": custom_table is None,
            "records": ([{"cells": [str(v) for v in row]} for row in custom_table["rows"]]
                        if custom_table else
                        [{"cells": [str(r.get("date", "")), str(r.get("type", "")), str(r.get("category", "")),
                                    str(r.get("description", "")), ("+" if r.get("type") == "Gelir" else "−") + " " + self.euro(Decimal(str(r.get("amount", "0"))))]}
                         for r in records]),
        }
        script = r'''param([string]$DataPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
$script:pdfData = Get-Content -LiteralPath $DataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$script:summaryIndex = 0
$script:recordIndex = 0
$doc = New-Object System.Drawing.Printing.PrintDocument
$doc.DefaultPageSettings.Landscape = $false
$a4Paper = $doc.PrinterSettings.PaperSizes | Where-Object { $_.Kind -eq [System.Drawing.Printing.PaperKind]::A4 } | Select-Object -First 1
if ($a4Paper) { $doc.DefaultPageSettings.PaperSize = $a4Paper }
$doc.DefaultPageSettings.Margins = New-Object System.Drawing.Printing.Margins(45,45,45,45)
$doc.DocumentName = [string]$script:pdfData.title
$initialPdfDirectory = [string]$script:pdfData.pdf_directory
if (Test-Path -LiteralPath $initialPdfDirectory -PathType Container) {
    $doc.PrinterSettings.PrintFileName = Join-Path $initialPdfDirectory ('gelir-gider-raporu-' + (Get-Date -Format 'yyyy-MM-dd-HHmmss') + '.pdf')
}
$doc.add_BeginPrint({ $script:summaryIndex = 0; $script:recordIndex = 0 })
$doc.add_PrintPage({
    param($sender,$e)
    $g = $e.Graphics
    $b = $e.MarginBounds
    $left = [float]$b.Left; $right = [float]$b.Right; $bottom = [float]$b.Bottom
    $titleFont = New-Object System.Drawing.Font('Arial',18,[System.Drawing.FontStyle]::Bold)
    $subFont = New-Object System.Drawing.Font('Arial',10)
    $headFont = New-Object System.Drawing.Font('Arial',9,[System.Drawing.FontStyle]::Bold)
    $bodyFont = New-Object System.Drawing.Font('Arial',9)
    $boldFont = New-Object System.Drawing.Font('Arial',9,[System.Drawing.FontStyle]::Bold)
    $black = [System.Drawing.Brushes]::Black
    $blue = [System.Drawing.Brushes]::DarkBlue
    $green = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(7,136,61))
    $red = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(201,39,50))
    $paleGreen = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(230,246,235))
    $paleRed = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255,240,240))
    $paleBlue = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(232,237,245))
    $line = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(205,216,229),0.6)
    $fmt = New-Object System.Drawing.StringFormat
    $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
    $fmt.Alignment = [System.Drawing.StringAlignment]::Near
    $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
    $g.DrawString('Basit Ev Muhasebe Programı',$titleFont,$blue,$left,($b.Top+2))
    $g.DrawString(([string]$script:pdfData.title + '  ·  ' + [string]$script:pdfData.created),$subFont,$black,$left,($b.Top+32))
    if ($script:pdfData.show_totals) {
        $g.DrawString(('Toplam gelir: ' + [string]$script:pdfData.income),$boldFont,$green,$left,($b.Top+56))
        $g.DrawString(('Toplam gider: ' + [string]$script:pdfData.expense),$boldFont,$red,($left+210),($b.Top+56))
        $g.DrawString(('Bakiye: ' + [string]$script:pdfData.balance),$boldFont,$blue,($left+420),($b.Top+56))
    }
    $y = [float]($b.Top+84)
    $rowHeight = [float]23
    $wPeriod = [float]110; $wType = [float]68; $wCategory = [float]125; $wAmount = [float]125
    $wDescription = [float]($b.Width-$wPeriod-$wType-$wCategory-$wAmount)
    if ($script:summaryIndex -lt @($script:pdfData.summary).Count) {
        $g.DrawString('Dönem özeti',$headFont,$blue,$left,$y); $y += 20
        $g.FillRectangle($paleBlue,$left,$y,$b.Width,$rowHeight)
        $g.DrawString('Dönem',$headFont,$black,[System.Drawing.RectangleF]::new($left,$y,$wPeriod,$rowHeight),$fmt)
        $g.DrawString('Gelir',$headFont,$black,[System.Drawing.RectangleF]::new(($left+$wPeriod),$y,$wType,$rowHeight),$fmt)
        $g.DrawString('Gider',$headFont,$black,[System.Drawing.RectangleF]::new(($left+$wPeriod+$wType),$y,$wType,$rowHeight),$fmt)
        $g.DrawString('Bakiye',$headFont,$black,[System.Drawing.RectangleF]::new(($right-$wAmount),$y,$wAmount,$rowHeight),$fmt)
        $y += $rowHeight
        while ($script:summaryIndex -lt @($script:pdfData.summary).Count -and ($y+$rowHeight) -le $bottom) {
            $r = $script:pdfData.summary[$script:summaryIndex]
            $g.DrawString([string]$r.period,$bodyFont,$black,[System.Drawing.RectangleF]::new($left,$y,$wPeriod,$rowHeight),$fmt)
            $g.DrawString([string]$r.income,$bodyFont,$green,[System.Drawing.RectangleF]::new(($left+$wPeriod),$y,$wType,$rowHeight),$fmt)
            $g.DrawString([string]$r.expense,$bodyFont,$red,[System.Drawing.RectangleF]::new(($left+$wPeriod+$wType),$y,$wType,$rowHeight),$fmt)
            $g.DrawString([string]$r.balance,$bodyFont,$black,[System.Drawing.RectangleF]::new(($right-$wAmount),$y,$wAmount,$rowHeight),$fmt)
            $g.DrawLine($line,$left,($y+$rowHeight),$right,($y+$rowHeight)); $y += $rowHeight; $script:summaryIndex++
        }
    }
    if ($script:summaryIndex -ge @($script:pdfData.summary).Count -and $script:recordIndex -lt @($script:pdfData.records).Count) {
        if (($y+42) -le $bottom) {
            $sectionTitle = if ($script:pdfData.table_kind -eq 'transactions') { 'İşlem detayları' } else { [string]$script:pdfData.title }
            $g.DrawString($sectionTitle,$headFont,$blue,$left,($y+1)); $y += 20
        }
        $g.FillRectangle($paleBlue,$left,$y,$b.Width,$rowHeight)
        $x = $left
        $headers = @($script:pdfData.table_headers)
        $widths = @($script:pdfData.table_widths | ForEach-Object { [float]$_ * $b.Width })
        for ($i=0; $i -lt $headers.Count; $i++) {
            $g.DrawString([string]$headers[$i],$headFont,$black,[System.Drawing.RectangleF]::new($x,$y,[float]$widths[$i],$rowHeight),$fmt)
            $x += [float]$widths[$i]
        }
        $y += $rowHeight
        while ($script:recordIndex -lt @($script:pdfData.records).Count -and ($y+$rowHeight) -le $bottom) {
            $r = $script:pdfData.records[$script:recordIndex]
            $isIncome = ([string]$r.cells[1] -eq 'Gelir')
            if ($script:pdfData.table_kind -eq 'transactions') {
                if ($isIncome) { $rowBrush=$paleGreen; $kindBrush=$green } else { $rowBrush=$paleRed; $kindBrush=$red }
            } else { $rowBrush=[System.Drawing.Brushes]::White; $kindBrush=$green }
            $g.FillRectangle($rowBrush,$left,$y,$b.Width,$rowHeight)
            $x = $left
            $vals = @($r.cells)
            for ($i=0; $i -lt $vals.Count; $i++) {
                $brush=$black; $font=$bodyFont
                if ($script:pdfData.table_kind -eq 'transactions') {
                    if ($i -eq 1) { $brush=$kindBrush }
                    if ($i -eq 4) { $brush=$kindBrush; $font=$boldFont }
                } elseif ($script:pdfData.table_kind -eq 'fixed_donors' -and $i -gt 0) {
                    if ([string]$vals[$i] -eq '✓') { $brush=$green; $font=$boldFont }
                    elseif ([string]$vals[$i] -eq '×') { $brush=$red; $font=$boldFont }
                } elseif ($script:pdfData.table_kind -eq 'donors' -and $i -eq 4) { $brush=$green; $font=$boldFont }
                $g.DrawString($vals[$i],$font,$brush,[System.Drawing.RectangleF]::new($x,$y,[float]$widths[$i],$rowHeight),$fmt)
                $x += [float]$widths[$i]
            }
            $g.DrawLine($line,$left,($y+$rowHeight),$right,($y+$rowHeight)); $y += $rowHeight; $script:recordIndex++
        }
    }
    $e.HasMorePages = ($script:summaryIndex -lt @($script:pdfData.summary).Count -or $script:recordIndex -lt @($script:pdfData.records).Count)
    $titleFont.Dispose(); $subFont.Dispose(); $headFont.Dispose(); $bodyFont.Dispose(); $boldFont.Dispose(); $green.Dispose(); $red.Dispose(); $paleGreen.Dispose(); $paleRed.Dispose(); $paleBlue.Dispose(); $line.Dispose(); $fmt.Dispose()
})
$form = New-Object System.Windows.Forms.Form
$form.Text = 'A4 Baskı Önizleme — Basit Ev Muhasebe Programı'
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.MinimumSize = New-Object System.Drawing.Size(900,650)
$form.KeyPreview = $true
$toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
$toolbar.Dock = [System.Windows.Forms.DockStyle]::Top
$toolbar.Height = 56
$toolbar.Padding = New-Object System.Windows.Forms.Padding(12,8,8,6)
$toolbar.WrapContents = $false
$printButton = New-Object System.Windows.Forms.Button
$printButton.Text = 'Yazdır / PDF seç'
$printButton.AutoSize = $true
$printButton.Height = 36
$printButton.Font = New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
$printButton.BackColor = [System.Drawing.Color]::FromArgb(223,243,255)
$printButton.ForeColor = [System.Drawing.Color]::FromArgb(23,74,114)
$printButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Text = 'Kapat'
$closeButton.AutoSize = $true
$closeButton.Height = 36
$closeButton.BackColor = [System.Drawing.Color]::FromArgb(223,243,255)
$closeButton.ForeColor = [System.Drawing.Color]::FromArgb(23,74,114)
$closeButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$toolbar.Controls.Add($printButton)
$toolbar.Controls.Add($closeButton)
$preview = New-Object System.Windows.Forms.PrintPreviewControl
$preview.Document = $doc
$preview.Dock = [System.Windows.Forms.DockStyle]::Fill
$preview.UseAntiAlias = $true
$preview.Zoom = 0.8
$script:printError = $null
$closeButton.Add_Click({ $form.Close() })
$printButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.PrintDialog
    try {
        $dialog.Document = $doc
        $dialog.UseEXDialog = $true
        $dialog.AllowPrintToFile = $true
        $dialog.AllowSelection = $false
        $dialog.AllowSomePages = $true
        if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $doc.PrinterSettings = $dialog.PrinterSettings
                # Use the selected Windows printer for the actual print job.
                # Microsoft Print to PDF then shows its own native Save dialog.
                if ($doc.PrinterSettings.PrinterName -like '*Microsoft Print to PDF*' -and
                    (Test-Path -LiteralPath $initialPdfDirectory -PathType Container)) {
                    $doc.PrinterSettings.PrintFileName = Join-Path $initialPdfDirectory ('gelir-gider-raporu-' + (Get-Date -Format 'yyyy-MM-dd-HHmmss') + '.pdf')
                }
                $doc.Print()
            }
            catch {
                $script:printError = $_.Exception.ToString()
                [void][System.Windows.Forms.MessageBox]::Show($script:printError,'Yazdırma hatası',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    } catch {
        $script:printError = $_.Exception.ToString()
        [void][System.Windows.Forms.MessageBox]::Show($script:printError,'Yazdırma penceresi hatası',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    } finally { $dialog.Dispose() }
})
$form.Controls.Add($preview)
$form.Controls.Add($toolbar)
try { [void]$form.ShowDialog() } finally { $doc.Dispose(); $form.Dispose() }
if ($script:printError) { throw $script:printError }
'''
        with tempfile.TemporaryDirectory(prefix="og_pdf_", dir=str(DATA_DIR)) as temp_dir:
            temp_dir = Path(temp_dir)
            data_path, script_path = temp_dir / "report.json", temp_dir / "print.ps1"
            data_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            script_path.write_text(script, encoding="utf-8-sig")
            result = subprocess.run([printer, "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File", str(script_path), str(data_path)],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or f"PowerShell çıkış kodu: {result.returncode}").strip())
        return None

    def show_pdf_error(self, details: str) -> None:
        log_file = DATA_DIR / "pdf_hata.txt"
        try:
            log_file.write_text(details, encoding="utf-8")
        except OSError:
            pass
        popup = tk.Toplevel(self.root)
        popup.title("PDF oluşturulamadı")
        popup.transient(self.root)
        popup.geometry("760x440")
        tk.Label(popup, text="PDF kaydedilemedi. Aşağıdaki hata ayrıntılarını kopyalayabilirsin.",
                 font=("Segoe UI", 11, "bold"), padx=12, pady=10).pack(anchor="w")
        text = tk.Text(popup, wrap="word", font=("Consolas", 9), height=15)
        text.pack(fill="both", expand=True, padx=12, pady=6)
        text.insert("1.0", details)
        text.configure(state="normal", exportselection=False, takefocus=True)
        text.bind("<KeyPress>", lambda event: "break")

        def write_clipboard(value: str) -> None:
            try:
                copy_text_to_windows_clipboard(value)
                copied.configure(text="Panoya yazıldı; kopyalama tamamlandı.", fg="#07883d")
            except (OSError, ctypes.ArgumentError) as exc:
                copied.configure(text=f"Panoya kopyalanamadı: {exc}", fg="#c92732")

        def copy_selection(event=None) -> str:
            try:
                selected = text.get("sel.first", "sel.last")
            except tk.TclError:
                copied.configure(text="Önce kopyalamak istediğin metni fareyle seç.", fg="#c27a00")
                return "break"
            write_clipboard(selected)
            return "break"

        def select_all(event=None) -> str:
            text.tag_add("sel", "1.0", "end-1c")
            text.mark_set("insert", "1.0")
            text.see("insert")
            return "break"

        text.bind("<Control-c>", copy_selection)
        text.bind("<Control-C>", copy_selection)
        text.bind("<Control-a>", select_all)
        text.bind("<Control-A>", select_all)
        menu = tk.Menu(text, tearoff=False)
        menu.add_command(label="Kopyala", command=copy_selection)
        menu.add_command(label="Tümünü seç", command=select_all)
        def show_text_menu(event) -> None:
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
        text.bind("<Button-3>", show_text_menu)
        text.bind("<Button-1>", lambda event: text.focus_set(), add="+")
        buttons = tk.Frame(popup, padx=12, pady=10)
        buttons.pack(fill="x")
        copied = tk.Label(buttons, text=f"Hata kaydı: {log_file}", fg="#52627a")
        copied.pack(side="left")
        def copy_details() -> None:
            write_clipboard(details)
        tk.Button(buttons, text="Kopyala", command=copy_details, bg="#e7f1ff", fg="#0b3d79", padx=14, pady=7).pack(side="right", padx=4)
        tk.Button(buttons, text="Kapat", command=popup.destroy, padx=14, pady=7).pack(side="right", padx=4)

    def refresh_transactions(self) -> None:
        start, end = self.start_date_entry.get().strip(), self.end_date_entry.get().strip()
        for label, value in (("Başlangıç", start), ("Bitiş", end)):
            if value:
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    messagebox.showwarning("Tarih biçimi", f"{label} tarihini YYYY-AA-GG biçiminde yaz.")
                    return
        if start and end and start > end:
            messagebox.showwarning("Tarih aralığı", "Başlangıç tarihi bitiş tarihinden sonra olamaz.")
            return
        kind = self.type_filter.get()
        category_filter = self.category_filter.get() if hasattr(self, "category_filter") else "Tüm Kategoriler"
        query = self.search_entry.get().strip().casefold() if hasattr(self, "search_entry") else ""
        rows = []
        for rec in self.store.get("transactions", []):
            day = rec.get("date", "")
            if start and day < start or end and day > end:
                continue
            if kind in ("Gelir", "Gider") and rec.get("type") != kind:
                continue
            if category_filter != "Tüm Kategoriler" and rec.get("category") != category_filter:
                continue
            if query and query not in (str(rec.get("description", "")) + " " + str(rec.get("category", ""))).casefold():
                continue
            rows.append(rec)
        rows.sort(key=lambda rec: (rec.get("date", ""), rec.get("created_at", "")), reverse=True)
        self.displayed_records = rows
        self.selected_row_index = None
        for child in self.table_rows_frame.winfo_children():
            child.destroy()
        if not rows:
            tk.Label(self.table_rows_frame, text="Seçilen ölçütlerde kayıt yok", bg="white", fg="#52627a", font=("Segoe UI", 12), pady=18).pack(fill="x")
        for index, rec in enumerate(rows):
            amount = Decimal(str(rec.get("amount", "0")))
            is_income = rec.get("type") == "Gelir"
            sign = "+" if is_income else "−"
            values = (rec.get("date", ""), rec.get("description", ""), rec.get("category", ""),
                      rec.get("type", ""), f"{sign} {self.euro(amount)}")
            row_bg = "#e6f6eb" if is_income else "#fff0f0"
            row = tk.Frame(self.table_rows_frame, bg=row_bg, bd=0, highlightthickness=0, height=39)
            row.transaction_type = rec.get("type", "")
            row.pack(fill="x")
            row.pack_propagate(False)
            for col, value in enumerate(values):
                color = "#07883d" if is_income else "#c92732"
                font = ("Segoe UI", 12)
                if col == 4:
                    font = ("Segoe UI", 13, "bold")
                weight = self.table_column_specs[col][2]
                x = sum(spec[2] for spec in self.table_column_specs[:col])
                cell = tk.Label(row, text=value, bg=row_bg, fg=color, font=font, anchor="w", justify="left", padx=10, bd=0, highlightthickness=0)
                cell.place(relx=x, rely=0, relwidth=weight, relheight=1)
                cell.bind("<Button-1>", lambda _event, row_index=index: self.select_table_row(row_index), add="+")
                cell.bind("<Double-1>", lambda _event, row_index=index: self.select_table_row(row_index, edit=True), add="+")
                cell.bind("<MouseWheel>", self.on_table_mousewheel, add="+")
            row.bind("<Button-1>", lambda _event, row_index=index: self.select_table_row(row_index), add="+")
            row.bind("<Double-1>", lambda _event, row_index=index: self.select_table_row(row_index, edit=True), add="+")
            row.bind("<MouseWheel>", self.on_table_mousewheel, add="+")
        income = sum((Decimal(str(r.get("amount", "0"))) for r in rows if r.get("type") == "Gelir"), Decimal("0"))
        expense = sum((Decimal(str(r.get("amount", "0"))) for r in rows if r.get("type") == "Gider"), Decimal("0"))
        self.summary_vars["Toplam Gelir"].set(self.euro(income))
        self.summary_vars["Toplam Gider"].set(self.euro(expense))
        self.summary_vars["Bakiye"].set(self.euro(income - expense))
        if hasattr(self, "month_summary_vars"):
            self.month_summary_vars["Gelir"].set(self.euro(income))
            self.month_summary_vars["Gider"].set(self.euro(expense))
            self.month_summary_vars["Bakiye"].set(self.euro(income-expense))
            for child in self.category_summary.winfo_children(): child.destroy()
            grouped = {}
            for rec in rows:
                if rec.get("type") == "Gider": grouped[rec.get("category", "Diğer")] = grouped.get(rec.get("category", "Diğer"), Decimal("0")) + Decimal(str(rec.get("amount", "0")))
            max_total = max(grouped.values(), default=Decimal("1")) or Decimal("1")
            for cat, total in sorted(grouped.items(), key=lambda x: x[1], reverse=True)[:6]:
                row = tk.Frame(self.category_summary, bg="white")
                row.pack(fill="x", pady=(5, 1))
                tk.Label(row, text=cat, bg="white", fg="#263a59", font=("Segoe UI", 10, "bold")).pack(side="left")
                tk.Label(row, text=self.euro(total), bg="white", fg="#263a59", font=("Segoe UI", 10)).pack(side="right")
                bar = tk.Canvas(self.category_summary, height=7, bg="white", highlightthickness=0)
                bar.pack(fill="x", pady=(0, 5))
                bar.create_rectangle(0, 0, max(8, int(245 * float(total / max_total))), 7, fill="#fb8b82", outline="")

    def clear_filters(self) -> None:
        self.start_date_entry.delete(0, "end")
        self.end_date_entry.delete(0, "end")
        self.type_filter.set("Tüm Türler")
        self.category_filter.set("Tüm Kategoriler")
        self.search_entry.delete(0, "end")
        self.refresh_transactions()

    def show_page(self, name: str, *, verify_sensitive: bool = True) -> None:
        if name == "Önemli Kişiler" and verify_sensitive:
            if not self.confirm_account_password("Önemli Kişiler bölümünü açma"):
                return
        self._update_navigation_state(name)
        if name == "Genel Bakış":
            self.show_dashboard(self.current_username)
        elif name in ("Gelirler", "Giderler"):
            self.open_transaction_form("Gelir" if name == "Gelirler" else "Gider")
        else:
            for child in self.content.winfo_children():
                child.destroy()
            tk.Label(self.content, text=name, bg="#ffffff", fg="#0b3d79", font=("Segoe UI", 24, "bold")).pack(anchor="w", pady=(0, 20))
            if name == "Kategoriler":
                tk.Button(self.content, text="＋ Yeni Kategori Ekle", command=self.add_category, bg="#1680e8", fg="white", relief="flat", padx=16, pady=10, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 14))
                for category in self.store.get("categories", []):
                    row = tk.Frame(self.content, bg="white", padx=12, pady=8, highlightbackground="#e1e8f1", highlightthickness=1)
                    row.pack(anchor="w", fill="x", pady=4)
                    tk.Label(row, text="•  " + category, bg="white", fg="#17325b", font=("Segoe UI", 14, "bold")).pack(side="left")
                    tk.Button(row, text="Sil", command=lambda value=category: self.delete_category(value), bg="#fff0f0", fg="#c92732", relief="groove", bd=1, padx=14, pady=5).pack(side="right")
            elif name == "Raporlar":
                self.show_reports()
            elif name == "Bağışçılar":
                self.show_donors()
            elif name == "Sabit Bağışçılar":
                self.show_fixed_donors()
            elif name == "Kişilerim":
                self.show_people()
            elif name == "Önemli Kişiler":
                self.show_important_contacts()
            elif name == "Ayarlar":
                self.show_settings()
            else:
                tk.Label(self.content, text=f"Sürüm: {APP_VERSION}\nKayıt klasörü: {DATA_DIR}", bg="#ffffff", fg="#17233d", justify="left", font=("Segoe UI", 12)).pack(anchor="w")
            self.enhance_controls(self.content)

    @staticmethod
    def ice_button(parent: tk.Misc, text: str, command, *, fg: str = "#174a72", **kwargs) -> tk.Button:
        options = {"bg": "#dff3ff", "activebackground": "#c4e8fa",
                   "activeforeground": fg, "relief": "raised", "bd": 2,
                   "padx": 16, "pady": 9, "font": ("Segoe UI", 11, "bold"),
                   "cursor": "hand2"}
        options.update(kwargs)
        return tk.Button(parent, text=text, command=command, fg=fg, **options)

    def show_important_contacts(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()
        self._editing_important_contact_id = None
        tk.Label(self.content, text="Önemli Kişiler", bg="#f7f9fc", fg="#0b3d79",
                 font=("Segoe UI", 23, "bold")).pack(anchor="w", pady=(0, 6))
        tk.Label(self.content,
                 text="Bu özel liste Kişilerimden, bağışçı kayıtlarından ve gelir-gider işlemlerinden bağımsızdır. Bölüme her girişte program şifresi sorulur.",
                 bg="#f7f9fc", fg="#52627a", font=("Segoe UI", 10), wraplength=900,
                 justify="left").pack(anchor="w", pady=(0, 12))

        form = tk.Frame(self.content, bg="white", padx=18, pady=14,
                        highlightbackground="#c5daf0", highlightthickness=1)
        form.pack(fill="x", pady=(0, 12))
        fields = tk.Frame(form, bg="white")
        fields.pack(fill="x")
        self.important_contact_entries = {}
        for column, (key, label, width) in enumerate((
            ("name", "Adı / Kurum", 28), ("phone", "Telefon numarası", 24), ("email", "E-posta", 32)
        )):
            tk.Label(fields, text=label, bg="white", fg="#263a59", font=("Segoe UI", 10, "bold")).grid(
                row=0, column=column, sticky="w", padx=(0 if column == 0 else 10, 0), pady=(0, 4))
            entry = ttk.Entry(fields, width=width)
            entry.grid(row=1, column=column, sticky="ew", padx=(0 if column == 0 else 10, 0))
            self.important_contact_entries[key] = entry
            fields.grid_columnconfigure(column, weight=1)
        form_actions = tk.Frame(form, bg="white")
        form_actions.pack(fill="x", pady=(10, 0))
        self.important_contact_save_button = self.ice_button(form_actions, "＋ Kişi ekle", self.save_important_contact)
        self.important_contact_save_button.pack(side="left")
        self.important_contact_cancel_button = self.ice_button(
            form_actions, "İptal", self.show_important_contacts, fg="#52627a")
        self.important_contact_cancel_button.pack(side="left", padx=8)
        self.important_contact_cancel_button.pack_forget()

        list_panel = tk.Frame(self.content, bg="white", padx=8, pady=8,
                              highlightbackground="#d7e1ee", highlightthickness=1)
        list_panel.pack(fill="both", expand=True)
        columns = ("name", "phone", "email")
        table = ttk.Treeview(list_panel, columns=columns, show="headings", height=12)
        self.important_contacts_table = table
        for column, label, width in (("name", "Adı / Kurum", 270), ("phone", "Telefon numarası", 230), ("email", "E-posta", 360)):
            table.heading(column, text=label)
            table.column(column, width=width, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(list_panel, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for contact in self.store.setdefault("important_contacts", []):
            contact_id = str(contact.setdefault("id", uuid.uuid4().hex))
            table.insert("", "end", iid=contact_id, values=(
                contact.get("name", ""), contact.get("phone", ""), contact.get("email", "")))
        if not table.get_children(""):
            table.insert("", "end", iid="__empty__", values=("Henüz önemli kişi eklenmedi", "", ""), tags=("empty",))
            table.tag_configure("empty", foreground="#718096")
        actions = tk.Frame(self.content, bg="#f7f9fc")
        actions.pack(fill="x", pady=(10, 0))
        self.ice_button(actions, "✎ Seçileni düzenle", self.edit_selected_important_contact).pack(side="left")
        self.ice_button(actions, "Sil", self.delete_selected_important_contact, fg="#bd2934").pack(side="left", padx=8)
        self.enhance_controls(self.content)

    def save_important_contact(self) -> None:
        values = {key: entry.get().strip() for key, entry in self.important_contact_entries.items()}
        if not values["name"]:
            messagebox.showwarning("Önemli Kişiler", "Kişinin adını veya kurum adını yaz.", parent=self.root)
            self.important_contact_entries["name"].focus_set()
            return
        if not values["phone"] and not values["email"]:
            messagebox.showwarning("İletişim bilgisi eksik", "Telefon numarası veya e-posta adresinden en az birini gir.", parent=self.root)
            return
        if values["email"] and not self.is_valid_email(values["email"]):
            messagebox.showwarning("E-posta geçersiz", "E-posta adresini kontrol et.", parent=self.root)
            self.important_contact_entries["email"].focus_set()
            return

        previous = [record.copy() for record in self.store.setdefault("important_contacts", [])]
        editing_id = self._editing_important_contact_id
        if editing_id:
            record = next((item for item in self.store["important_contacts"]
                           if str(item.get("id")) == str(editing_id)), None)
            if record is None:
                messagebox.showerror("Kişi bulunamadı", "Bu kişi artık listede yok.", parent=self.root)
                self.show_important_contacts()
                return
            record.update(values)
        else:
            self.store["important_contacts"].append({"id": uuid.uuid4().hex, **values})
        try:
            atomic_json_write(BOOKS_FILE, self.store)
        except OSError as exc:
            self.store["important_contacts"] = previous
            messagebox.showerror("Kayıt yapılamadı", str(exc), parent=self.root)
            return
        self.show_important_contacts()

    def edit_selected_important_contact(self) -> None:
        selected = self.important_contacts_table.selection()
        if not selected or selected[0] == "__empty__":
            messagebox.showinfo("Kişi seçilmedi", "Düzenlemek için listeden bir kişi seç.", parent=self.root)
            return
        contact_id = str(selected[0])
        contact = next((item for item in self.store.get("important_contacts", [])
                        if str(item.get("id")) == contact_id), None)
        if contact is None:
            messagebox.showerror("Kişi bulunamadı", "Bu kişi artık listede yok.", parent=self.root)
            return
        self._editing_important_contact_id = contact_id
        for key, entry in self.important_contact_entries.items():
            entry.delete(0, "end")
            entry.insert(0, str(contact.get(key, "")))
        self.important_contact_save_button.configure(text="Bilgileri güncelle")
        self.important_contact_cancel_button.pack(side="left", padx=8)
        self.important_contact_entries["name"].focus_set()

    def delete_selected_important_contact(self) -> None:
        selected = self.important_contacts_table.selection()
        if not selected or selected[0] == "__empty__":
            messagebox.showinfo("Kişi seçilmedi", "Silmek için listeden bir kişi seç.", parent=self.root)
            return
        contact_id = str(selected[0])
        contact = next((item for item in self.store.get("important_contacts", [])
                        if str(item.get("id")) == contact_id), None)
        if contact is None:
            messagebox.showerror("Kişi bulunamadı", "Bu kişi artık listede yok.", parent=self.root)
            return
        if not messagebox.askyesno("Önemli kişiyi sil", f"{contact.get('name', '')} listesinden kaldırılsın mı?",
                                   parent=self.root):
            return
        previous = [record.copy() for record in self.store.get("important_contacts", [])]
        self.store["important_contacts"] = [record for record in self.store["important_contacts"]
                                              if str(record.get("id")) != contact_id]
        try:
            atomic_json_write(BOOKS_FILE, self.store)
        except OSError as exc:
            self.store["important_contacts"] = previous
            messagebox.showerror("Kişi silinemedi", str(exc), parent=self.root)
            return
        self.show_important_contacts()

    def show_donors(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()
        header = tk.Frame(self.content, bg="#f7f9fc")
        header.pack(fill="x", pady=(0, 14))
        tk.Label(header, text="Bağışçılar", bg="#f7f9fc", fg="#0b3d79", font=("Segoe UI", 23, "bold")).pack(side="left")
        actions = tk.Frame(header, bg="#f7f9fc")
        actions.pack(side="right")
        self.ice_button(actions, "＋ Kişilerimden seç", lambda: self.show_people(pick_for="regular")).pack(side="left", padx=5)
        self.ice_button(actions, "▣ Yazdır", self.print_donors).pack(side="left", padx=5)
        tk.Label(self.content, text="Bağışçıların iletişim ve bağış bilgileri", bg="#f7f9fc", fg="#52627a",
                 font=("Segoe UI", 11)).pack(anchor="w", pady=(0, 10))
        wrap = tk.Frame(self.content, bg="white", highlightbackground="#d7e1ee", highlightthickness=1)
        wrap.pack(fill="both", expand=True)
        columns = ("name", "address", "phone", "email", "amount")
        table = ttk.Treeview(wrap, columns=columns, show="headings", height=16)
        for col, label, width in (("name", "İsim", 210), ("address", "Adres", 300), ("phone", "Telefon", 170),
                                  ("email", "E-posta", 250), ("amount", "Bağış tutarı", 160)):
            table.heading(col, text=label)
            table.column(col, width=width, anchor="w", stretch=True)
        scrollbar = ttk.Scrollbar(wrap, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        scrollbar.pack(side="right", fill="y", pady=8)
        for donor in self.store.get("donors", []):
            person = self.person_by_id(donor.get("person_id"))
            details = person or donor
            amount = donor.get("amount", "")
            try:
                shown_amount = self.euro(Decimal(str(amount))) if amount else "—"
            except InvalidOperation:
                shown_amount = str(amount)
            table.insert("", "end", values=(details.get("name", donor.get("name", "")),
                                             details.get("address", donor.get("address", "")),
                                             details.get("phone", donor.get("phone", "")),
                                             details.get("email", donor.get("email", "")), shown_amount))
        self.enhance_controls(self.content)

    def show_fixed_donors(self, year: int | None = None) -> None:
        year = int(year or getattr(self, "fixed_donors_year", datetime.now().year))
        self.fixed_donors_year = year
        self.pending_fixed_payment = None
        for child in self.content.winfo_children():
            child.destroy()
        header = tk.Frame(self.content, bg="#f7f9fc")
        header.pack(fill="x", pady=(0, 10))
        tk.Label(header, text="Sabit Bağışçılar", bg="#f7f9fc", fg="#0b3d79", font=("Segoe UI", 23, "bold")).pack(side="left")
        actions = tk.Frame(header, bg="#f7f9fc")
        actions.pack(side="right")
        self.ice_button(actions, "＋ Kişilerimden seç", lambda: self.show_people(pick_for="fixed", year=year)).pack(side="left", padx=5)
        self.ice_button(actions, "▣ Yazdır", lambda: self.print_fixed_donors(year)).pack(side="left", padx=5)

        controls = tk.Frame(self.content, bg="#f7f9fc")
        controls.pack(fill="x", pady=(0, 10))
        tk.Label(controls, text="Yıl", bg="#f7f9fc", fg="#263a59", font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 7))
        current_year = datetime.now().year
        year_end = max(2040, current_year + 2)
        years = sorted(set(range(current_year - 10, year_end + 1)) |
                       {int(y) for donor in self.store.get("fixed_donors", [])
                        for y in donor.get("payments", {}) if str(y).isdigit()})
        year_var = tk.StringVar(value=str(year))
        year_picker = ttk.Combobox(controls, textvariable=year_var, values=years, state="readonly", width=8)
        year_picker.pack(side="left", padx=(0, 18))
        year_picker.bind("<<ComboboxSelected>>", lambda _event: self.show_fixed_donors(int(year_var.get())))
        self.fixed_selection_label = tk.Label(controls, text="Ödeme işaretlemek için önce ilgili ay kutusunu seç.",
                                              bg="#f7f9fc", fg="#52627a", font=("Segoe UI", 10))
        self.fixed_selection_label.pack(side="left", padx=4)
        self.ice_button(controls, "×  Ödenmedi", lambda: self.apply_fixed_payment_status("unpaid", year),
                        fg="#bd2934", font=("Segoe UI", 12, "bold"), padx=16, pady=9).pack(side="right", padx=(6, 0))
        self.ice_button(controls, "✓  Ödendi", lambda: self.apply_fixed_payment_status("paid", year),
                        fg="#138347", font=("Segoe UI", 12, "bold"), padx=16, pady=9).pack(side="right", padx=(6, 0))

        month_names = ("Oca", "Şub", "Mar", "Nis", "May", "Haz", "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara")
        table_wrap = tk.Frame(self.content, bg="white", highlightbackground="#d7e1ee", highlightthickness=1)
        table_wrap.pack(fill="both", expand=True)
        headings = tk.Frame(table_wrap, bg="#e7f4fc", padx=8, pady=8)
        headings.pack(fill="x")
        tk.Label(headings, text="İsim", width=23, anchor="w", bg="#e7f4fc", fg="#14213d",
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(2, 4))
        for month in month_names:
            tk.Label(headings, text=month, width=5, anchor="center", bg="#e7f4fc", fg="#14213d",
                     font=("Segoe UI", 9, "bold")).pack(side="left", padx=1)
        canvas = tk.Canvas(table_wrap, bg="white", highlightthickness=0)
        scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=canvas.yview)
        rows_frame = tk.Frame(canvas, bg="white")
        canvas_window = canvas.create_window((0, 0), window=rows_frame, anchor="nw")
        rows_frame.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(canvas_window, width=event.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scrollbar.pack(side="right", fill="y", padx=(0, 8), pady=8)
        self.fixed_payment_buttons = {}
        for donor_index, donor in enumerate(self.store.get("fixed_donors", [])):
            row_bg = "#f8fcff" if donor_index % 2 == 0 else "#ffffff"
            row = tk.Frame(rows_frame, bg=row_bg, padx=8, pady=4)
            row.pack(fill="x")
            tk.Label(row, text=donor.get("name", ""), width=23, anchor="w", bg=row_bg, fg="#14213d",
                     font=("Segoe UI", 11)).pack(side="left", padx=(2, 4))
            year_payments = donor.get("payments", {}).get(str(year), {})
            for month_index, month in enumerate(month_names, start=1):
                status = year_payments.get(str(month_index), "")
                mark = "✓" if status == "paid" else ("×" if status == "unpaid" else "")
                color = "#16834a" if status == "paid" else ("#c92b37" if status == "unpaid" else "#395672")
                cell = self.ice_button(row, mark, lambda idx=donor_index, m=month_index, y=year: self.select_fixed_payment(idx, m, y),
                                       fg=color, width=5, padx=4, pady=4, font=("Segoe UI", 12, "bold"))
                # Tiny adjacent month cells flicker when hover colors toggle
                # under the pointer; keep them visually stable and highlight
                # only the explicitly selected cell.
                cell._hover_effect_bound = True
                cell.pack(side="left", padx=1)
                self.fixed_payment_buttons[(donor_index, month_index)] = cell
        if not self.store.get("fixed_donors", []):
            tk.Label(rows_frame, text="Henüz sabit bağışçı eklenmedi.", bg="white", fg="#52627a",
                     font=("Segoe UI", 12)).pack(anchor="w", padx=14, pady=18)
        self.enhance_controls(self.content)

    def select_fixed_payment(self, donor_index: int, month_index: int, year: int) -> None:
        self.pending_fixed_payment = (donor_index, month_index, year)
        for button in self.fixed_payment_buttons.values():
            button.configure(bg="#dff3ff")
        self.fixed_payment_buttons[(donor_index, month_index)].configure(bg="#a9d9f2")
        donor = self.store.get("fixed_donors", [])[donor_index]
        month = ("Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık")[month_index - 1]
        self.fixed_selection_label.configure(text=f"Seçili: {donor.get('name', '')} · {month} {year}")

    def apply_fixed_payment_status(self, status: str, year: int) -> None:
        selected = getattr(self, "pending_fixed_payment", None)
        if selected is None:
            messagebox.showinfo("Ay seçilmedi", "Önce bağışçının ilgili ay kutusunu seç.", parent=self.root)
            return
        donor_index, month_index, selected_year = selected
        if selected_year != year:
            self.show_fixed_donors(year)
            return
        donor = self.store.get("fixed_donors", [])[donor_index]
        month = ("Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık")[month_index - 1]
        label = "ödendi" if status == "paid" else "ödenmedi"
        amount = Decimal("0")
        if status == "paid":
            try:
                amount = Decimal(str(donor.get("amount", "0"))).quantize(Decimal("0.01"))
            except (InvalidOperation, ValueError):
                amount = Decimal("0")
            if amount <= 0:
                messagebox.showwarning("Bağış tutarı eksik", "Bu sabit bağışçı için önce geçerli bir aylık bağış tutarı kaydet.", parent=self.root)
                return
            prompt = (f"{donor.get('name', '')} için {month} {year} sabit bağışı "
                      f"{self.euro(amount)} olarak, bugünün tarihiyle gelir kaydına eklensin mi?")
        else:
            prompt = (f"{donor.get('name', '')} için {month} {year} bağışı ödenmedi olarak işaretlensin mi? "
                      "Bu aya ait otomatik gelir kaydı varsa kaldırılır.")
        if not messagebox.askyesno("İşlemi onayla", prompt, parent=self.root):
            return
        payments = donor.setdefault("payments", {})
        year_payments = payments.setdefault(str(year), {})
        previous = year_payments.get(str(month_index))
        donor_id = donor.setdefault("id", uuid.uuid4().hex)
        payment_id = f"fixed:{donor_id}:{year}:{month_index}"
        old_transactions = self.store.setdefault("transactions", [])[:]
        year_payments[str(month_index)] = status
        if status == "paid":
            if not any(item.get("donor_payment_id") == payment_id for item in self.store["transactions"]):
                self.store["transactions"].append({
                    "date": datetime.now().strftime("%Y-%m-%d"), "type": "Gelir", "category": "Bağış",
                    "amount": format(amount, ".2f"),
                    "description": f"Sabit bağış — {donor.get('name', '')} — {month} {year}",
                    "created_at": datetime.now().isoformat(timespec="seconds"),
                    "source": "Sabit bağış", "donor_id": donor_id, "donor_payment_id": payment_id,
                })
        else:
            self.store["transactions"] = [item for item in self.store["transactions"]
                                          if item.get("donor_payment_id") != payment_id]
        try:
            atomic_json_write(BOOKS_FILE, self.store)
        except OSError as exc:
            self.store["transactions"] = old_transactions
            if previous is None:
                year_payments.pop(str(month_index), None)
            else:
                year_payments[str(month_index)] = previous
            messagebox.showerror("Durum kaydedilemedi", str(exc), parent=self.root)
            return
        self.show_fixed_donors(year)

    def person_by_id(self, person_id) -> dict | None:
        if not person_id:
            return None
        return next((person for person in self.store.get("people", [])
                     if str(person.get("id")) == str(person_id)), None)

    def show_people(self, pick_for: str | None = None, year: int | None = None) -> None:
        for child in self.content.winfo_children():
            child.destroy()
        heading = "Kişilerim" if pick_for is None else "Kişilerimden kişi seç"
        tk.Label(self.content, text=heading, bg="#f7f9fc", fg="#0b3d79",
                 font=("Segoe UI", 23, "bold")).pack(anchor="w", pady=(0, 8))
        hint = ("Kişi bilgilerini burada bir kez kaydet. İsimlerin solundaki kutulardan e-posta alıcılarını seçebilirsin."
                if pick_for is None else "Bir isme tıklayınca bilgileri açılır; tutarı girip kaydedince bağışçı listesine eklenir.")
        tk.Label(self.content, text=hint, bg="#f7f9fc", fg="#52627a",
                 font=("Segoe UI", 11)).pack(anchor="w", pady=(0, 12))
        actions = tk.Frame(self.content, bg="#f7f9fc")
        actions.pack(fill="x", pady=(0, 12))
        self.ice_button(actions, "＋ Yeni kişi", lambda: self.open_person_form(pick_for, year)).pack(side="left", padx=(0, 6))
        if pick_for is None:
            self.ice_button(actions, "🔐 Gönderici Gmail hesabı", self.open_sender_gmail).pack(side="left", padx=6)
        self.people_email_button = self.ice_button(actions, "✉ Seçilenlere e-posta (0)", self.email_selected_people,
                                                   state="disabled")
        self.people_email_button.pack(side="left", padx=6)
        self.ice_button(actions, "▣ Yazdır", self.print_people).pack(side="left", padx=6)
        if pick_for is None:
            def selected_person_id_for_action(action: str) -> str | None:
                selection = table.selection()
                if selection:
                    return str(selection[0])
                checked_ids = [person_id for person_id in table.get_children("")
                               if person_id in self.selected_email_person_ids]
                if len(checked_ids) == 1:
                    return checked_ids[0]
                if len(checked_ids) > 1:
                    messagebox.showinfo(
                        "Bir kişi seç",
                        f"Birden fazla kişi e-posta için işaretli. {action} için istediğin kişinin satırına tıkla.",
                        parent=self.root)
                else:
                    messagebox.showinfo("Kişi seçilmedi", f"{action} için listeden bir kişinin satırına tıkla.",
                                        parent=self.root)
                return None

            def edit_selected_person() -> None:
                person_id = selected_person_id_for_action("Düzenleme")
                if not person_id:
                    return
                if not self.confirm_account_password("Kişi bilgilerini düzenleme"):
                    return
                self.open_person_form(person_id=person_id)

            def remove_selected_person() -> None:
                person_id = selected_person_id_for_action("Listeden kaldırma")
                if not person_id:
                    return
                person = self.person_by_id(person_id)
                if not person:
                    messagebox.showerror("Kişi bulunamadı", "Seçilen kişi kaydı artık mevcut değil.", parent=self.root)
                    return
                if not messagebox.askyesno(
                        "Kişiyi listeden kaldır",
                        f"{person.get('name', 'Bu kişi')} Kişilerim listesinden kaldırılsın mı?\n\n"
                        "Kişi seçme ve e-posta listesinde görünmez. Bağış kayıtları ve ödeme geçmişi korunur.",
                        parent=self.root):
                    return
                if not self.confirm_account_password("Kişiyi listeden kaldırma"):
                    return
                was_selected_for_email = person_id in self.selected_email_person_ids
                old_archived = person.get("archived")
                person["archived"] = True
                self.selected_email_person_ids.discard(person_id)
                try:
                    atomic_json_write(BOOKS_FILE, self.store)
                except OSError as exc:
                    if old_archived is None:
                        person.pop("archived", None)
                    else:
                        person["archived"] = old_archived
                    if was_selected_for_email:
                        self.selected_email_person_ids.add(person_id)
                    messagebox.showerror("Kişi kaldırılamadı", str(exc), parent=self.root)
                    return
                self.show_people(pick_for, year)

            self.ice_button(actions, "✎ Düzenle seçili", edit_selected_person).pack(side="left", padx=6)
            self.ice_button(actions, "⌫ Kişiyi listeden kaldır", remove_selected_person).pack(side="left", padx=6)
        if pick_for:
            return_to = "Sabit Bağışçılar" if pick_for == "fixed" else "Bağışçılar"
            self.ice_button(actions, "← Geri dön", lambda: self.show_page(return_to)).pack(side="right", padx=6)

        wrap = tk.Frame(self.content, bg="white", highlightbackground="#cbd9e8", highlightthickness=1)
        wrap.pack(fill="both", expand=True)
        columns = ("mail", "name", "address", "phone", "email")
        table = ttk.Treeview(wrap, columns=columns, show="headings", height=18, selectmode="browse")
        self.people_table = table
        for column, title, width, anchor in (
                ("mail", "☐ Tümü", 105, "center"), ("name", "İsim", 210, "w"),
                ("address", "Adres", 310, "w"), ("phone", "Telefon", 165, "w"), ("email", "E-posta", 250, "w")):
            table.heading(column, text=title)
            table.column(column, width=width, anchor=anchor, stretch=True)
        scrollbar = ttk.Scrollbar(wrap, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True, padx=8, pady=8)
        scrollbar.pack(side="right", fill="y", pady=8)
        people = sorted((item for item in self.store.get("people", []) if not item.get("archived")),
                        key=lambda item: str(item.get("name", "")).casefold())
        for person in people:
            person_id = str(person.get("id", ""))
            mark = "☑" if person_id in self.selected_email_person_ids else "☐"
            table.insert("", "end", iid=person_id, values=(mark, person.get("name", ""), person.get("address", ""),
                                                              person.get("phone", ""), person.get("email", "")))

        def update_select_all_heading() -> None:
            ids = {str(person.get("id", "")) for person in people}
            all_checked = bool(ids) and ids.issubset(self.selected_email_person_ids)
            table.heading("mail", text="☑ Tümü" if all_checked else "☐ Tümü", command=toggle_all_people)

        def toggle_all_people() -> None:
            ids = {str(person.get("id", "")) for person in people}
            if ids and ids.issubset(self.selected_email_person_ids):
                self.selected_email_person_ids.difference_update(ids)
            else:
                self.selected_email_person_ids.update(ids)
            for person_id in ids:
                if table.exists(person_id):
                    values = list(table.item(person_id, "values"))
                    values[0] = "☑" if person_id in self.selected_email_person_ids else "☐"
                    table.item(person_id, values=values)
            update_select_all_heading()
            self.update_email_button_state()

        update_select_all_heading()
        if not people:
            tk.Label(wrap, text="Henüz kişi eklenmedi. Önce Yeni kişi düğmesine bas.", bg="white",
                     fg="#52627a", font=("Segoe UI", 12)).place(relx=0.5, rely=0.5, anchor="center")

        def table_click(event):
            item_id = table.identify_row(event.y)
            column_id = table.identify_column(event.x)
            if not item_id:
                return None
            if column_id == "#1":
                if item_id in self.selected_email_person_ids:
                    self.selected_email_person_ids.remove(item_id)
                    mark = "☐"
                else:
                    self.selected_email_person_ids.add(item_id)
                    mark = "☑"
                values = list(table.item(item_id, "values"))
                values[0] = mark
                table.item(item_id, values=values)
                update_select_all_heading()
                self.update_email_button_state()
                return "break"
            if pick_for and column_id == "#2":
                self.open_person_membership(item_id, pick_for, year)
                return "break"
            return None

        table.bind("<Button-1>", table_click, add="+")
        if pick_for:
            def use_selected_person() -> None:
                selection = table.selection()
                if not selection:
                    messagebox.showinfo("Kişi seçilmedi", "Listeden bir kişiyi seç veya adına tıkla.", parent=self.root)
                    return
                self.open_person_membership(selection[0], pick_for, year)
            table.bind("<Double-1>", lambda _event: use_selected_person(), add="+")
            self.ice_button(actions, "Seçili kişiyi çağır", use_selected_person).pack(side="left", padx=6)
        self.enhance_controls(self.content)
        self.update_email_button_state()

    def open_person_form(self, pick_for: str | None = None, year: int | None = None,
                         person_id: str | None = None) -> None:
        existing_person = self.person_by_id(person_id) if person_id else None
        for child in self.content.winfo_children():
            child.destroy()
        body = tk.Frame(self.content, bg="white", padx=28, pady=24,
                        highlightbackground="#d7e1ee", highlightthickness=1)
        body.pack(anchor="nw", fill="x")
        tk.Label(body, text="Kişi bilgilerini düzenle" if existing_person else "Kişi bilgileri", bg="white", fg="#0b3d79",
                 font=("Segoe UI", 21, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))
        entries = {}
        for row_index, (key, label) in enumerate((("name", "İsim"), ("address", "Adres"),
                                                   ("phone", "Telefon"), ("email", "E-posta")), start=1):
            tk.Label(body, text=label, bg="white", fg="#263a59", font=("Segoe UI", 11, "bold")).grid(
                row=row_index, column=0, sticky="w", pady=6, padx=(0, 16))
            entry = ttk.Entry(body, width=48)
            entry.grid(row=row_index, column=1, sticky="ew", pady=6)
            if existing_person:
                entry.insert(0, existing_person.get(key, ""))
            entries[key] = entry
        body.grid_columnconfigure(1, weight=1)

        def save_person() -> None:
            name = entries["name"].get().strip()
            address = entries["address"].get().strip()
            if not name or not address:
                messagebox.showwarning("Eksik bilgi", "İsim ve adres alanlarını doldur.", parent=self.root)
                return
            values = {key: entries[key].get().strip() for key in ("name", "address", "phone", "email")}
            if existing_person:
                old_values = dict(existing_person)
                existing_person.update(values)
                person = existing_person
            else:
                person = values
                person.update({"id": uuid.uuid4().hex, "created_at": datetime.now().isoformat(timespec="seconds")})
                self.store.setdefault("people", []).append(person)
            try:
                atomic_json_write(BOOKS_FILE, self.store)
            except OSError as exc:
                if existing_person:
                    existing_person.clear()
                    existing_person.update(old_values)
                else:
                    self.store["people"].pop()
                messagebox.showerror("Kişi kaydedilemedi", str(exc), parent=self.root)
                return
            self.show_people(pick_for, year)

        buttons = tk.Frame(body, bg="white")
        buttons.grid(row=5, column=0, columnspan=2, sticky="e", pady=(20, 0))
        back = (lambda: self.show_people(pick_for, year))
        self.ice_button(buttons, "← Geri dön", back).pack(side="left", padx=5)
        self.ice_button(buttons, "Kaydet", save_person).pack(side="left", padx=5)
        entries["name"].focus_set()
        self.enhance_controls(self.content)

    def open_person_membership(self, person_id: str, donor_kind: str, year: int | None = None) -> None:
        person = self.person_by_id(person_id)
        if not person:
            messagebox.showerror("Kişi bulunamadı", "Bu kayıt Kişilerim havuzunda bulunamadı.", parent=self.root)
            self.show_people(pick_for=donor_kind, year=year)
            return
        fixed = donor_kind == "fixed"
        collection = "fixed_donors" if fixed else "donors"
        destination = "Sabit Bağışçılar" if fixed else "Bağışçılar"
        if any(str(record.get("person_id", "")) == str(person_id) for record in self.store.get(collection, [])):
            messagebox.showinfo("Zaten ekli", f"{person.get('name', '')} bu bağışçı listesinde zaten bulunuyor.", parent=self.root)
            self.show_fixed_donors(year) if fixed else self.show_donors()
            return
        for child in self.content.winfo_children():
            child.destroy()
        body = tk.Frame(self.content, bg="white", padx=28, pady=24,
                        highlightbackground="#d7e1ee", highlightthickness=1)
        body.pack(anchor="nw", fill="x")
        tk.Label(body, text="Sabit bağışçı bilgileri" if fixed else "Geçici bağışçı bilgileri",
                 bg="white", fg="#0b3d79", font=("Segoe UI", 21, "bold")).grid(
                     row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))
        for row_index, (key, label) in enumerate((("name", "İsim"), ("address", "Adres"),
                                                   ("phone", "Telefon"), ("email", "E-posta")), start=1):
            tk.Label(body, text=label, bg="white", fg="#263a59", font=("Segoe UI", 11, "bold")).grid(
                row=row_index, column=0, sticky="w", pady=6, padx=(0, 16))
            tk.Label(body, text=person.get(key, "") or "—", bg="white", fg="#17325b",
                     font=("Segoe UI", 11)).grid(row=row_index, column=1, sticky="w", pady=6)
        tk.Label(body, text="Aylık bağış tutarı (€)", bg="white", fg="#263a59",
                 font=("Segoe UI", 11, "bold")).grid(row=5, column=0, sticky="w", pady=6, padx=(0, 16))
        amount_entry = ttk.Entry(body, width=24)
        amount_entry.grid(row=5, column=1, sticky="w", pady=6)
        note = "Kaydedince 12 aylık ödeme kutuları açılacak." if fixed else "Kaydedince bu bağış ana gelir listesine de eklenecek."
        tk.Label(body, text=note, bg="white", fg="#52627a", font=("Segoe UI", 10)).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))

        def save_membership() -> None:
            amount_text = amount_entry.get().strip().replace("€", "").replace(" ", "")
            try:
                normalized = amount_text.replace(".", "").replace(",", ".") if "," in amount_text else amount_text
                amount = Decimal(normalized).quantize(Decimal("0.01"))
                if amount <= 0:
                    raise InvalidOperation
            except (ValueError, InvalidOperation):
                messagebox.showwarning("Tutar gerekli", "Sıfırdan büyük geçerli bir bağış tutarı gir.", parent=self.root)
                return
            member = {key: person.get(key, "") for key in ("name", "address", "phone", "email")}
            member.update({"id": uuid.uuid4().hex, "person_id": str(person_id), "amount": format(amount, ".2f"),
                           "created_at": datetime.now().isoformat(timespec="seconds")})
            if fixed:
                member["payments"] = {}
            self.store.setdefault(collection, []).append(member)
            transaction = None
            if not fixed:
                transaction = {"date": datetime.now().strftime("%Y-%m-%d"), "type": "Gelir", "category": "Bağış",
                               "amount": format(amount, ".2f"), "description": f"Geçici bağış — {person.get('name', '')}",
                               "created_at": datetime.now().isoformat(timespec="seconds"), "source": "Geçici bağış",
                               "donor_id": member["id"], "person_id": str(person_id),
                               "donor_payment_id": f"temporary:{member['id']}:initial"}
                self.store.setdefault("transactions", []).append(transaction)
            try:
                atomic_json_write(BOOKS_FILE, self.store)
            except OSError as exc:
                self.store[collection].pop()
                if transaction is not None:
                    self.store["transactions"].pop()
                messagebox.showerror("Bağışçı kaydedilemedi", str(exc), parent=self.root)
                return
            if fixed:
                self.show_fixed_donors(year)
            else:
                self.show_donors()

        buttons = tk.Frame(body, bg="white")
        buttons.grid(row=7, column=0, columnspan=2, sticky="e", pady=(20, 0))
        self.ice_button(buttons, "← Geri dön", lambda: self.show_people(pick_for=donor_kind, year=year)).pack(side="left", padx=5)
        self.ice_button(buttons, "Kaydet", save_membership).pack(side="left", padx=5)
        amount_entry.focus_set()
        self.enhance_controls(self.content)

    @staticmethod
    def is_valid_email(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", value.strip(), re.IGNORECASE))

    def selected_people_email_addresses(self) -> list[str]:
        return [str(person.get("email", "")).strip() for person in self.store.get("people", [])
                if not person.get("archived")
                if str(person.get("id", "")) in self.selected_email_person_ids
                and self.is_valid_email(str(person.get("email", "")))]

    def open_url_in_browser(self, uri: str) -> None:
        # Use the system's registered URL handler. Browser executable paths vary
        # between Windows installations (Program Files, x86, and user profile).
        if not webbrowser.open(uri, new=2, autoraise=True):
            raise OSError("Bağlantı varsayılan tarayıcıda açılamadı.")

    def open_sender_gmail(self) -> None:
        sender_email = str(self.settings.get("sender_email", "")).strip()
        if not self.is_valid_email(sender_email):
            messagebox.showinfo("Gönderici Gmail hesabı", "Önce Ayarlar bölümünde geçerli gönderici e-posta adresini kaydet.", parent=self.root)
            return
        gmail_url = "https://mail.google.com/mail/?" + urllib.parse.urlencode({"authuser": sender_email})
        chooser_url = "https://accounts.google.com/AccountChooser?" + urllib.parse.urlencode({
            "Email": sender_email,
            "continue": gmail_url,
        })
        try:
            self.open_url_in_browser(chooser_url)
        except Exception as exc:
            messagebox.showerror("Gmail açılamadı", str(exc), parent=self.root)

    def update_email_button_state(self) -> None:
        if not hasattr(self, "people_email_button") or not self.people_email_button.winfo_exists():
            return
        count = len(self.selected_people_email_addresses())
        self.people_email_button.configure(text=f"✉ Seçilenlere e-posta ({count})",
                                           state="normal" if count else "disabled")

    def email_selected_people(self) -> None:
        addresses = self.selected_people_email_addresses()
        if not addresses:
            messagebox.showinfo("Geçerli e-posta adresi yok",
                                "Seçtiğin kişilerde geçerli bir e-posta adresi bulunamadı. Kişi bilgilerini düzeltip tekrar dene.",
                                parent=self.root)
            return
        recipient_field = "Gizli (Bcc)" if len(addresses) > 1 else "Kime (To)"
        if not messagebox.askyesno("E-posta taslağı", f"{len(addresses)} adres {recipient_field} alanına eklenecek.\n\n"
                                   "E-posta taslağı açılacak; gönderme işlemini sen yapacaksın. Devam edilsin mi?",
                                   parent=self.root):
            return
        sender_email = str(self.settings.get("sender_email", "")).strip()
        if not self.is_valid_email(sender_email):
            messagebox.showinfo("Gönderici Gmail hesabı", "Önce Ayarlar bölümünde geçerli gönderici e-posta adresini kaydet.", parent=self.root)
            return
        # Keep Gmail's compose parameters on the final Gmail URL. Wrapping this
        # in AccountChooser can land in the mailbox while dropping the compose
        # recipient query. authuser targets the configured signed-in account.
        recipient_parameter = "bcc" if len(addresses) > 1 else "to"
        compose_parameters = urllib.parse.urlencode({
            "view": "cm",
            "fs": "1",
            recipient_parameter: ",".join(addresses),
            "authuser": sender_email,
        })
        uri = f"https://mail.google.com/mail/?{compose_parameters}"
        try:
            self.open_url_in_browser(uri)
        except Exception as exc:
            messagebox.showerror("E-posta açılamadı", str(exc), parent=self.root)

    def print_people(self) -> None:
        rows = [[person.get("name", ""), person.get("address", ""), person.get("phone", ""), person.get("email", "")]
                for person in self.store.get("people", [])]
        if not rows:
            messagebox.showinfo("Kişilerim", "Yazdırılacak kişi kaydı yok.", parent=self.root)
            return
        self.create_pdf([], "Kişilerim Listesi", custom_table={
            "kind": "donors", "headers": ["İsim", "Adres", "Telefon", "E-posta"],
            "widths": [0.22, 0.34, 0.18, 0.26], "rows": rows})

    def print_donors(self) -> None:
        rows = []
        for donor in self.store.get("donors", []):
            person = self.person_by_id(donor.get("person_id")) or donor
            rows.append([person.get("name", donor.get("name", "")), person.get("address", donor.get("address", "")),
                         person.get("phone", donor.get("phone", "")), person.get("email", donor.get("email", "")),
                         self.euro(Decimal(str(donor.get("amount") or "0"))) if donor.get("amount") else "—"])
        if not rows:
            messagebox.showinfo("Bağışçılar", "Yazdırılacak bağışçı kaydı yok.", parent=self.root)
            return
        self.create_pdf([], "Bağışçılar Listesi", custom_table={
            "kind": "donors", "headers": ["İsim", "Adres", "Telefon", "E-posta", "Bağış tutarı"],
            "widths": [0.18, 0.24, 0.16, 0.25, 0.17], "rows": rows})

    def print_fixed_donors(self, year: int) -> None:
        month_names = ("Oca", "Şub", "Mar", "Nis", "May", "Haz", "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara")
        rows = []
        for donor in self.store.get("fixed_donors", []):
            year_payments = donor.get("payments", {}).get(str(year), {})
            rows.append([donor.get("name", "")] + [
                "✓" if year_payments.get(str(month), "") == "paid" else
                ("×" if year_payments.get(str(month), "") == "unpaid" else "")
                for month in range(1, 13)])
        if not rows:
            messagebox.showinfo("Sabit bağışçılar", "Yazdırılacak sabit bağışçı yok.", parent=self.root)
            return
        self.create_pdf([], f"Sabit Bağışçılar — {year}", custom_table={
            "kind": "fixed_donors", "headers": ["İsim", *month_names],
            "widths": [0.20] + [0.8 / 12] * 12, "rows": rows})

    def print_custom_table(self, title: str, headers: list[str], rows: list[list[str]],
                           widths: list[float], kind: str) -> None:
        self.create_pdf([], title, custom_table={"kind": kind, "headers": headers, "widths": widths, "rows": rows})

    def _scroll_settings_with_wheel(self, event):
        canvas = self._settings_scroll_canvas
        if canvas is None:
            return
        try:
            widget = self.root.winfo_containing(event.x_root, event.y_root)
            while widget is not None:
                if widget == canvas:
                    canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")
                    return "break"
                widget = getattr(widget, "master", None)
        except tk.TclError:
            self._settings_scroll_canvas = None

    def show_settings(self) -> None:
        outer = tk.Frame(self.content, bg="#f7f9fc")
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg="#f7f9fc", highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        settings_body = tk.Frame(canvas, bg="#f7f9fc")
        body_window = canvas.create_window((0, 0), window=settings_body, anchor="nw")
        self._settings_scroll_canvas = canvas

        def update_scroll_region(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))
            if settings_body.winfo_reqheight() > canvas.winfo_height() + 2:
                if not scrollbar.winfo_ismapped():
                    scrollbar.pack(side="right", fill="y")
            elif scrollbar.winfo_ismapped():
                scrollbar.pack_forget()

        def resize_settings_body(event) -> None:
            canvas.itemconfigure(body_window, width=event.width)
            update_scroll_region()

        settings_body.bind("<Configure>", update_scroll_region, add="+")
        canvas.bind("<Configure>", resize_settings_body, add="+")

        panel = tk.Frame(settings_body, bg="white", padx=20, pady=12, highlightbackground="#d7e1ee", highlightthickness=1)
        panel.pack(anchor="nw", fill="x")
        tk.Label(panel, text="A4 yazdırma ve PDF kaydetme", bg="white", fg="#122a50", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(panel,
                 text="PDF yazdırırken bu klasör dosya adı için başlangıç önerisi olur. Kaydetme konumunu Windows’un kendi penceresinde değiştirebilirsin.",
                 bg="white", fg="#52627a", font=("Segoe UI", 11), wraplength=1120, justify="left").pack(anchor="w", pady=(4, 6))
        tk.Label(panel, text="Gönderici Gmail hesabı", bg="white", fg="#122a50",
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(2, 4))
        sender_email_entry = ttk.Entry(panel, font=("Segoe UI", 11), width=48)
        sender_email_entry.insert(0, str(self.settings.get("sender_email", "")))
        sender_email_entry.pack(anchor="w", fill="x", pady=(0, 6))
        tk.Label(panel, text="Bu adres Google giriş/seçiminde ve Gmail taslağını açarken kullanılır. Şifre programa kaydedilmez.",
                 bg="white", fg="#52627a", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 6))
        path_row = tk.Frame(panel, bg="white")
        path_row.pack(fill="x")
        path_entry = ttk.Entry(path_row, font=("Segoe UI", 11))
        path_entry.insert(0, str(self.settings.get("pdf_directory", Path.home())))
        path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        path_buttons = tk.Frame(path_row, bg="white")
        path_buttons.pack(side="right")

        def choose_folder() -> None:
            current = Path(path_entry.get().strip()).expanduser()
            initial = str(current if current.is_dir() else Path.home())
            selected = filedialog.askdirectory(parent=self.root, title="PDF başlangıç klasörünü seç", initialdir=initial, mustexist=True)
            if selected:
                path_entry.delete(0, "end")
                path_entry.insert(0, selected)

        tk.Button(path_buttons, text="📁 Konum seç", command=choose_folder, bg="#e7f1ff", fg="#0b3d79",
                  relief="raised", bd=2, padx=16, pady=8, font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))

        cover_row = tk.Frame(panel, bg="white")
        cover_row.pack(anchor="w", pady=(8, 0))
        cover_name = Path(str(self.settings.get("cover_image", ""))).name
        cover_label = tk.Label(cover_row, text=f"Açılış kapak resmi: {cover_name}", bg="white", fg="#122a50", font=("Segoe UI", 11, "bold"))
        cover_label.pack(side="left", padx=(0, 8))

        def choose_cover_image() -> None:
            selected = filedialog.askopenfilename(
                parent=self.root, title="Açılışta gösterilecek resmi seç",
                filetypes=[("Resim dosyaları", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff"), ("Tüm dosyalar", "*.*")])
            if not selected:
                return
            custom_path = IMAGE_DIR / "acilis_kapak_kullanici.png"
            temporary_path = IMAGE_DIR / "acilis_kapak_kullanici.tmp"
            old_bytes = custom_path.read_bytes() if custom_path.is_file() else None
            old_settings = SETTINGS_FILE.read_bytes() if SETTINGS_FILE.exists() else None
            old_account = ACCOUNT_FILE.read_bytes() if ACCOUNT_FILE.exists() else None
            previous_setting = self.settings.get("cover_image")
            try:
                IMAGE_DIR.mkdir(parents=True, exist_ok=True)
                with Image.open(selected) as source:
                    source.convert("RGB").save(temporary_path, format="PNG")
                temporary_path.replace(custom_path)
                self.settings["cover_image"] = custom_path.name
                atomic_json_write(SETTINGS_FILE, self.settings)
                account_meta = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
                account_meta["cover_image"] = custom_path.name
                atomic_json_write(ACCOUNT_FILE, account_meta)
            except (OSError, ValueError) as exc:
                temporary_path.unlink(missing_ok=True)
                if old_bytes is None:
                    custom_path.unlink(missing_ok=True)
                else:
                    custom_path.write_bytes(old_bytes)
                if previous_setting is None:
                    self.settings.pop("cover_image", None)
                else:
                    self.settings["cover_image"] = previous_setting
                for target, old_content in ((SETTINGS_FILE, old_settings), (ACCOUNT_FILE, old_account)):
                    try:
                        if old_content is None:
                            target.unlink(missing_ok=True)
                        else:
                            target.write_bytes(old_content)
                    except OSError:
                        pass
                messagebox.showerror("Kapak resmi kaydedilemedi", str(exc), parent=self.root)
                return
            messagebox.showinfo("Kapak resmi kaydedildi",
                                "Seçilen resim açılış ekranında kullanılacak. Değişikliği görmek için programı kapatıp yeniden aç.",
                                parent=self.root)
            cover_label.configure(text=f"Açılış kapak resmi: {custom_path.name}")

        tk.Button(cover_row, text="🖼️ Açılış resmi ekle / değiştir", command=choose_cover_image,
                  bg="#e7f1ff", fg="#0b3d79", relief="raised", bd=2, padx=16, pady=8,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left", padx=(0, 8))

        def save_location() -> None:
            directory = Path(path_entry.get().strip()).expanduser()
            if not directory.is_dir():
                messagebox.showwarning("Klasör bulunamadı", "Var olan bir PC veya USB klasörü seç.", parent=self.root)
                return
            sender_email = sender_email_entry.get().strip()
            if sender_email and not self.is_valid_email(sender_email):
                messagebox.showwarning("E-posta adresi geçersiz", "Gönderici için geçerli bir Gmail adresi yaz.", parent=self.root)
                return
            previous = dict(self.settings)
            self.settings["pdf_directory"] = str(directory.resolve())
            self.settings["sender_email"] = sender_email
            try:
                atomic_json_write(SETTINGS_FILE, self.settings)
            except OSError as exc:
                self.settings.clear()
                self.settings.update(previous)
                messagebox.showerror("Ayar kaydedilemedi", str(exc), parent=self.root)
                return
            messagebox.showinfo("Ayarlar kaydedildi", f"Gönderici Gmail: {sender_email or 'belirtilmedi'}\nPDF klasörü: {directory}", parent=self.root)

        tk.Button(path_buttons, text="Kaydet", command=save_location, bg="#1680e8", fg="white", relief="raised", bd=2,
                  padx=20, pady=9, font=("Segoe UI", 11, "bold")).pack(side="left")

        security_panel = tk.Frame(settings_body, bg="#f4f9ff", padx=20, pady=12,
                                  highlightbackground="#c5daf0", highlightthickness=1)
        security_panel.pack(anchor="nw", fill="x", pady=(10, 0))
        tk.Label(security_panel, text="Hesap güvenliği", bg="#f4f9ff", fg="#123f76",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(security_panel,
                 text="Şifre değişikliği mevcut şifreyi ister. 5 dakika işlem yapılmazsa oturum kilitlenir. Kurtarma kodunu ayrı ve güvenli bir yerde sakla.",
                 bg="#f4f9ff", fg="#52627a", font=("Segoe UI", 10), wraplength=1120,
                 justify="left").pack(anchor="w", pady=(4, 8))
        security_buttons = tk.Frame(security_panel, bg="#f4f9ff")
        security_buttons.pack(anchor="w")
        self.ice_button(security_buttons, "🔑 Şifreyi değiştir", self.change_password).pack(side="left", padx=(0, 10))
        self.ice_button(security_buttons, "♻ Kurtarma kodunu yenile", self.rotate_recovery_code).pack(side="left")

        backup_panel = tk.Frame(settings_body, bg="#f2f8ff", padx=20, pady=12,
                                highlightbackground="#c5daf0", highlightthickness=1)
        backup_panel.pack(anchor="nw", fill="x", pady=(10, 0))
        tk.Label(backup_panel, text="Yedekleme", bg="#f2f8ff", fg="#123f76",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(backup_panel,
                 text="Kişiler, bağışçılar, ödemeler, gelir-gider kayıtları, kategoriler, ayarlar ve giriş hesabı tek bir ZIP dosyasına kaydedilir. Yedek kişisel ve mali bilgiler içerir; güvenli bir PC veya USB klasörü seç.",
                 bg="#f2f8ff", fg="#52627a", font=("Segoe UI", 10), wraplength=1120,
                 justify="left").pack(anchor="w", pady=(4, 8))
        backup_buttons = tk.Frame(backup_panel, bg="#f2f8ff")
        backup_buttons.pack(anchor="w")
        tk.Button(backup_buttons, text="📦  Yedek Al", command=self.backup_all_program_data,
                  bg="#dceeff", fg="#174a83", activebackground="#c6e2ff", relief="raised", bd=2,
                  padx=18, pady=9, font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left", padx=(0, 10))
        tk.Button(backup_buttons, text="↩  Yedekten Geri Al", command=self.restore_program_backup,
                  bg="#e7f4e9", fg="#24633b", activebackground="#d5ebd9", relief="raised", bd=2,
                  padx=18, pady=9, font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left")

        reset_panel = tk.Frame(settings_body, bg="#fff8f8", padx=20, pady=12,
                               highlightbackground="#efb8b8", highlightthickness=1)
        reset_panel.pack(anchor="nw", fill="x", pady=(10, 0))
        tk.Label(reset_panel, text="Tüm program verilerini sıfırla", bg="#fff8f8", fg="#9f1d27",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(reset_panel,
                 text="Kişiler, bağışçılar, ödeme geçmişi, gelir-gider kayıtları, eklenen kategoriler ve ayarlar silinir. Giriş hesabı da kaldırılır; sıfırlamadan sonra yeni kullanıcı adı ve şifre oluşturman gerekir.",
                 bg="#fff8f8", fg="#5c4a4a", font=("Segoe UI", 10), wraplength=1120,
                 justify="left").pack(anchor="w", pady=(4, 8))
        tk.Button(reset_panel, text="🗑  Verileri Sil ve İlk Kuruluma Dön",
                  command=self.reset_all_program_data, bg="#c83b43", fg="white",
                  activebackground="#ad2932", activeforeground="white", relief="raised", bd=2,
                  padx=16, pady=9, font=("Segoe UI", 10, "bold"), cursor="hand2").pack(anchor="w")

    def change_password(self) -> None:
        if self.data_key is None or not self.authenticated:
            messagebox.showerror("Şifre değiştir", "Önce programa giriş yap.", parent=self.root)
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Şifreyi değiştir")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        panel = tk.Frame(dialog, bg="white", padx=22, pady=18)
        panel.pack(fill="both", expand=True)
        tk.Label(panel, text="Mevcut şifreyi doğrula, sonra yeni şifreni iki kez gir.",
                 bg="white", fg="#17325b", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        entries = {}
        for row, (key, label) in enumerate((("current", "Mevcut şifre"), ("new", "Yeni şifre"), ("confirm", "Yeni şifreyi tekrar")), start=1):
            tk.Label(panel, text=label, bg="white", fg="#52627a", font=("Segoe UI", 10)).grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(panel, width=34, show="•")
            entry.grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=5)
            entries[key] = entry

        def save_password() -> None:
            current = entries["current"].get()
            new_password = entries["new"].get()
            confirmation = entries["confirm"].get()
            try:
                account = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                messagebox.showerror("Şifre değiştirilemedi", f"Hesap dosyası okunamadı.\n{exc}", parent=dialog)
                return
            if not password_matches(current, account):
                messagebox.showerror("Mevcut şifre hatalı", "Şifre değişmedi.", parent=dialog)
                entries["current"].delete(0, "end")
                entries["current"].focus_set()
                return
            if len(new_password) < 8:
                messagebox.showwarning("Şifre kısa", "Yeni şifre en az 8 karakter olmalı.", parent=dialog)
                return
            if new_password != confirmation:
                messagebox.showwarning("Şifre eşleşmiyor", "Yeni şifre alanları aynı değil.", parent=dialog)
                return
            credentials = password_record(new_password)
            account.update(credentials)
            account["data_key_wrap"] = wrap_data_key(self.data_key, new_password, "password")
            try:
                atomic_json_write(ACCOUNT_FILE, account)
            except (OSError, RuntimeError) as exc:
                messagebox.showerror("Şifre kaydedilemedi", str(exc), parent=dialog)
                return
            dialog.destroy()
            messagebox.showinfo("Şifre değişti", "Yeni şifrenle bir sonraki girişte oturum aç. Kayıt dosyaları şifreli kalır.", parent=self.root)

        buttons = tk.Frame(panel, bg="white")
        buttons.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        self.ice_button(buttons, "Kaydet", save_password).pack(side="left")
        self.ice_button(buttons, "Vazgeç", dialog.destroy, bg="#eef3fb", fg="#354b68").pack(side="right")
        dialog.grab_set()
        entries["current"].focus_set()

    def rotate_recovery_code(self) -> None:
        if not self.confirm_account_password("kurtarma kodunu yenileme"):
            return
        if self.data_key is None:
            messagebox.showerror("Kurtarma kodu", "Şifreli anahtar bellekte bulunamadı.", parent=self.root)
            return
        try:
            account = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
            new_code, recovery = make_recovery_credentials(self.data_key)
            account["recovery"] = recovery
            atomic_json_write(ACCOUNT_FILE, account)
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            messagebox.showerror("Kod yenilenemedi", str(exc), parent=self.root)
            return
        self.show_recovery_code(new_code, "Yeni kurtarma kodu")
        messagebox.showinfo("Kod yenilendi", "Eski kurtarma kodu artık geçersiz. Yeni kodu güvenli yerde sakla.", parent=self.root)

    def backup_all_program_data(self) -> None:
        destination = filedialog.askdirectory(
            parent=self.root,
            title="Yedeğin kaydedileceği PC veya USB klasörünü seç",
            initialdir=str(Path.home()),
            mustexist=True,
        )
        if not destination:
            return
        folder = Path(destination)
        try:
            archive_path, file_count = self._write_program_backup(folder, "Muhasebe-Yedek")
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            if isinstance(exc, RuntimeError):
                messagebox.showwarning("Yedek alınamadı", str(exc), parent=self.root)
                return
            messagebox.showerror("Yedek alınamadı", f"ZIP yedeği oluşturulamadı.\n{exc}", parent=self.root)
            return
        messagebox.showinfo("Yedek alındı", f"{file_count} dosya yedeklendi:\n{archive_path}", parent=self.root)

    def _write_program_backup(self, folder: Path, name_prefix: str) -> tuple[Path, int]:
        files = sorted(path for path in DATA_DIR.rglob("*")
                       if path.is_file() and not path.name.endswith(".tmp")) if DATA_DIR.exists() else []
        if not files:
            raise RuntimeError("Yedeklenecek program verisi bulunamadı.")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        archive_path = folder / f"{name_prefix}-{stamp}.zip"
        suffix = 2
        while archive_path.exists():
            archive_path = folder / f"{name_prefix}-{stamp}-{suffix}.zip"
            suffix += 1
        try:
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in files:
                    archive.write(path, path.relative_to(APP_DIR))
                archive.writestr(
                    "yedek-bilgisi.txt",
                    f"Basit Ev Muhasebe Programı\nSürüm: {APP_VERSION}\n"
                    f"Yedek zamanı: {datetime.now().isoformat(timespec='seconds')}\n"
                    "Bu yedek kişi ve mali kayıtların yanı sıra giriş hesabı doğrulama dosyasını içerir.\n",
                )
        except (OSError, zipfile.BadZipFile):
            try:
                archive_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return archive_path, len(files)

    def restore_program_backup(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.root, title="Geri yüklenecek şifreli muhasebe ZIP yedeğini seç",
            initialdir=str(Path.home()),
            filetypes=(("Muhasebe ZIP yedeği", "*.zip"), ("Tüm dosyalar", "*.*")),
        )
        if not selected:
            return
        archive_path = Path(selected)
        restored_files: dict[Path, bytes] = {}
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                total_size = 0
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename.replace("\\", "/")
                    parts = name.split("/")
                    if parts[0] != "veriler":
                        continue
                    if len(parts) < 2 or any(part in ("", ".", "..") or ":" in part for part in parts[1:]):
                        raise ValueError("Yedekte güvenli olmayan dosya yolu bulundu.")
                    if info.file_size > 128 * 1024 * 1024:
                        raise ValueError("Yedekte beklenenden büyük bir dosya var; geri yükleme durduruldu.")
                    total_size += info.file_size
                    if total_size > 512 * 1024 * 1024:
                        raise ValueError("Yedek toplam boyutu sınırı aşıyor; geri yükleme durduruldu.")
                    relative = Path(*parts[1:])
                    if relative in restored_files:
                        raise ValueError("Yedekte yinelenen dosya bulundu.")
                    restored_files[relative] = archive.read(info)
        except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
            messagebox.showerror("Yedek okunamadı", f"Seçilen ZIP yedeği açılamadı veya güvenli değil.\n{exc}", parent=self.root)
            return

        account_rel = Path("kullanici.json")
        books_rel = Path("muhasebe_verileri.json")
        settings_rel = Path("ayarlar.json")
        if account_rel not in restored_files or books_rel not in restored_files:
            messagebox.showerror("Yedek uyumsuz", "Bu yedekte hesap veya muhasebe kayıtları eksik.", parent=self.root)
            return
        try:
            account = json.loads(restored_files[account_rel].decode("utf-8"))
            required = ("username", "salt", "hash", "rounds", "data_key_wrap", "recovery")
            if not isinstance(account, dict) or any(key not in account for key in required):
                raise ValueError("Yedek bu şifreli sürümle oluşturulmamış.")
            if not is_encrypted_json(restored_files[books_rel]):
                raise ValueError("Yedek muhasebe dosyası şifreli değil; geri yükleme reddedildi.")
            if settings_rel in restored_files and not is_encrypted_json(restored_files[settings_rel]):
                raise ValueError("Yedek ayar dosyası şifreli değil; geri yükleme reddedildi.")
            restored_key = None
            restored_store = None
            restored_settings = None
            if self.data_key is not None:
                try:
                    restored_store = decode_json_bytes(restored_files[books_rel], books_rel.name, self.data_key)
                    restored_settings = decode_json_bytes(restored_files.get(settings_rel, b"{}"), settings_rel.name, self.data_key)
                    restored_key = self.data_key
                except ValueError:
                    pass
            if restored_key is None:
                code = simpledialog.askstring(
                    "Yedek kurtarma kodu",
                    "Bu yedek başka bir program kopyasından olabilir. Yedeği oluştururken saklanan kurtarma kodunu gir.",
                    parent=self.root)
                if code is None:
                    return
                restored_key = unlock_with_recovery(account, code)
                restored_store = decode_json_bytes(restored_files[books_rel], books_rel.name, restored_key)
                restored_settings = decode_json_bytes(restored_files.get(settings_rel, b"{}"), settings_rel.name, restored_key)
            if not isinstance(restored_store, dict) or not isinstance(restored_store.get("transactions", []), list):
                raise ValueError("Muhasebe veri dosyası geçersiz.")
            if int(restored_store.get("schema_version", 0)) > DATA_SCHEMA:
                raise ValueError("Bu yedek mevcut program sürümünden daha yeni.")
            for key, default in (("categories", ["Bağış", "Aidat", "Kira", "Elektrik", "Su", "Maaş", "Diğer"]),
                                 ("donors", []), ("fixed_donors", []), ("people", []),
                                 ("important_contacts", []), ("transactions", [])):
                restored_store.setdefault(key, default)
            if not isinstance(restored_settings, dict):
                raise ValueError("Ayar dosyası geçersiz.")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError, InvalidTag) as exc:
            messagebox.showerror("Yedek uyumsuz", f"Yedek doğrulanamadı; kayıtlar değiştirilmedi.\n{exc}", parent=self.root)
            return

        warning = (
            f"“{archive_path.name}” içindeki kayıtlar bu programın yerini alacak.\n\n"
            "Mevcut kişiler, bağışçılar, işlemler, ayarlar ve giriş hesabı değiştirilecek. "
            "Önce mevcut durum aynı klasöre güvenlik yedeği olarak kaydedilecek.\n\n"
            f"Yedekteki kullanıcı adı: {account['username']}\n"
            "Devam etmek istiyor musun? Sonrasında yedekteki kullanıcı adı ve şifreyle giriş yapılır."
        )
        if not messagebox.askyesno("Yedekten geri al", warning, icon="warning", parent=self.root):
            return
        if not self.confirm_account_password("yedekten geri yükleme"):
            return
        try:
            safety_backup, _ = self._write_program_backup(archive_path.parent, "Muhasebe-GeriYukleme-Oncesi")
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            messagebox.showerror("Geri yükleme durduruldu", f"Mevcut verilerin güvenlik yedeği alınamadı; kayıtlar değiştirilmedi.\n{exc}", parent=self.root)
            return

        old_files = {path.relative_to(DATA_DIR): path.read_bytes()
                     for path in DATA_DIR.rglob("*") if path.is_file()} if DATA_DIR.exists() else {}
        old_key = self.data_key
        global ACTIVE_DATA_KEY
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            for path in DATA_DIR.rglob("*"):
                if path.is_file():
                    path.unlink()
            for relative, content in restored_files.items():
                if relative in (books_rel, settings_rel):
                    continue
                target = DATA_DIR / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            self.data_key = restored_key
            ACTIVE_DATA_KEY = restored_key
            atomic_json_write(BOOKS_FILE, restored_store)
            atomic_json_write(SETTINGS_FILE, restored_settings)
        except (OSError, RuntimeError) as exc:
            try:
                for path in DATA_DIR.rglob("*"):
                    if path.is_file():
                        path.unlink()
                for relative, content in old_files.items():
                    target = DATA_DIR / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
            except OSError as restore_exc:
                self.data_key = old_key
                ACTIVE_DATA_KEY = old_key
                messagebox.showerror("Geri yükleme hatası", f"Güvenlik kopyası burada:\n{safety_backup}\n\nAyrıntı: {exc}\nGeri alma hatası: {restore_exc}", parent=self.root)
                return
            self.data_key = old_key
            ACTIVE_DATA_KEY = old_key
            messagebox.showerror("Geri yükleme hatası", f"Önceki kayıtlar geri kondu.\n{exc}", parent=self.root)
            return

        self.store = empty_store()
        self.settings = {"cover_image": str(account.get("cover_image", ""))}
        self.selected_email_person_ids.clear()
        messagebox.showinfo("Geri yükleme tamamlandı", f"Yedek geri yüklendi.\n\nMevcut durumun güvenlik kopyası:\n{safety_backup}\n\nŞimdi yedekteki hesapla giriş yap.", parent=self.root)
        self.lock_app()

    def reset_all_program_data(self) -> None:
        global ACTIVE_DATA_KEY
        warning = (
            "Programı ilk kurulum durumuna döndürüyorsun.\n\n"
            "Tüm kişi ve bağışçı kayıtları, gelir-gider işlemleri, ödeme geçmişi, özel kategoriler, "
            "PDF klasörü ve gönderici e-posta ayarı silinecek. Giriş hesabın da kaldırılacak; "
            "sonrasında yeni kullanıcı adı ve şifre oluşturman gerekecek.\n\n"
            "Bu işlem geri alınamaz. Devam etmek istiyor musun?"
        )
        if not messagebox.askyesno("Tüm verileri sil ve sıfırla", warning, icon="warning", parent=self.root):
            return
        if not self.confirm_account_password("tüm program verilerini ve giriş hesabını silme"):
            return

        files = (BOOKS_FILE, SETTINGS_FILE, ACCOUNT_FILE)
        previous = {path: path.read_bytes() if path.exists() else None for path in files}
        fresh_store = {
            "schema_version": DATA_SCHEMA,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "transactions": [],
            "categories": ["Bağış", "Aidat", "Kira", "Elektrik", "Su", "Maaş", "Diğer"],
            "donors": [],
            "fixed_donors": [],
            "people": [],
            "important_contacts": [],
        }
        try:
            atomic_json_write(BOOKS_FILE, fresh_store)
            SETTINGS_FILE.unlink(missing_ok=True)
            ACCOUNT_FILE.unlink(missing_ok=True)
        except OSError as exc:
            restore_errors = []
            for path, content in previous.items():
                try:
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(content)
                except OSError as restore_exc:
                    restore_errors.append(f"{path.name}: {restore_exc}")
            detail = f"\n\nGeri yükleme hatası: {'; '.join(restore_errors)}" if restore_errors else ""
            messagebox.showerror("Sıfırlama yapılamadı", f"Veriler sıfırlanamadı; mevcut dosyalar geri yüklendi.\n{exc}{detail}", parent=self.root)
            return

        self.store = fresh_store
        self.settings.clear()
        self.selected_email_person_ids.clear()
        self.authenticated = False
        self.data_key = None
        ACTIVE_DATA_KEY = None
        messagebox.showinfo("Sıfırlama tamamlandı", "Program ilk kurulum durumuna döndü. Yeni kullanıcı adı ve şifre oluştur.", parent=self.root)
        self.show_login()

    def delete_category(self, category: str) -> None:
        if not messagebox.askyesno("Kategoriyi sil", f"“{category}” kategorisini seçeneklerden silmek istiyor musun?\n\nEski işlemlerdeki kayıtlı kategori adı korunur."):
            return
        categories = self.store.setdefault("categories", [])
        old = categories[:]
        self.store["categories"] = [value for value in categories if value != category]
        try:
            atomic_json_write(BOOKS_FILE, self.store)
        except OSError as exc:
            self.store["categories"] = old
            messagebox.showerror("Kategori silinemedi", str(exc))
            return
        self.show_page("Kategoriler")

    def open_transaction_form(self, transaction_type: str, existing: dict | None = None) -> None:
        form = self.content
        for child in form.winfo_children():
            child.destroy()
        body = ttk.Frame(form, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"{'Kaydı Düzenle' if existing else 'Yeni'} {transaction_type} Kaydı", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 18))
        ttk.Label(body, text="Tarih (YYYY-AA-GG)").grid(row=1, column=0, sticky="w", pady=5)
        day = ttk.Entry(body, width=28)
        day.insert(0, existing.get("date", "") if existing else datetime.now().strftime("%Y-%m-%d"))
        day.grid(row=1, column=1, padx=(12, 0), pady=5)
        self.date_picker_button(body, day).grid(row=1, column=2, padx=(6, 0), pady=5)
        ttk.Label(body, text="Kategori").grid(row=2, column=0, sticky="w", pady=5)
        category = ttk.Combobox(body, values=self.store.get("categories", []), width=25)
        category.set(existing.get("category", "Diğer") if existing else "Diğer")
        category.grid(row=2, column=1, padx=(12, 0), pady=5)
        ttk.Label(body, text="Tutar (€)").grid(row=3, column=0, sticky="w", pady=5)
        amount_entry = ttk.Entry(body, width=28)
        if existing:
            amount_entry.insert(0, str(existing.get("amount", "")))
        amount_entry.grid(row=3, column=1, padx=(12, 0), pady=5)
        ttk.Label(body, text="Açıklama").grid(row=4, column=0, sticky="w", pady=5)
        description = ttk.Entry(body, width=28)
        if existing:
            description.insert(0, existing.get("description", ""))
        description.grid(row=4, column=1, padx=(12, 0), pady=5)

        def save() -> None:
            try:
                datetime.strptime(day.get().strip(), "%Y-%m-%d")
                raw = amount_entry.get().strip().replace("€", "").replace(" ", "")
                raw = raw.replace(".", "").replace(",", ".") if "," in raw else raw
                amount = Decimal(raw).quantize(Decimal("0.01"))
                if amount <= 0:
                    raise InvalidOperation
            except (ValueError, InvalidOperation):
                messagebox.showwarning("Bilgi gerekli", "Geçerli tarih ve sıfırdan büyük tutar gir.", parent=form)
                return
            updated = {"date": day.get().strip(), "type": transaction_type, "category": category.get().strip() or "Diğer", "amount": format(amount, ".2f"), "description": description.get().strip(), "created_at": datetime.now().isoformat(timespec="seconds")}
            previous = existing.copy() if existing else None
            if existing:
                existing.update(updated)
            else:
                self.store.setdefault("transactions", []).append(updated)
            try:
                atomic_json_write(BOOKS_FILE, self.store)
            except OSError as exc:
                if existing:
                    existing.clear()
                    existing.update(previous)
                else:
                    self.store["transactions"].pop()
                messagebox.showerror("Kayıt yapılamadı", str(exc), parent=form)
                return
            self.show_dashboard(self.current_username)

        buttons = ttk.Frame(body)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e", pady=(20, 0))
        self.ice_button(buttons, "← Ana sayfaya dön", lambda: self.show_dashboard(self.current_username)).pack(side="left", padx=5)
        self.ice_button(buttons, "Kaydet", save).pack(side="left", padx=5)
        day.focus_set()
        self.enhance_controls(form)

    def edit_selected_transaction(self) -> None:
        index = getattr(self, "selected_row_index", None)
        if index is None:
            messagebox.showinfo("Kayıt seç", "Düzenlemek için tablodan bir işlem seç.")
            return
        rows = getattr(self, "displayed_records", [])
        if index < len(rows):
            rec = rows[index]
            self.open_transaction_form(rec.get("type", "Gelir"), rec)

    def on_transaction_double_click(self, event) -> None:
        return None

    def add_category(self) -> None:
        for child in self.content.winfo_children():
            child.destroy()
        tk.Label(self.content, text="Yeni Kategori", bg="white", fg="#0b3d79", font=("Segoe UI", 21, "bold")).pack(anchor="w", pady=12)
        entry = ttk.Entry(self.content, width=36)
        entry.pack(anchor="w", pady=10)
        def save_category() -> None:
            value = entry.get().strip()
            if not value:
                messagebox.showwarning("Kategori", "Kategori adı yaz.")
                return
            categories = self.store.setdefault("categories", [])
            if value.casefold() in [x.casefold() for x in categories]:
                messagebox.showwarning("Kategori", "Bu kategori zaten mevcut.")
                return
            categories.append(value)
            atomic_json_write(BOOKS_FILE, self.store)
            self.show_page("Kategoriler")
        tk.Button(self.content, text="Kaydet", command=save_category, bg="#1680e8", fg="white", relief="flat", padx=16, pady=9).pack(anchor="w")
        tk.Button(self.content, text="← Geri", command=lambda: self.show_page("Kategoriler"), bg="#edf3fb", fg="#17325b", relief="solid", padx=16, pady=8).pack(anchor="w", pady=10)
        self.enhance_controls(self.content)

    def show_reports(self) -> None:
        tk.Label(self.content, text="Gelir ve Gider Raporları", bg="#f7f9fc", fg="#122a50",
                 font=("Segoe UI", 23, "bold")).pack(anchor="w", pady=(0, 10))
        controls = tk.Frame(self.content, bg="white", padx=10, pady=9,
                            highlightbackground="#d7e1ee", highlightthickness=1)
        controls.pack(fill="x", pady=(0, 8))
        tk.Label(controls, text="Başlangıç", bg="white", fg="#263a59", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 5))
        start_entry = ttk.Entry(controls, width=12)
        start_entry.insert(0, f"{datetime.now():%Y}-01-01")
        start_entry.pack(side="left")
        self.date_picker_button(controls, start_entry).pack(side="left", padx=(4, 9))
        tk.Label(controls, text="Bitiş", bg="white", fg="#263a59", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 5))
        end_entry = ttk.Entry(controls, width=12)
        end_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))
        end_entry.pack(side="left")
        self.date_picker_button(controls, end_entry).pack(side="left", padx=(4, 9))
        tk.Label(controls, text="Gruplama", bg="white", fg="#263a59", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 5))
        period = ttk.Combobox(controls, values=("Günlük", "Aylık", "Yıllık"), state="readonly", width=9)
        period.set("Günlük")
        period.pack(side="left", padx=(0, 8))
        tk.Button(controls, text="🖨 Yazdır", command=self.print_report, bg="#e7f1ff", fg="#0b3d79",
                  relief="raised", bd=2, padx=14, pady=7, font=("Segoe UI", 10, "bold")).pack(side="right")

        comparison = tk.Frame(self.content, bg="#f7f9fc")
        comparison.pack(fill="x", pady=(0, 7))
        self.report_comparison_vars = {}
        for title, color, pale in (("Gelir · önceki eşit dönemle karşılaştırma", "#07883d", "#e7f7ee"),
                                   ("Gider · önceki eşit dönemle karşılaştırma", "#c92732", "#fff0f0"),
                                   ("Bakiye · önceki eşit dönemle karşılaştırma", "#174a83", "#e8f3ff")):
            card = tk.Frame(comparison, bg=pale, padx=9, pady=7,
                            highlightbackground="#d7e1ee", highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 7))
            tk.Label(card, text=title, bg=pale, fg=color, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            variable = tk.StringVar(value="Rapor oluşturuluyor…")
            self.report_comparison_vars[title] = variable
            tk.Label(card, textvariable=variable, bg=pale, fg="#263a59", font=("Segoe UI", 9),
                     anchor="w", justify="left", wraplength=390).pack(anchor="w", pady=(3, 0))

        donation_summary = tk.Frame(self.content, bg="white", padx=10, pady=7,
                                   highlightbackground="#d7e1ee", highlightthickness=1)
        donation_summary.pack(fill="x", pady=(0, 7))
        tk.Label(donation_summary, text="Bağış kaynağı özeti", bg="white", fg="#122a50",
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 12))
        self.report_donation_var = tk.StringVar(value="Rapor oluşturuluyor…")
        tk.Label(donation_summary, textvariable=self.report_donation_var, bg="white", fg="#263a59",
                 font=("Segoe UI", 9), anchor="w", justify="left").pack(side="left", fill="x", expand=True)

        chart_mode = tk.StringVar(value="Dönem grafiği")
        chart_modes = tk.Frame(self.content, bg="#f7f9fc")
        chart_modes.pack(fill="x", pady=(0, 4))
        chart_mode_buttons = {}
        chart = tk.Canvas(self.content, bg="white", height=205, highlightthickness=1,
                          highlightbackground="#d7e1ee")
        chart.pack(fill="x", pady=(0, 8))

        report_table = ttk.Treeview(self.content, columns=("period", "income", "expense", "balance"),
                                    show="headings", height=4)
        for col, label, width in (("period", "Dönem", 180), ("income", "Gelir", 180),
                                  ("expense", "Gider", 180), ("balance", "Bakiye", 180)):
            report_table.heading(col, text=label)
            report_table.column(col, width=width, anchor="w")
        report_table.pack(fill="x")
        report_table.tag_configure("Gelir", foreground="#07883d")
        report_table.tag_configure("Gider", foreground="#c92732")
        tk.Label(self.content, text="Seçilen dönemin işlem detayları", bg="#f7f9fc", fg="#122a50",
                 font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(7, 3))
        detail = ttk.Treeview(self.content, columns=("date", "type", "category", "description", "amount"),
                              show="headings", height=3)
        for col, label, width in (("date", "Tarih", 115), ("type", "Tür", 90), ("category", "Kategori", 145),
                                  ("description", "Açıklama", 340), ("amount", "Tutar", 145)):
            detail.heading(col, text=label)
            detail.column(col, width=width, anchor="w")
        detail.tag_configure("Gelir", foreground="#07883d")
        detail.tag_configure("Gider", foreground="#c92732")
        detail.pack(fill="both", expand=True)
        buttons = tk.Frame(self.content, bg="#f7f9fc")
        buttons.pack(fill="x", pady=(7, 0))

        def update_chart_mode_buttons() -> None:
            for label, button in chart_mode_buttons.items():
                active = chart_mode.get() == label
                button.configure(bg="#1680e8" if active else "#dff3ff",
                                 fg="white" if active else "#174a72")

        def select_chart_mode(value: str) -> None:
            chart_mode.set(value)
            update_chart_mode_buttons()
            render_report()

        for label in ("Dönem grafiği", "Kategori grafiği"):
            button = self.ice_button(chart_modes, label, lambda value=label: select_chart_mode(value),
                                     padx=13, pady=6, font=("Segoe UI", 9, "bold"))
            button.pack(side="left", padx=(0, 6))
            chart_mode_buttons[label] = button
        update_chart_mode_buttons()

        def format_change(current: Decimal, previous: Decimal) -> str:
            difference = current - previous
            sign = "+" if difference > 0 else ("−" if difference < 0 else "")
            amount_text = f"{sign}{self.euro(abs(difference))}"
            if previous == 0:
                percent = "yeni" if current != 0 else "0%"
            else:
                percentage = difference / abs(previous) * Decimal("100")
                percent = f"{percentage:+.1f}%".replace(".", ",")
            return f"Şimdi {self.euro(current)} · Önce {self.euro(previous)} · {amount_text} ({percent})"

        def render_report() -> None:
            start, end = start_entry.get().strip(), end_entry.get().strip()
            try:
                start_date = datetime.strptime(start, "%Y-%m-%d").date()
                end_date = datetime.strptime(end, "%Y-%m-%d").date()
            except ValueError:
                messagebox.showwarning("Tarih biçimi", "Başlangıç ve bitiş tarihini YYYY-AA-GG biçiminde yaz.", parent=self.root)
                return
            if start_date > end_date:
                messagebox.showwarning("Tarih aralığı", "Başlangıç tarihi bitiş tarihinden sonra olamaz.", parent=self.root)
                return

            filtered = [rec for rec in self.store.get("transactions", [])
                        if start <= str(rec.get("date", "")) <= end]
            self.report_records = filtered
            self.report_period_name = period.get()
            current_income = sum((Decimal(str(rec.get("amount", "0"))) for rec in filtered
                                  if rec.get("type") == "Gelir"), Decimal("0"))
            current_expense = sum((Decimal(str(rec.get("amount", "0"))) for rec in filtered
                                   if rec.get("type") == "Gider"), Decimal("0"))
            duration = end_date - start_date
            previous_end = start_date - timedelta(days=1)
            previous_start = previous_end - duration
            previous_records = [rec for rec in self.store.get("transactions", [])
                                if previous_start.strftime("%Y-%m-%d") <= str(rec.get("date", ""))
                                <= previous_end.strftime("%Y-%m-%d")]
            previous_income = sum((Decimal(str(rec.get("amount", "0"))) for rec in previous_records
                                   if rec.get("type") == "Gelir"), Decimal("0"))
            previous_expense = sum((Decimal(str(rec.get("amount", "0"))) for rec in previous_records
                                    if rec.get("type") == "Gider"), Decimal("0"))
            values_to_compare = (current_income, current_expense, current_income-current_expense,
                                 previous_income, previous_expense, previous_income-previous_expense)
            for (title, variable), current, previous in zip(self.report_comparison_vars.items(),
                                                             values_to_compare[:3], values_to_compare[3:]):
                variable.set(format_change(current, previous))

            donation_groups = {
                "Sabit bağış": [Decimal("0"), 0],
                "Geçici bağış": [Decimal("0"), 0],
                "Diğer bağış": [Decimal("0"), 0],
            }
            for rec in filtered:
                if rec.get("type") != "Gelir" or str(rec.get("category", "")).casefold() != "bağış":
                    continue
                source = str(rec.get("source", ""))
                group = source if source in ("Sabit bağış", "Geçici bağış") else "Diğer bağış"
                donation_groups[group][0] += Decimal(str(rec.get("amount", "0")))
                donation_groups[group][1] += 1
            self.report_donation_var.set("   ·   ".join(
                f"{name}: {self.euro(amount)} / {count} kayıt"
                for name, (amount, count) in donation_groups.items()))

            grouped: dict[str, dict[str, Decimal]] = {}
            for rec in filtered:
                date = str(rec.get("date", ""))
                key = date[:10] if period.get() == "Günlük" else (date[:7] if period.get() == "Aylık" else date[:4])
                needed = 10 if period.get() == "Günlük" else (7 if period.get() == "Aylık" else 4)
                if len(key) < needed or rec.get("type") not in ("Gelir", "Gider"):
                    continue
                grouped.setdefault(key, {"Gelir": Decimal("0"), "Gider": Decimal("0")})
                grouped[key][rec["type"]] += Decimal(str(rec.get("amount", "0")))
            for item in report_table.get_children():
                report_table.delete(item)
            for item in detail.get_children():
                detail.delete(item)
            periods = sorted(grouped)
            self.report_period_summary = [
                {"period": key, "income": grouped[key]["Gelir"], "expense": grouped[key]["Gider"],
                 "balance": grouped[key]["Gelir"] - grouped[key]["Gider"]}
                for key in periods
            ]
            for key in periods:
                values = grouped[key]
                report_table.insert("", "end", values=(key, self.euro(values["Gelir"]),
                                                         self.euro(values["Gider"]),
                                                         self.euro(values["Gelir"]-values["Gider"])))
            for rec in sorted(filtered, key=lambda row: (str(row.get("date", "")),
                                                          str(row.get("created_at", ""))), reverse=True):
                sign = "+" if rec.get("type") == "Gelir" else "−"
                detail.insert("", "end", values=(rec.get("date", ""), rec.get("type", ""),
                                                    rec.get("category", ""), rec.get("description", ""),
                                                    f"{sign} {self.euro(Decimal(str(rec.get('amount', '0'))))}"),
                              tags=(rec.get("type", ""),))

            chart.delete("all")
            chart.update_idletasks()
            width = max(chart.winfo_width(), 700)
            chart.create_text(18, 16, text="● Gelir", anchor="w", fill="#07883d", font=("Segoe UI", 9, "bold"))
            chart.create_text(92, 16, text="● Gider", anchor="w", fill="#c92732", font=("Segoe UI", 9, "bold"))
            if chart_mode.get() == "Kategori grafiği":
                category_totals: dict[str, dict[str, Decimal]] = {}
                for rec in filtered:
                    kind = rec.get("type")
                    if kind not in ("Gelir", "Gider"):
                        continue
                    category = str(rec.get("category", "")).strip() or "Kategorisiz"
                    category_totals.setdefault(category, {"Gelir": Decimal("0"), "Gider": Decimal("0")})
                    category_totals[category][kind] += Decimal(str(rec.get("amount", "0")))
                ordered = sorted(category_totals.items(),
                                 key=lambda pair: pair[1]["Gelir"]+pair[1]["Gider"], reverse=True)
                if len(ordered) > 6:
                    remainder = ordered[5:]
                    merged = {"Gelir": sum((item[1]["Gelir"] for item in remainder), Decimal("0")),
                              "Gider": sum((item[1]["Gider"] for item in remainder), Decimal("0"))}
                    ordered = ordered[:5] + [("Diğer kategoriler", merged)]
                if not ordered:
                    chart.create_text(width//2, 105, text="Bu tarih aralığında kategori kaydı yok.",
                                      fill="#52627a", font=("Segoe UI", 11))
                else:
                    max_value = max(max(totals["Gelir"], totals["Gider"]) for _, totals in ordered) or Decimal("1")
                    max_bar_width = max(100, width - 330)
                    for index, (category, totals) in enumerate(ordered):
                        y = 43 + index * 27
                        label = category if len(category) <= 20 else category[:19] + "…"
                        chart.create_text(14, y+9, text=label, anchor="w", fill="#17325b",
                                          font=("Segoe UI", 9, "bold"))
                        income_width = float(totals["Gelir"] / max_value) * max_bar_width
                        expense_width = float(totals["Gider"] / max_value) * max_bar_width
                        chart.create_rectangle(175, y, 175+max(1, income_width), y+8,
                                               fill="#19a75a", outline="")
                        chart.create_rectangle(175, y+12, 175+max(1, expense_width), y+20,
                                               fill="#e8464d", outline="")
                        chart.create_text(width-12, y+4, text=self.euro(totals["Gelir"]), anchor="e",
                                          fill="#07883d", font=("Segoe UI", 8, "bold"))
                        chart.create_text(width-12, y+16, text=self.euro(totals["Gider"]), anchor="e",
                                          fill="#c92732", font=("Segoe UI", 8, "bold"))
            elif not periods:
                chart.create_text(width//2, 105, text="Bu tarih aralığında işlem bulunamadı.",
                                  fill="#52627a", font=("Segoe UI", 11))
            else:
                max_value = max(max(grouped[key]["Gelir"], grouped[key]["Gider"]) for key in periods) or Decimal("1")
                visible = periods[-12:]
                slot = min(68, max(48, (width-80)/max(1, len(visible))))
                grouped_width = slot*max(0, len(visible)-1)+40
                start_x = max(40, (width-grouped_width)/2)
                baseline, chart_height = 177, 125
                chart.create_line(35, baseline, width-20, baseline, fill="#bbc7d5")
                for index, key in enumerate(visible):
                    x = start_x + index*slot
                    income_h = float(grouped[key]["Gelir"] / max_value) * chart_height
                    expense_h = float(grouped[key]["Gider"] / max_value) * chart_height
                    chart.create_rectangle(x, baseline-income_h, x+18, baseline, fill="#19a75a", outline="")
                    chart.create_rectangle(x+22, baseline-expense_h, x+40, baseline, fill="#e8464d", outline="")
                    chart.create_text(x+20, baseline+13, text=key, fill="#17325b", font=("Segoe UI", 8, "bold"))

        tk.Button(buttons, text="📊 Raporu oluştur", command=render_report, bg="#1680e8", fg="white",
                  relief="groove", bd=2, padx=14, pady=8, font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Button(buttons, text="▣ Raporu PDF yazdır", command=self.print_report, bg="#ffffff", fg="#17325b",
                  relief="groove", bd=2, padx=14, pady=8, font=("Segoe UI", 10, "bold")).pack(side="left", padx=8)
        tk.Button(buttons, text="↺ Temizle", command=lambda: (
            start_entry.delete(0, "end"), end_entry.delete(0, "end"),
            start_entry.insert(0, f"{datetime.now():%Y}-01-01"),
            end_entry.insert(0, datetime.now().strftime("%Y-%m-%d")),
            period.set("Günlük"), chart_mode.set("Dönem grafiği"), update_chart_mode_buttons(), render_report()),
                  bg="#eef3fb", fg="#17325b", relief="raised", bd=2, padx=14, pady=8,
                  font=("Segoe UI", 10, "bold")).pack(side="right")
        render_report()
        self.enhance_controls(self.content)

    def print_report(self) -> None:
        records = getattr(self, "report_records", [])
        summary = getattr(self, "report_period_summary", [])
        period = getattr(self, "report_period_name", "Günlük")
        self.create_pdf(records, f"{period} Gelir-Gider Raporu", summary)


def main() -> None:
    root = tk.Tk()
    AccountingDemo(root)
    root.mainloop()


if __name__ == "__main__":
    main()






