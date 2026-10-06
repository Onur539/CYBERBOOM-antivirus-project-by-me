# ============================================================
# CYBERBOOM 3.0
# Modern Windows Static Security Scanner
#
# Python 3.10+
# Harici paket yok
# Defender yok
# tkinterdnd2 yok
# Dosya çalıştırmaz
# Dosya değiştirmez
#
# Özellikler:
# - CyberSürükle
# - CyberHızlı
# - Tam Sistem
# - Dosya Tara
# - Klasör Tara
# - Durdur
# - SHA-256
# - PE analizi
# - String/API göstergeleri
# - Entropy
# - Şüpheli davranış açıklaması
# - Thread-safe GUI
# - Kontrollü worker sistemi
# - Güvenli kapanış
# ============================================================

import os
import re
import sys
import json
import math
import time
import queue
import ctypes
import hashlib
import threading

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from pathlib import Path
from datetime import datetime


# ============================================================
# UYGULAMA
# ============================================================

APP_NAME = "CyberBoom"
VERSION = "3.0"

WINDOW_WIDTH = 1200
WINDOW_HEIGHT = 780

BASE_DIR = Path.home() / "CyberBoom"
HISTORY_FILE = BASE_DIR / "history.json"

BASE_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# RENKLER
# ============================================================

BG = "#070b14"
PANEL = "#0d1524"
PANEL2 = "#111d31"
PANEL3 = "#172640"

WHITE = "#f5f8ff"
MUTED = "#8290a8"

BLUE = "#3d82ff"
CYAN = "#38d9ff"
GREEN = "#21dda0"
YELLOW = "#ffc857"
RED = "#ff4d67"
PURPLE = "#a678ff"

BORDER = "#243651"


# ============================================================
# WINDOWS DRAG & DROP
# ============================================================

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:

    from ctypes import wintypes

    WM_DROPFILES = 0x0233
    GWL_WNDPROC = -4

    WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_longlong,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_int64
    )

    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32

    DragAcceptFiles = shell32.DragAcceptFiles
    DragQueryFileW = shell32.DragQueryFileW
    DragFinish = shell32.DragFinish

    SetWindowLongPtrW = user32.SetWindowLongPtrW
    CallWindowProcW = user32.CallWindowProcW


# ============================================================
# UZANTILAR
# ============================================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".ocx",
    ".com",
    ".msi"
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta"
}

SKIP_DIRECTORIES = {
    "$recycle.bin",
    "system volume information",
    "$windows.~bt",
    "$windows.~ws",
    "windows.old"
}


# ============================================================
# DAVRANIŞ GÖSTERGELERİ
# ============================================================

INDICATORS = [

    # NETWORK
    (
        b"winhttp",
        "Ağ iletişimi",
        "Windows HTTP iletişim API'si göstergesi bulundu.",
        2
    ),

    (
        b"wininet",
        "Ağ iletişimi",
        "Windows Internet API'si göstergesi bulundu.",
        2
    ),

    (
        b"urldownloadtofile",
        "Dosya indirme",
        "İnternetten dosya indirme API'si göstergesi bulundu.",
        3
    ),

    (
        b"urlmon",
        "Uzaktan içerik",
        "Uzaktan içerik alma mekanizmasıyla ilişkili gösterge bulundu.",
        2
    ),

    (
        b"downloadstring",
        "Uzaktan içerik",
        "Uzak içerik indirme davranışına işaret eden ifade bulundu.",
        3
    ),

    # PROCESS
    (
        b"createprocess",
        "Process oluşturma",
        "Yeni process oluşturmayla ilişkili API göstergesi bulundu.",
        2
    ),

    (
        b"openprocess",
        "Process erişimi",
        "Başka process'e erişim API'si göstergesi bulundu.",
        3
    ),

    (
        b"writeprocessmemory",
        "Process belleği",
        "Başka process belleğine yazma API'si göstergesi bulundu.",
        4
    ),

    (
        b"createremotethread",
        "Uzak thread",
        "Başka process içinde thread oluşturma göstergesi bulundu.",
        4
    ),

    (
        b"virtualallocex",
        "Uzak bellek",
        "Başka process belleği tahsisiyle ilişkili gösterge bulundu.",
        3
    ),

    # POWERSHELL / SCRIPT
    (
        b"powershell",
        "PowerShell",
        "PowerShell kullanımıyla ilişkili ifade bulundu.",
        1
    ),

    (
        b"-encodedcommand",
        "Kodlanmış PowerShell",
        "Kodlanmış PowerShell komutu göstergesi bulundu.",
        4
    ),

    (
        b"invoke-expression",
        "Dinamik çalıştırma",
        "Dinamik PowerShell kodu çalıştırma göstergesi bulundu.",
        4
    ),

    (
        b"wscript.shell",
        "Windows Script Host",
        "Windows komut ortamına erişim göstergesi bulundu.",
        3
    ),

    (
        b"mshta",
        "MSHTA",
        "MSHTA çalıştırma mekanizması göstergesi bulundu.",
        3
    ),

    # PERSISTENCE
    (
        b"currentversion\\run",
        "Başlangıç kalıcılığı",
        "Windows Run anahtarıyla ilişkili gösterge bulundu.",
        4
    ),

    (
        b"currentversion/run",
        "Başlangıç kalıcılığı",
        "Windows başlangıç kalıcılığıyla ilişkili gösterge bulundu.",
        4
    ),

    # DISCOVERY
    (
        b"systeminfo",
        "Sistem keşfi",
        "Sistem bilgisi toplama komutu göstergesi bulundu.",
        1
    ),

    (
        b"ipconfig",
        "Ağ keşfi",
        "Ağ yapılandırması sorgulama göstergesi bulundu.",
        1
    ),

    (
        b"whoami",
        "Kullanıcı keşfi",
        "Mevcut kullanıcıyı öğrenme göstergesi bulundu.",
        1
    ),

    # SYSTEM TOOLS
    (
        b"regsvr32",
        "DLL çalıştırma",
        "regsvr32 kullanımına ilişkin gösterge bulundu.",
        3
    ),

    (
        b"rundll32",
        "DLL çalıştırma",
        "rundll32 kullanımına ilişkin gösterge bulundu.",
        3
    ),

    (
        b"certutil",
        "Sistem aracı",
        "Windows certutil aracıyla ilişkili ifade bulundu.",
        2
    ),

    (
        b"bitsadmin",
        "Arka plan indirme",
        "BITS indirme mekanizması göstergesi bulundu.",
        3
    ),

    # CREDENTIAL
    (
        b"lsass",
        "Credential erişimi",
        "Windows kimlik doğrulama süreciyle ilişkili ifade bulundu.",
        3
    ),

    (
        b"sekurlsa",
        "Credential erişimi",
        "Credential erişimiyle ilişkili bilinen bileşen adı bulundu.",
        5
    ),

    (
        b"mimikatz",
        "Credential aracı",
        "Bilinen credential aracı adı bulundu.",
        7
    )
]


# ============================================================
# SCAN RESULT
# ============================================================

class ScanResult:

    def __init__(self, path):

        self.path = str(path)

        self.size = 0
        self.sha256 = ""

        self.extension = (
            Path(path)
            .suffix
            .lower()
        )

        self.score = 0

        self.categories = []

        self.indicators = []

        self.errors = []

        self.is_pe = False
        self.architecture = ""

        self.entropy = 0.0

        self.base64_blocks = 0

        self.suspicious = False

        self.high_risk = False

    def add(
        self,
        category,
        explanation,
        score
    ):

        self.score += score

        if category not in self.categories:

            self.categories.append(
                category
            )

        self.indicators.append({
            "category": category,
            "explanation": explanation,
            "score": score
        })

    def finalize(self):

        self.suspicious = (
            self.score >= 8
        )

        strong = {
            "Credential aracı",
            "Credential erişimi",
            "Uzak thread",
            "Process belleği",
            "Kodlanmış PowerShell"
        }

        self.high_risk = any(
            x in self.categories
            for x in strong
        )


# ============================================================
# SCANNER ENGINE
# ============================================================

class ScannerEngine:

    def __init__(
        self,
        stop_event
    ):

        self.stop_event = stop_event

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    def hash_file(
        self,
        path,
        result
    ):

        sha = hashlib.sha256()

        try:

            with open(
                path,
                "rb"
            ) as f:

                while True:

                    if self.stop_event.is_set():
                        return

                    data = f.read(
                        1024 * 1024
                    )

                    if not data:
                        break

                    sha.update(
                        data
                    )

            result.sha256 = sha.hexdigest()

        except Exception as e:

            result.errors.append(
                str(e)
            )

    # --------------------------------------------------------
    # ENTROPY
    # --------------------------------------------------------

    def entropy(
        self,
        data
    ):

        if not data:
            return 0

        counts = [0] * 256

        for byte in data:
            counts[byte] += 1

        length = len(data)

        value = 0.0

        for count in counts:

            if count == 0:
                continue

            p = count / length

            value -= (
                p *
                math.log2(p)
            )

        return value

    # --------------------------------------------------------
    # PE
    # --------------------------------------------------------

    def analyze_pe(
        self,
        path,
        result
    ):

        try:

            with open(
                path,
                "rb"
            ) as f:

                dos = f.read(
                    64
                )

                if len(dos) < 64:
                    return

                if dos[:2] != b"MZ":
                    return

                pe_offset = int.from_bytes(
                    dos[60:64],
                    "little"
                )

                if pe_offset <= 0:
                    return

                if pe_offset > 10_000_000:
                    return

                f.seek(
                    pe_offset
                )

                if f.read(4) != b"PE\x00\x00":
                    return

                result.is_pe = True

                coff = f.read(
                    20
                )

                if len(coff) != 20:
                    return

                machine = int.from_bytes(
                    coff[0:2],
                    "little"
                )

                section_count = int.from_bytes(
                    coff[2:4],
                    "little"
                )

                optional_size = int.from_bytes(
                    coff[16:18],
                    "little"
                )

                if machine == 0x14C:

                    result.architecture = "x86"

                elif machine == 0x8664:

                    result.architecture = "x64"

                elif machine == 0xAA64:

                    result.architecture = "ARM64"

                else:

                    result.architecture = (
                        f"0x{machine:X}"
                    )

                optional = f.read(
                    optional_size
                )

                if len(optional) >= 2:

                    magic = int.from_bytes(
                        optional[:2],
                        "little"
                    )

                    if magic not in (
                        0x10B,
                        0x20B
                    ):

                        result.add(
                            "Bozuk PE",
                            "PE başlığı beklenen biçimle eşleşmiyor.",
                            3
                        )

                # İlk 1 MB
                f.seek(0)

                sample = f.read(
                    1024 * 1024
                )

                result.entropy = self.entropy(
                    sample
                )

                if (
                    result.entropy >= 7.5
                ):

                    result.add(
                        "Yüksek entropy",
                        "Dosyanın örnek bölümünde yüksek entropy bulundu. "
                        "Bu durum sıkıştırılmış veya paketlenmiş veriyle "
                        "uyumlu olabilir.",
                        2
                    )

                # Sections
                for _ in range(
                    min(section_count, 96)
                ):

                    section = f.read(
                        40
                    )

                    if len(section) != 40:
                        break

                    name = (
                        section[:8]
                        .rstrip(b"\x00")
                        .decode(
                            "ascii",
                            errors="replace"
                        )
                    )

                    characteristics = int.from_bytes(
                        section[36:40],
                        "little"
                    )

                    executable = bool(
                        characteristics &
                        0x20000000
                    )

                    writable = bool(
                        characteristics &
                        0x80000000
                    )

                    if executable and writable:

                        result.add(
                            "RWX PE section",
                            f"{name} bölümü yazılabilir ve "
                            "çalıştırılabilir olarak işaretlenmiş.",
                            3
                        )

        except Exception as e:

            result.errors.append(
                str(e)
            )

    # --------------------------------------------------------
    # CONTENT
    # --------------------------------------------------------

    def analyze_content(
        self,
        path,
        result
    ):

        try:

            with open(
                path,
                "rb"
            ) as f:

                data = f.read(
                    16 * 1024 * 1024
                )

            lower = data.lower()

            for (
                pattern,
                category,
                explanation,
                score
            ) in INDICATORS:

                if self.stop_event.is_set():
                    return

                if pattern in lower:

                    result.add(
                        category,
                        explanation,
                        score
                    )

            # Base64-like
            try:

                text = data.decode(
                    "latin1",
                    errors="ignore"
                )

                matches = re.findall(
                    r"(?<![A-Za-z0-9+/])"
                    r"[A-Za-z0-9+/]{160,}={0,2}"
                    r"(?![A-Za-z0-9+/])",
                    text
                )

                result.base64_blocks = len(
                    matches
                )

                if result.base64_blocks >= 2:

                    result.add(
                        "Obfuscation göstergesi",
                        "Uzun Base64 benzeri veri blokları bulundu. "
                        "Bunlar kodlanmış veya gömülü veri olabilir.",
                        2
                    )

            except Exception:
                pass

        except Exception as e:

            result.errors.append(
                str(e)
            )

    # --------------------------------------------------------
    # MAIN ANALYSIS
    # --------------------------------------------------------

    def analyze(
        self,
        path
    ):

        result = ScanResult(
            path
        )

        if self.stop_event.is_set():
            return result

        try:

            result.size = os.path.getsize(
                path
            )

        except Exception as e:

            result.errors.append(
                str(e)
            )

            return result

        # Hash
        self.hash_file(
            path,
            result
        )

        if self.stop_event.is_set():
            return result

        # PE
        if result.extension in EXECUTABLE_EXTENSIONS:

            self.analyze_pe(
                path,
                result
            )

        if self.stop_event.is_set():
            return result

        # Content
        self.analyze_content(
            path,
            result
        )

        # Script
        if result.extension in SCRIPT_EXTENSIONS:

            result.add(
                "Script dosyası",
                "Dosya bir script türünde. Script dosyaları "
                "sistem komutları çalıştırabilir.",
                1
            )

        result.finalize()

        return result


# ============================================================
# DOSYA KUYRUĞU
# ============================================================

class FileCollector:

    def __init__(
        self,
        stop_event
    ):

        self.stop_event = stop_event

    def collect(
        self,
        roots,
        quick=False
    ):

        for root in roots:

            if self.stop_event.is_set():
                return

            root = os.path.abspath(
                root
            )

            if os.path.isfile(root):

                yield root
                continue

            if not os.path.isdir(root):
                continue

            # scandir tabanlı kontrollü traversal
            yield from self.walk(
                root,
                quick
            )

    def walk(
        self,
        root,
        quick=False
    ):

        stack = [root]

        while stack:

            if self.stop_event.is_set():
                return

            current = stack.pop()

            try:

                with os.scandir(
                    current
                ) as entries:

                    for entry in entries:

                        if self.stop_event.is_set():
                            return

                        try:

                            if entry.is_dir(
                                follow_symlinks=False
                            ):

                                name = entry.name.lower()

                                if name in SKIP_DIRECTORIES:
                                    continue

                                # Hızlı taramada bazı dev klasörleri atla
                                if quick and name in {
                                    "node_modules",
                                    ".git",
                                    "__pycache__"
                                }:
                                    continue

                                stack.append(
                                    entry.path
                                )

                            elif entry.is_file(
                                follow_symlinks=False
                            ):

                                yield entry.path

                        except (
                            PermissionError,
                            OSError
                        ):

                            continue

            except (
                PermissionError,
                OSError
            ):

                continue


# ============================================================
# GUI
# ============================================================

class CyberBoomApp:

    def __init__(
        self,
        root
    ):

        self.root = root

        self.root.title(
            f"{APP_NAME} {VERSION}"
        )

        self.root.geometry(
            f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}"
        )

        self.root.minsize(
            1050,
            680
        )

        self.root.configure(
            bg=BG
        )

        # ----------------------------------------------------
        # STATE
        # ----------------------------------------------------

        self.stop_event = threading.Event()

        self.worker_thread = None

        self.collector_thread = None

        self.events = queue.Queue(
            maxsize=200
        )

        self.running = False

        self.closing = False

        self.mode = ""

        self.total_seen = 0
        self.total_scanned = 0

        self.current_file = ""

        self.results_found = 0

        self.start_time = 0

        self.build_ui()

        self.install_drop()

        # UI event loop
        self.root.after(
            100,
            self.process_events
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )

    # ========================================================
    # UI
    # ========================================================

    def build_ui(
        self
    ):

        # HEADER
        header = tk.Frame(
            self.root,
            bg=BG
        )

        header.pack(
            fill="x",
            padx=30,
            pady=(24, 10)
        )

        tk.Label(
            header,
            text="CyberBoom",
            font=(
                "Segoe UI",
                30,
                "bold"
            ),
            bg=BG,
            fg=WHITE
        ).pack(
            side="left"
        )

        tk.Label(
            header,
            text="  SECURITY CENTER",
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            bg=BG,
            fg=CYAN
        ).pack(
            side="left",
            pady=15
        )

        self.status = tk.Label(
            header,
            text="● READY",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg=BG,
            fg=GREEN
        )

        self.status.pack(
            side="right",
            pady=12
        )

        # MAIN PANEL
        main = tk.Frame(
            self.root,
            bg=PANEL
        )

        main.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=10
        )

        # LEFT
        left = tk.Frame(
            main,
            bg=PANEL
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=25,
            pady=25
        )

        # DROP AREA
        self.drop_area = tk.Frame(
            left,
            bg=PANEL2,
            height=190,
            highlightthickness=1,
            highlightbackground=BORDER
        )

        self.drop_area.pack(
            fill="x"
        )

        self.drop_area.pack_propagate(
            False
        )

        tk.Label(
            self.drop_area,
            text="CYBERSÜRÜKLE",
            font=(
                "Segoe UI",
                20,
                "bold"
            ),
            bg=PANEL2,
            fg=WHITE
        ).pack(
            pady=(38, 7)
        )

        tk.Label(
            self.drop_area,
            text=(
                "Dosya veya klasörü pencereye bırak\n"
                "statik güvenlik analizi otomatik başlasın"
            ),
            font=(
                "Segoe UI",
                10
            ),
            bg=PANEL2,
            fg=MUTED
        ).pack()

        # BUTTONS
        buttons = tk.Frame(
            left,
            bg=PANEL
        )

        buttons.pack(
            fill="x",
            pady=22
        )

        self.quick_button = self.button(
            buttons,
            "⚡ CyberHızlı",
            self.quick_scan,
            BLUE
        )

        self.quick_button.pack(
            side="left",
            padx=(0, 8)
        )

        self.full_button = self.button(
            buttons,
            "🛡 Tam Sistem",
            self.full_scan,
            GREEN
        )

        self.full_button.pack(
            side="left",
            padx=8
        )

        self.file_button = self.button(
            buttons,
            "📄 Dosya Tara",
            self.file_scan,
            PANEL3
        )

        self.file_button.pack(
            side="left",
            padx=8
        )

        self.folder_button = self.button(
            buttons,
            "📁 Klasör Tara",
            self.folder_scan,
            PANEL3
        )

        self.folder_button.pack(
            side="left",
            padx=8
        )

        self.stop_button = self.button(
            buttons,
            "■ Durdur",
            self.stop_scan,
            RED
        )

        self.stop_button.pack(
            side="right"
        )

        self.stop_button.config(
            state="disabled"
        )

        # PROGRESS
        self.progress_text = tk.Label(
            left,
            text="Hazır",
            font=(
                "Segoe UI",
                10
            ),
            bg=PANEL,
            fg=MUTED,
            anchor="w"
        )

        self.progress_text.pack(
            fill="x"
        )

        style = ttk.Style()

        try:
            style.theme_use(
                "clam"
            )
        except Exception:
            pass

        style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor="#202e46",
            background=BLUE,
            lightcolor=BLUE,
            darkcolor=BLUE,
            bordercolor="#202e46"
        )

        self.progress = ttk.Progressbar(
            left,
            style="Cyber.Horizontal.TProgressbar",
            maximum=100,
            value=0
        )

        self.progress.pack(
            fill="x",
            pady=(7, 15)
        )

        self.current = tk.Label(
            left,
            text="Tarama başlatılmadı",
            font=(
                "Segoe UI",
                9
            ),
            bg=PANEL,
            fg=MUTED,
            anchor="w"
        )

        self.current.pack(
            fill="x"
        )

        # RIGHT REPORT
        right = tk.Frame(
            main,
            bg="#09111f",
            width=350
        )

        right.pack(
            side="right",
            fill="y",
            padx=(0, 25),
            pady=25
        )

        right.pack_propagate(
            False
        )

        tk.Label(
            right,
            text="ANALİZ DURUMU",
            font=(
                "Segoe UI",
                10,
                "bold"
            ),
            bg="#09111f",
            fg=CYAN
        ).pack(
            anchor="w",
            padx=20,
            pady=(22, 5)
        )

        self.report_title = tk.Label(
            right,
            text="Hazır",
            font=(
                "Segoe UI",
                17,
                "bold"
            ),
            bg="#09111f",
            fg=WHITE,
            wraplength=300,
            justify="left"
        )

        self.report_title.pack(
            anchor="w",
            padx=20,
            pady=10
        )

        self.report = tk.Text(
            right,
            bg="#09111f",
            fg=MUTED,
            font=(
                "Segoe UI",
                9
            ),
            relief="flat",
            bd=0,
            wrap="word"
        )

        self.report.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        self.report.config(
            state="disabled"
        )

    # ========================================================
    # BUTTON
    # ========================================================

    def button(
        self,
        parent,
        text,
        command,
        color
    ):

        return tk.Button(
            parent,
            text=text,
            command=command,
            font=(
                "Segoe UI",
                9,
                "bold"
            ),
            bg=color,
            fg="white",
            activebackground=color,
            activeforeground="white",
            relief="flat",
            bd=0,
            width=13,
            height=2,
            cursor="hand2"
        )

    # ========================================================
    # DRAG & DROP
    # ========================================================

    def install_drop(
        self
    ):

        if not IS_WINDOWS:
            return

        try:

            hwnd = self.root.winfo_id()

            DragAcceptFiles(
                hwnd,
                True
            )

            self.drop_proc = WNDPROC(
                self.window_proc
            )

            self.old_proc = SetWindowLongPtrW(
                hwnd,
                GWL_WNDPROC,
                self.drop_proc
            )

        except Exception:

            self.old_proc = None

    def window_proc(
        self,
        hwnd,
        msg,
        wparam,
        lparam
    ):

        if msg == WM_DROPFILES:

            try:

                count = DragQueryFileW(
                    wparam,
                    0xFFFFFFFF,
                    None,
                    0
                )

                paths = []

                for i in range(
                    count
                ):

                    length = DragQueryFileW(
                        wparam,
                        i,
                        None,
                        0
                    )

                    buffer = ctypes.create_unicode_buffer(
                        length + 1
                    )

                    DragQueryFileW(
                        wparam,
                        i,
                        buffer,
                        length + 1
                    )

                    paths.append(
                        buffer.value
                    )

                DragFinish(
                    wparam
                )

                self.root.after(
                    0,
                    lambda p=paths:
                    self.drop_scan(p)
                )

                return 0

            except Exception:
                pass

        if self.old_proc:

            return CallWindowProcW(
                self.old_proc,
                hwnd,
                msg,
                wparam,
                lparam
            )

        return user32.DefWindowProcW(
            hwnd,
            msg,
            wparam,
            lparam
        )

    def drop_scan(
        self,
        paths
    ):

        if self.running:
            return

        self.start(
            paths,
            "CyberSürükle"
        )

    # ========================================================
    # SELECTION
    # ========================================================

    def file_scan(
        self
    ):

        if self.running:
            return

        path = filedialog.askopenfilename(
            title="CyberBoom - Dosya seç"
        )

        if path:

            self.start(
                [path],
                "Tek Dosya"
            )

    def folder_scan(
        self
    ):

        if self.running:
            return

        path = filedialog.askdirectory(
            title="CyberBoom - Klasör seç"
        )

        if path:

            self.start(
                [path],
                "Klasör"
            )

    # ========================================================
    # QUICK
    # ========================================================

    def quick_scan(
        self
    ):

        if self.running:
            return

        home = Path.home()

        folders = [
            home / "Desktop",
            home / "Downloads",
            home / "Documents"
        ]

        temp = os.environ.get(
            "TEMP"
        )

        if temp:
            folders.append(
                Path(temp)
            )

        self.start(
            [
                str(x)
                for x in folders
                if x.exists()
            ],
            "CyberHızlı",
            quick=True
        )

    # ========================================================
    # FULL
    # ========================================================

    def full_scan(
        self
    ):

        if self.running:
            return

        if not IS_WINDOWS:

            messagebox.showerror(
                "CyberBoom",
                "Tam sistem modu Windows içindir."
            )

            return

        self.start(
            [r"C:\\"],
            "Tam Sistem"
        )

    # ========================================================
    # START
    # ========================================================

    def start(
        self,
        roots,
        mode,
        quick=False
    ):

        if self.running:
            return

        self.stop_event.clear()

        self.running = True

        self.mode = mode

        self.total_seen = 0
        self.total_scanned = 0

        self.results_found = 0

        self.current_file = ""

        self.start_time = time.monotonic()

        self.progress["value"] = 0

        self.progress_text.config(
            text=f"{mode} hazırlanıyor..."
        )

        self.current.config(
            text="Dosya kuyruğu oluşturuluyor..."
        )

        self.status.config(
            text="● SCANNING",
            fg=BLUE
        )

        self.report_title.config(
            text="Tarama devam ediyor"
        )

        self.set_report(
            "CyberBoom dosyaları çalıştırmadan "
            "statik olarak analiz ediyor.\n\n"
            "Pencere aktif kalmaya devam eder."
        )

        self.set_buttons(
            False
        )

        self.stop_button.config(
            state="normal"
        )

        # Worker
        self.worker_thread = threading.Thread(
            target=self.worker,
            args=(
                roots,
                quick
            ),
            daemon=True
        )

        self.worker_thread.start()

    # ========================================================
    # WORKER
    # ========================================================

    def worker(
        self,
        roots,
        quick
    ):

        engine = ScannerEngine(
            self.stop_event
        )

        collector = FileCollector(
            self.stop_event
        )

        try:

            for path in collector.collect(
                roots,
                quick
            ):

                if self.stop_event.is_set():
                    break

                # Dosyayı GUI'ye doğrudan göndermiyoruz.
                # Event kuyruğuna sınırlı sayıda event koyuyoruz.

                result = engine.analyze(
                    path
                )

                if self.stop_event.is_set():
                    break

                self.total_seen += 1

                if result.suspicious:

                    self.results_found += 1

                    self.put_event(
                        (
                            "THREAT",
                            result
                        )
                    )

                    self.stop_event.set()

                    return

                self.total_scanned += 1

                # UI event flood engeli
                if (
                    self.total_scanned % 20 == 0
                ):

                    self.put_event(
                        (
                            "PROGRESS",
                            self.total_scanned,
                            path
                        )
                    )

            if self.stop_event.is_set():

                self.put_event(
                    (
                        "STOPPED",
                        self.total_scanned
                    )
                )

            else:

                self.put_event(
                    (
                        "DONE",
                        self.total_scanned
                    )
                )

        except Exception as e:

            self.put_event(
                (
                    "ERROR",
                    str(e)
                )
            )

    # ========================================================
    # EVENT QUEUE
    # ========================================================

    def put_event(
        self,
        event
    ):

        try:

            self.events.put_nowait(
                event
            )

        except queue.Full:

            # GUI geride kaldıysa progress eventini
            # kaybetmek problem değil.
            pass

    def process_events(
        self
    ):

        if self.closing:
            return

        processed = 0

        # Tek UI tick'te maksimum 30 event
        # Böylece GUI kuyruğu büyüyemez.

        while processed < 30:

            try:

                event = self.events.get_nowait()

            except queue.Empty:

                break

            processed += 1

            kind = event[0]

            if kind == "PROGRESS":

                count = event[1]
                path = event[2]

                self.total_scanned = count

                self.current_file = path

                elapsed = (
                    time.monotonic()
                    - self.start_time
                )

                speed = (
                    count / elapsed
                    if elapsed > 0
                    else 0
                )

                self.progress_text.config(
                    text=(
                        f"{self.mode}  •  "
                        f"{count:,} dosya  •  "
                        f"{speed:.1f} dosya/sn"
                    )
                )

                self.current.config(
                    text=path
                )

                # Belirsiz toplamda indeterminate
                self.progress.config(
                    mode="indeterminate"
                )

                if not self.progress.instate(
                    ("paused",)
                ):

                    self.progress.start(
                        8
                    )

            elif kind == "THREAT":

                result = event[1]

                self.handle_threat(
                    result
                )

            elif kind == "DONE":

                self.handle_done(
                    event[1]
                )

            elif kind == "STOPPED":

                self.handle_stopped(
                    event[1]
                )

            elif kind == "ERROR":

                self.handle_error(
                    event[1]
                )

        self.root.after(
            100,
            self.process_events
        )

    # ========================================================
    # THREAT
    # ========================================================

    def handle_threat(
        self,
        result
    ):

        self.running = False

        self.progress.stop()

        self.progress.config(
            mode="determinate",
            value=100
        )

        self.status.config(
            text="● ANALYSIS ALERT",
            fg=RED
        )

        self.report_title.config(
            text="⚠ Şüpheli göstergeler bulundu"
        )

        self.current.config(
            text=result.path
        )

        self.set_buttons(
            True
        )

        self.stop_button.config(
            state="disabled"
        )

        self.set_report(
            self.make_report(
                result
            )
        )

        messagebox.showwarning(
            "CyberBoom",
            "Şüpheli davranış göstergeleri bulundu.\n\n"
            "Tarama durduruldu.\n\n"
            "Dosya çalıştırılmadı ve değiştirilmedi."
        )

    # ========================================================
    # DONE
    # ========================================================

    def handle_done(
        self,
        count
    ):

        self.running = False

        self.progress.stop()

        self.progress.config(
            mode="determinate",
            value=100
        )

        self.status.config(
            text="● SCAN COMPLETE",
            fg=GREEN
        )

        self.progress_text.config(
            text=(
                f"{self.mode} tamamlandı • "
                f"{count:,} dosya"
            )
        )

        self.current.config(
            text="Tarama tamamlandı"
        )

        self.report_title.config(
            text="✓ Şüpheli gösterge bulunmadı"
        )

        self.set_report(
            f"Tarama tamamlandı.\n\n"
            f"Mod: {self.mode}\n"
            f"Taranan: {count:,}\n\n"
            "Dosyalar çalıştırılmadı.\n"
            "Dosyalar değiştirilmedi.\n\n"
            "Sonuç CyberBoom statik analiz motoruna aittir."
        )

        self.set_buttons(
            True
        )

        self.stop_button.config(
            state="disabled"
        )

    # ========================================================
    # STOPPED
    # ========================================================

    def handle_stopped(
        self,
        count
    ):

        if not self.running:
            return

        self.running = False

        self.progress.stop()

        self.status.config(
            text="● STOPPED",
            fg=YELLOW
        )

        self.progress_text.config(
            text=(
                f"Tarama durduruldu • "
                f"{count:,} dosya"
            )
        )

        self.current.config(
            text="Tarama durduruldu"
        )

        self.report_title.config(
            text="Tarama durduruldu"
        )

        self.set_report(
            f"Tarama kullanıcı tarafından durduruldu.\n\n"
            f"İncelenen: {count:,}"
        )

        self.set_buttons(
            True
        )

        self.stop_button.config(
            state="disabled"
        )

    # ========================================================
    # ERROR
    # ========================================================

    def handle_error(
        self,
        error
    ):

        self.running = False

        self.progress.stop()

        self.status.config(
            text="● ERROR",
            fg=RED
        )

        self.report_title.config(
            text="Tarama hatası"
        )

        self.set_report(
            "Tarama motoru beklenmeyen bir hata ile "
            "karşılaştı.\n\n"
            f"{error}"
        )

        self.set_buttons(
            True
        )

        self.stop_button.config(
            state="disabled"
        )

    # ========================================================
    # STOP
    # ========================================================

    def stop_scan(
        self
    ):

        if not self.running:
            return

        self.status.config(
            text="● STOPPING",
            fg=YELLOW
        )

        self.current.config(
            text="Tarama güvenli şekilde durduruluyor..."
        )

        self.stop_button.config(
            state="disabled"
        )

        self.stop_event.set()

    # ========================================================
    # BUTTON STATE
    # ========================================================

    def set_buttons(
        self,
        enabled
    ):

        state = (
            "normal"
            if enabled
            else "disabled"
        )

        for button in (
            self.quick_button,
            self.full_button,
            self.file_button,
            self.folder_button
        ):

            button.config(
                state=state
            )

    # ========================================================
    # REPORT
    # ========================================================

    def make_report(
        self,
        result
    ):

        lines = []

        lines.append(
            "DOSYA"
        )

        lines.append(
            result.path
        )

        lines.append(
            ""
        )

        lines.append(
            "SHA-256"
        )

        lines.append(
            result.sha256 or "Hesaplanamadı"
        )

        lines.append(
            ""
        )

        lines.append(
            f"Boyut: {self.format_size(result.size)}"
        )

        if result.is_pe:

            lines.append(
                f"Mimari: {result.architecture}"
            )

            lines.append(
                f"Entropy: {result.entropy:.2f}"
            )

        lines.append(
            f"Statik skor: {result.score}"
        )

        lines.append(
            ""
        )

        lines.append(
            "MUHTEMEL ETKİLER"
        )

        categories = set(
            result.categories
        )

        if (
            "Ağ iletişimi" in categories
            or "Dosya indirme" in categories
            or "Uzaktan içerik" in categories
        ):

            lines.append(
                "• Ağ üzerinden veri alma/gönderme "
                "davranışı araştırılmalı."
            )

        if (
            "Process belleği" in categories
            or "Uzak thread" in categories
            or "Process erişimi" in categories
        ):

            lines.append(
                "• Başka process'lere erişim veya "
                "bellek manipülasyonu göstergeleri var."
            )

        if (
            "Credential erişimi" in categories
            or "Credential aracı" in categories
        ):

            lines.append(
                "• Kimlik bilgilerine erişimle ilişkili "
                "göstergeler bulundu."
            )

        if (
            "Başlangıç kalıcılığı" in categories
        ):

            lines.append(
                "• Windows başlangıç kalıcılığıyla "
                "ilişkili gösterge bulundu."
            )

        if (
            "Kodlanmış PowerShell" in categories
            or "Obfuscation göstergesi" in categories
        ):

            lines.append(
                "• Kod gizleme/kodlama göstergeleri bulundu."
            )

        lines.append(
            ""
        )

        lines.append(
            "BULGULAR"
        )

        for item in result.indicators:

            lines.append(
                f"• [{item['category']}]"
            )

            lines.append(
                f"  {item['explanation']}"
            )

        lines.append(
            ""
        )

        lines.append(
            "NOT"
        )

        lines.append(
            "Bu sonuç statik göstergelere dayanır. "
            "Bir API veya string bulunması tek başına "
            "dosyanın zararlı olduğunu kanıtlamaz."
        )

        return "\n".join(
            lines
        )

    # ========================================================
    # REPORT TEXT
    # ========================================================

    def set_report(
        self,
        text
    ):

        self.report.config(
            state="normal"
        )

        self.report.delete(
            "1.0",
            "end"
        )

        self.report.insert(
            "1.0",
            text
        )

        self.report.config(
            state="disabled"
        )

    # ========================================================
    # FORMAT
    # ========================================================

    @staticmethod
    def format_size(
        size
    ):

        value = float(size)

        for unit in (
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        ):

            if value < 1024:

                return (
                    f"{value:.1f} {unit}"
                )

            value /= 1024

        return (
            f"{value:.1f} PB"
        )

    # ========================================================
    # SAFE CLOSE
    # ========================================================

    def close(
        self
    ):

        if self.closing:
            return

        if self.running:

            answer = messagebox.askyesno(
                "CyberBoom",
                "Tarama devam ediyor.\n\n"
                "Kapatmadan önce taramayı durdurayım mı?"
            )

            if not answer:
                return

            self.stop_event.set()

            self.closing = True

            self.status.config(
                text="● CLOSING",
                fg=YELLOW
            )

            self.root.after(
                50,
                self.wait_for_worker
            )

            return

        self.destroy()

    def wait_for_worker(
        self
    ):

        thread_alive = (
            self.worker_thread is not None
            and self.worker_thread.is_alive()
        )

        if thread_alive:

            self.root.after(
                50,
                self.wait_for_worker
            )

            return

        self.destroy()

    def destroy(
        self
    ):

        self.closing = True

        self.stop_event.set()

        try:

            if IS_WINDOWS:

                hwnd = self.root.winfo_id()

                DragAcceptFiles(
                    hwnd,
                    False
                )

        except Exception:
            pass

        self.root.destroy()


# ============================================================
# MAIN
# ============================================================

def main():

    if sys.version_info < (
        3,
        10
    ):

        messagebox.showerror(
            "CyberBoom",
            "Python 3.10 veya daha yeni bir sürüm gerekiyor."
        )

        return

    root = tk.Tk()

    # Windows DPI
    if IS_WINDOWS:

        try:

            ctypes.windll.shcore.SetProcessDpiAwareness(
                1
            )

        except Exception:
            pass

    app = CyberBoomApp(
        root
    )

    root.mainloop()


if __name__ == "__main__":

    main()
