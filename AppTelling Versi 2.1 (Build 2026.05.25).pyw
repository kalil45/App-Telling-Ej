import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD
import csv
import re
import os
import random
import hashlib
from datetime import datetime
from openpyxl import Workbook, load_workbook

# Set appearance and theme
ctk.set_appearance_mode("Dark")  # Default to Dark mode
ctk.set_default_color_theme("green")

class LoginWindow(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, on_success):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)
        self.on_success = on_success
        self.title("EJ ANALYZER - SECURITY ACCESS")
        self.geometry("400x350")
        self.configure(fg_color="#000000")
        self.resizable(False, False)

        # Terminal Code Scroll Background for Login
        self.canvas_bg = tk.Canvas(self, bg="#000000", highlightthickness=0)
        self.canvas_bg.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        self.code_snippets = [
            "CONNECTING...", "BYPASSING FIREWALL", "ACCESSING DATABASE",
            "DECRYPTING LOGS", "HANDSHAKE SUCCESS", "GET /AUTH/LOGIN",
            "USER: ADMIN", "STATUS: RESTRICTED", "ENCRYPTION: AES-256",
            "MOUNTING /DEV/SDA1", "ROOT ACCESS GRANTED?", "TERMINAL_START"
        ]
        self.active_lines = []

        def draw_bg_scroll():
            for line_id in self.active_lines[:]:
                self.move(line_id, 0, 10)
                if self.coords(line_id)[1] > 350:
                    self.delete(line_id)
                    self.active_lines.remove(line_id)

            if random.random() > 0.6:
                code = random.choice(self.code_snippets)
                line_id = self.canvas_bg.create_text(
                    random.randint(10, 300), 0, text=code, fill="#003b00", 
                    font=("Consolas", 8), anchor="nw"
                )
                self.active_lines.append(line_id)
            self.after(100, draw_bg_scroll)

        # Overload Canvas move/coords for easier access
        self.move = self.canvas_bg.move
        self.coords = self.canvas_bg.coords
        self.delete = self.canvas_bg.delete
        
        self.after(100, draw_bg_scroll)

        # UI Elements
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.place(relx=0.5, rely=0.25, anchor="center")

        self.label = ctk.CTkLabel(self.header_frame, text="EJ ANALYZER", 
                                 text_color="#00ff41", 
                                 font=ctk.CTkFont(size=28, weight="bold"))
        self.label.pack()
        
        self.sub_label = ctk.CTkLabel(self.header_frame, text="SYSTEM PROTECTION ACTIVE", 
                                     text_color="#008f11", 
                                     font=ctk.CTkFont(size=10))
        self.sub_label.pack()

        self.input_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.input_frame.place(relx=0.5, rely=0.6, anchor="center")

        self.password_entry = ctk.CTkEntry(self.input_frame, show="*", 
                                          fg_color="#000000", 
                                          text_color="#00ff41", 
                                          border_color="#008f11",
                                          width=220, height=45,
                                          placeholder_text="Enter Security Code",
                                          placeholder_text_color="#003b00",
                                          font=ctk.CTkFont(family="Consolas", size=16),
                                          justify="center")
        self.password_entry.pack(pady=10)
        self.password_entry.bind("<Return>", lambda e: self.check_password())

        self.login_button = ctk.CTkButton(self, text="[ AUTHORIZE ]", 
                                         fg_color="transparent", 
                                         hover_color="#001a00",
                                         text_color="#00ff41",
                                         border_width=1,
                                         border_color="#008f11",
                                         width=150,
                                         font=ctk.CTkFont(family="Consolas", weight="bold"),
                                         command=self.check_password)
        self.login_button.place(relx=0.5, rely=0.85, anchor="center")

        self.error_label = ctk.CTkLabel(self, text="", text_color="#ff0000", font=("Consolas", 10))
        self.error_label.place(relx=0.5, rely=0.73, anchor="center")
        
        self.password_entry.focus()
        tk.Misc.lift(self.header_frame)
        tk.Misc.lift(self.input_frame)
        tk.Misc.lift(self.login_button)

    def check_password(self):
        stored_hash = "158a323a7ba44870f23d96f1516dd70aa48e9a72db4ebb026b0a89e212a208ab"
        input_password = self.password_entry.get()
        
        # Hitung hash dari input pengguna
        input_hash = hashlib.sha256(input_password.encode()).hexdigest()

        if input_hash == stored_hash:
            self.destroy()
            self.on_success()
        else:
            self.error_label.configure(text="INVALID CODE. ACCESS DENIED.")
            self.password_entry.delete(0, 'end')

class AtmLogAnalyzer(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)

        self.title("ATM Log Analyzer Pro - By Khalil Finanda")
        self.geometry("1100x700")
        
        # Color Palette (Hacker Style)
        self.hacker_green = "#00ff41" # Matrix/Hacker Green
        self.hacker_green_dark = "#008f11"
        self.bg_black = "#0d0208" # Deep Black
        self.sidebar_black = "#000000"
        self.text_green = "#00ff41"
        self.accent_red = "#ff0000"
        self.accent_amber = "#ffb000"
        
        # Override background color for the main window
        self.configure(fg_color=self.bg_black)
        
        # File output utama
        self.excel_output = "Hasil_Analisa_ATM.xlsx"

        # Variables
        self.matrix_active = True
        self.file_path = tk.StringVar()
        for f in ["tell.txt", "tell mesin hyosung.txt", "tell mesin Hitachi.txt"]:
            if os.path.exists(f):
                self.file_path.set(os.path.abspath(f))
                break
        
        self.lembar_awal = tk.StringVar(value="0")
        self.denom_k1 = tk.StringVar(value="100000")
        self.denom_k2 = tk.StringVar(value="100000")
        self.denom_k3 = tk.StringVar(value="100000")
        self.denom_k4 = tk.StringVar(value="100000")
        self.pengisian_awal = tk.StringVar(value="0")
        self.pengisian_awal_hitachi = tk.StringVar(value="0")
        self.join_dir = tk.StringVar()
        self.search_query = tk.StringVar()

        # Configure layout (1x2 grid)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_frames()
        
        # Cek saldo awal otomatis jika file default ada
        if self.file_path.get():
            self.auto_detect_initial_balance()
            
        # Select default frame
        self.select_frame_by_name("atm")

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0, fg_color=self.sidebar_black)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(8, weight=1)

        # Terminal Code Scroll Background for Sidebar
        self.canvas_code = tk.Canvas(self.sidebar_frame, bg=self.sidebar_black, 
                                    highlightthickness=0, width=200, height=800)
        self.canvas_code.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        self.code_snippets = [
            "import os, sys", "def analyze_log(file):", "if status == 200:",
            "while True:", "try:", "  exec(cmd)", "except Error as e:",
            "logging.info('DONE')", "db.connect('127.0.0.1')", "git push origin",
            "npm install --silent", "SELECT * FROM atm_logs", "chmod +x script.sh",
            "python3 app.pyw", "curl -X GET /api/v2", "systemctl restart",
            "ping -c 4 8.8.8.8", "ssh root@remote", "grep -i 'error' .",
            "sudo apt upgrade", "docker-compose up -d", "pip install ctk",
            "ls -la /usr/bin", "cat /etc/passwd", "openssl genrsa",
            "netstat -tuln", "iptables -A INPUT", "rm -rf /tmp/*"
        ]
        
        self.active_lines = []

        # Mulai animasi
        self.after(500, self.draw_code_scroll)
        tk.Misc.lift(self.canvas_code)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="LOG ANALYZER", 
                                       font=ctk.CTkFont(size=20, weight="bold"),
                                       text_color=self.hacker_green,
                                       fg_color="transparent")
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 10))
        tk.Misc.lift(self.logo_label)
        
        self.sub_logo_label = ctk.CTkLabel(self.sidebar_frame, text="Pro Version", 
                                          font=ctk.CTkFont(size=12),
                                          text_color=self.hacker_green_dark)
        self.sub_logo_label.grid(row=1, column=0, padx=20, pady=(0, 30))

        # Buttons with Glow-like hover (border color change)
        button_params = {
            "corner_radius": 8, "height": 40, "border_spacing": 10,
            "fg_color": "transparent", "text_color": self.hacker_green,
            "hover_color": "#001a00", "border_width": 1, "border_color": "#003b00",
            "anchor": "w"
        }

        self.btn_atm = ctk.CTkButton(self.sidebar_frame, text="Analisa ATM", command=self.btn_atm_event, **button_params)
        self.btn_atm.grid(row=2, column=0, sticky="ew", padx=10, pady=2)

        self.btn_crm = ctk.CTkButton(self.sidebar_frame, text="Rekap CRM", command=self.btn_crm_event, **button_params)
        self.btn_crm.grid(row=3, column=0, sticky="ew", padx=10, pady=2)

        self.btn_hitachi = ctk.CTkButton(self.sidebar_frame, text="CRM Hitachi", command=self.btn_hitachi_event, **button_params)
        self.btn_hitachi.grid(row=4, column=0, sticky="ew", padx=10, pady=2)

        self.btn_join = ctk.CTkButton(self.sidebar_frame, text="Join File TXT", command=self.btn_join_event, **button_params)
        self.btn_join.grid(row=5, column=0, sticky="ew", padx=10, pady=2)

        self.btn_advanced = ctk.CTkButton(self.sidebar_frame, text="Analisa Lanjutan", command=self.btn_advanced_event, **button_params)
        self.btn_advanced.grid(row=6, column=0, sticky="ew", padx=10, pady=2)

        self.btn_toggle_matrix = ctk.CTkButton(self.sidebar_frame, text="Matikan Matrix", command=self.toggle_matrix, **button_params)
        self.btn_toggle_matrix.grid(row=7, column=0, sticky="ew", padx=10, pady=2)

        # Bottom info
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Appearance Mode:", text_color=self.hacker_green, anchor="w")
        self.appearance_mode_label.grid(row=8, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Dark", "Light", "System"],
                                                                       fg_color=self.bg_black,
                                                                       button_color=self.hacker_green_dark,
                                                                       button_hover_color=self.hacker_green,
                                                                       text_color=self.hacker_green,
                                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

    def create_main_frames(self):
        # Header and Common Input Section
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(2, weight=1)

        # Header Title
        self.header_label = ctk.CTkLabel(self.main_container, text="Analisa ATM", 
                                        text_color=self.hacker_green,
                                        font=ctk.CTkFont(size=24, weight="bold"))
        self.header_label.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Common Input Frame (File Path)
        self.input_frame = ctk.CTkFrame(self.main_container, fg_color=self.sidebar_black, border_width=1, border_color=self.hacker_green_dark)
        self.input_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        self.input_frame.grid_columnconfigure(1, weight=1)

        self.lbl_file = ctk.CTkLabel(self.input_frame, text="File Log:", text_color=self.hacker_green)
        self.lbl_file.grid(row=0, column=0, padx=15, pady=15)
        
        self.entry_file = ctk.CTkEntry(self.input_frame, textvariable=self.file_path, 
                                       fg_color=self.bg_black, text_color=self.hacker_green, 
                                       border_color=self.hacker_green_dark)
        self.entry_file.grid(row=0, column=1, padx=(0, 10), pady=15, sticky="ew")
        
        # Register for Drag and Drop
        self.entry_file.drop_target_register(DND_FILES)
        self.entry_file.dnd_bind('<<Drop>>', self.handle_drop)
        
        self.btn_browse = ctk.CTkButton(self.input_frame, text="Browse", width=100, 
                                       fg_color=self.hacker_green_dark, hover_color=self.hacker_green,
                                       text_color="black",
                                       command=self.browse_file)
        self.btn_browse.grid(row=0, column=2, padx=(0, 15), pady=15)

        # Dynamic Content Frame
        self.content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_frame.grid(row=2, column=0, sticky="nsew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(1, weight=1)

        # Sub-frames for each tab
        self.frame_atm = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.frame_crm = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.frame_hitachi = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.frame_join = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.frame_advanced = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        # --- Frame ATM Content ---
        self.lbl_stok = ctk.CTkLabel(self.frame_atm, text="Stok Lembar Awal", text_color=self.hacker_green, font=ctk.CTkFont(weight="bold"))
        self.lbl_stok.pack(anchor="w", pady=(10, 5))
        self.entry_stok = ctk.CTkEntry(self.frame_atm, textvariable=self.lembar_awal, height=40, 
                                       fg_color=self.bg_black, text_color=self.hacker_green, 
                                       border_color=self.hacker_green_dark, font=ctk.CTkFont(size=16))
        self.entry_stok.pack(fill="x", pady=(0, 20))
        
        self.btn_run_hyosung = ctk.CTkButton(self.frame_atm, text="JALANKAN ANALISA HYOSUNG / HITACHI", 
                                             height=45, fg_color=self.hacker_green_dark, hover_color=self.hacker_green,
                                             text_color="black", font=ctk.CTkFont(weight="bold"),
                                             command=self.run_hyosung)
        self.btn_run_hyosung.pack(fill="x", pady=5)
        
        self.btn_run_ncr = ctk.CTkButton(self.frame_atm, text="JALANKAN ANALISA NCR", 
                                         height=45, fg_color=self.hacker_green_dark, hover_color=self.hacker_green,
                                         text_color="black", font=ctk.CTkFont(weight="bold"),
                                         command=self.run_ncr)
        self.btn_run_ncr.pack(fill="x", pady=5)

        # --- Denom Config for NCR (Grid) ---
        self.denom_frame = ctk.CTkFrame(self.frame_atm, fg_color="transparent")
        self.denom_frame.pack(fill="x", pady=10)
        
        for i in range(4):
            self.denom_frame.grid_columnconfigure(i, weight=1)
            lbl = ctk.CTkLabel(self.denom_frame, text=f"Denom K{i+1}", text_color=self.hacker_green_dark, font=ctk.CTkFont(size=11))
            lbl.grid(row=0, column=i, padx=5)
            
            var = [self.denom_k1, self.denom_k2, self.denom_k3, self.denom_k4][i]
            ent = ctk.CTkEntry(self.denom_frame, textvariable=var, height=30, 
                               fg_color=self.bg_black, text_color=self.hacker_green, 
                               border_color=self.hacker_green_dark, justify="center")
            ent.grid(row=1, column=i, padx=5, pady=(0, 5))

        # --- Frame CRM Content ---
        self.lbl_modal = ctk.CTkLabel(self.frame_crm, text="Modal Awal CRM (Rp)", text_color=self.hacker_green, font=ctk.CTkFont(weight="bold"))
        self.lbl_modal.pack(anchor="w", pady=(10, 5))
        self.entry_modal = ctk.CTkEntry(self.frame_crm, textvariable=self.pengisian_awal, height=40, 
                                        fg_color=self.bg_black, text_color=self.hacker_green, 
                                        border_color=self.hacker_green_dark, font=ctk.CTkFont(size=16))
        self.entry_modal.pack(fill="x", pady=(0, 20))
        
        self.crm_btn_group = ctk.CTkFrame(self.frame_crm, fg_color="transparent")
        self.crm_btn_group.pack(fill="x")
        self.btn_cashin = ctk.CTkButton(self.crm_btn_group, text="REKAP CASH IN", height=45, 
                                        fg_color=self.hacker_green_dark, hover_color=self.hacker_green, 
                                        text_color="black", font=ctk.CTkFont(weight="bold"), command=self.run_cashin)
        self.btn_cashin.pack(side="left", expand=True, fill="x", padx=(0, 5))
        self.btn_withdraw = ctk.CTkButton(self.crm_btn_group, text="REKAP WITHDRAW", height=45, 
                                          fg_color=self.hacker_green_dark, hover_color=self.hacker_green, 
                                          text_color="black", font=ctk.CTkFont(weight="bold"), command=self.run_withdraw)
        self.btn_withdraw.pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        self.btn_balance = ctk.CTkButton(self.frame_crm, text="HITUNG SALDO AKHIR CRM", 
                                         height=45, fg_color="#1a1a1a", hover_color="#333333", 
                                         text_color=self.hacker_green, border_width=1, border_color=self.hacker_green_dark, 
                                         command=self.run_crm_balance)
        self.btn_balance.pack(fill="x", pady=20)

        # --- Frame Hitachi Content ---
        self.lbl_modal_hitachi = ctk.CTkLabel(self.frame_hitachi, text="Modal Awal CRM Hitachi (Rp)", text_color=self.hacker_green, font=ctk.CTkFont(weight="bold"))
        self.lbl_modal_hitachi.pack(anchor="w", pady=(10, 5))
        self.entry_modal_hitachi = ctk.CTkEntry(self.frame_hitachi, textvariable=self.pengisian_awal_hitachi, height=40, 
                                                fg_color=self.bg_black, text_color=self.hacker_green, 
                                                border_color=self.hacker_green_dark, font=ctk.CTkFont(size=16))
        self.entry_modal_hitachi.pack(fill="x", pady=(0, 20))
        
        self.hitachi_btn_group = ctk.CTkFrame(self.frame_hitachi, fg_color="transparent")
        self.hitachi_btn_group.pack(fill="x")
        self.btn_cashin_hitachi = ctk.CTkButton(self.hitachi_btn_group, text="REKAP CASH IN HITACHI", height=45, 
                                               fg_color=self.hacker_green_dark, hover_color=self.hacker_green, 
                                               text_color="black", font=ctk.CTkFont(weight="bold"), command=self.run_hitachi_cashin)
        self.btn_cashin_hitachi.pack(side="left", expand=True, fill="x", padx=(0, 5))
        self.btn_withdraw_hitachi = ctk.CTkButton(self.hitachi_btn_group, text="REKAP WITHDRAW HITACHI", height=45, 
                                                 fg_color=self.hacker_green_dark, hover_color=self.hacker_green, 
                                                 text_color="black", font=ctk.CTkFont(weight="bold"), command=self.run_hitachi_withdraw)
        self.btn_withdraw_hitachi.pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        self.btn_balance_hitachi = ctk.CTkButton(self.frame_hitachi, text="HITUNG SALDO AKHIR CRM HITACHI", 
                                                height=45, fg_color="#1a1a1a", hover_color="#333333", 
                                                text_color=self.hacker_green, border_width=1, border_color=self.hacker_green_dark, 
                                                command=self.run_hitachi_balance)
        self.btn_balance_hitachi.pack(fill="x", pady=20)

        # --- Frame Join Content ---
        self.lbl_join_title = ctk.CTkLabel(self.frame_join, text="Gabungkan Beberapa File TXT", 
                                          text_color=self.hacker_green, font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_join_title.pack(anchor="w", pady=(10, 5))
        
        self.lbl_join_desc = ctk.CTkLabel(self.frame_join, text="Pilih folder yang berisi file-file .txt yang ingin digabungkan.", 
                                         text_color=self.hacker_green_dark, wraplength=600, justify="left")
        self.lbl_join_desc.pack(anchor="w", pady=(0, 20))

        self.join_input_frame = ctk.CTkFrame(self.frame_join, fg_color="transparent")
        self.join_input_frame.pack(fill="x", pady=5)
        
        self.entry_join_dir = ctk.CTkEntry(self.join_input_frame, textvariable=self.join_dir, height=40, 
                                          fg_color=self.bg_black, text_color=self.hacker_green, 
                                          border_color=self.hacker_green_dark, font=ctk.CTkFont(size=14))
        self.entry_join_dir.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Register for Drag and Drop (Folders)
        self.entry_join_dir.drop_target_register(DND_FILES)
        self.entry_join_dir.dnd_bind('<<Drop>>', self.handle_drop_join)
        
        self.btn_browse_join = ctk.CTkButton(self.join_input_frame, text="Pilih Folder", width=120, height=40,
                                            fg_color=self.hacker_green_dark, hover_color=self.hacker_green,
                                            text_color="black", font=ctk.CTkFont(weight="bold"),
                                            command=self.browse_join_dir)
        self.btn_browse_join.pack(side="right")

        self.btn_run_join = ctk.CTkButton(self.frame_join, text="GABUNGKAN SEKARANG", 
                                         height=50, fg_color="#004d00", hover_color=self.hacker_green,
                                         text_color="white", font=ctk.CTkFont(size=16, weight="bold"),
                                         command=self.run_join_files)
        self.btn_run_join.pack(fill="x", pady=30)

        # --- Frame Advanced Content ---
        self.lbl_adv_title = ctk.CTkLabel(self.frame_advanced, text="Analisa Lanjutan & Diagnostik", 
                                          text_color=self.hacker_green, font=ctk.CTkFont(size=18, weight="bold"))
        self.lbl_adv_title.pack(anchor="w", pady=(10, 5))

        # 1. Search Section
        self.search_frame = ctk.CTkFrame(self.frame_advanced, fg_color=self.sidebar_black, border_width=1, border_color=self.hacker_green_dark)
        self.search_frame.pack(fill="x", pady=10)
        
        self.lbl_search = ctk.CTkLabel(self.search_frame, text="Cari TXN / No Kartu:", text_color=self.hacker_green)
        self.lbl_search.pack(side="left", padx=10, pady=10)
        
        self.entry_search = ctk.CTkEntry(self.search_frame, textvariable=self.search_query, width=250,
                                        fg_color=self.bg_black, text_color=self.hacker_green, border_color=self.hacker_green_dark)
        self.entry_search.pack(side="left", padx=10, pady=10)
        
        self.btn_find = ctk.CTkButton(self.search_frame, text="CARI TRANSAKSI", width=120,
                                     fg_color=self.hacker_green_dark, hover_color=self.hacker_green,
                                     text_color="black", font=ctk.CTkFont(weight="bold"),
                                     command=self.run_transaction_finder)
        self.btn_find.pack(side="right", padx=10, pady=10)

        # 2. Diagnostic Buttons
        self.diag_btn_frame = ctk.CTkFrame(self.frame_advanced, fg_color="transparent")
        self.diag_btn_frame.pack(fill="x", pady=10)
        
        self.btn_health = ctk.CTkButton(self.diag_btn_frame, text="CEK KESEHATAN MESIN", height=45,
                                       fg_color="#1a1a1a", hover_color="#333333",
                                       text_color=self.hacker_green, border_width=1, border_color=self.hacker_green_dark,
                                       command=self.run_health_check)
        self.btn_health.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        self.btn_anomaly = ctk.CTkButton(self.diag_btn_frame, text="DETEKSI ANOMALI", height=45,
                                        fg_color="#1a1a1a", hover_color="#333333",
                                        text_color=self.accent_amber, border_width=1, border_color=self.accent_amber,
                                        command=self.run_anomaly_detection)
        self.btn_anomaly.pack(side="left", expand=True, fill="x", padx=5)

        self.btn_vault = ctk.CTkButton(self.diag_btn_frame, text="LOG BUKA BRANKAS", height=45,
                                      fg_color="#1a1a1a", hover_color="#333333",
                                      text_color="#ff4d4d", border_width=1, border_color="#ff4d4d",
                                      command=self.run_vault_log)
        self.btn_vault.pack(side="left", expand=True, fill="x", padx=(5, 0))

        # --- Log Section (Always Visible) ---
        self.log_frame = ctk.CTkFrame(self.main_container, fg_color=self.sidebar_black, border_width=1, border_color=self.hacker_green_dark)
        self.log_frame.grid(row=3, column=0, sticky="nsew", pady=(20, 0))
        self.log_frame.grid_columnconfigure(0, weight=1)
        self.log_frame.grid_rowconfigure(1, weight=1)

        self.lbl_log = ctk.CTkLabel(self.log_frame, text="LOG AKTIVITAS", text_color=self.hacker_green, font=ctk.CTkFont(weight="bold"))
        self.lbl_log.grid(row=0, column=0, padx=15, pady=(10, 5), sticky="w")
        
        self.btn_clear_log = ctk.CTkButton(self.log_frame, text="Clear", width=60, height=24, 
                                          fg_color="transparent", text_color=self.hacker_green_dark,
                                          border_width=1, border_color=self.hacker_green_dark, command=self.clear_log)
        self.btn_clear_log.grid(row=0, column=1, padx=15, pady=(10, 5), sticky="e")

        self.output_text = ctk.CTkTextbox(self.log_frame, font=("Consolas", 12), fg_color=self.bg_black, text_color=self.hacker_green, height=150)
        self.output_text.grid(row=1, column=0, columnspan=2, padx=15, pady=(0, 15), sticky="nsew")

        # Bottom Actions
        self.action_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.action_frame.grid(row=4, column=0, sticky="ew", pady=(15, 0))

        self.lbl_output = ctk.CTkLabel(self.action_frame, text=f"Output: {self.excel_output}", 
                                      font=ctk.CTkFont(slant="italic"), text_color=self.hacker_green_dark)
        self.lbl_output.pack(side="left")

        self.btn_del = ctk.CTkButton(self.action_frame, text="HAPUS HASIL", width=120, 
                                     fg_color=self.accent_red, hover_color="#990000", text_color="white", command=self.delete_excel)
        self.btn_del.pack(side="right", padx=(10, 0))

        self.btn_open = ctk.CTkButton(self.action_frame, text="BUKA HASIL EXCEL", width=150, 
                                      fg_color=self.accent_amber, text_color="black", hover_color="#cc8a00", command=self.open_excel)
        self.btn_open.pack(side="right")

    def select_frame_by_name(self, name):
        # Update button colors
        self.btn_atm.configure(fg_color=self.hacker_green_dark if name == "atm" else "transparent", 
                               text_color="black" if name == "atm" else self.hacker_green)
        self.btn_crm.configure(fg_color=self.hacker_green_dark if name == "crm" else "transparent", 
                               text_color="black" if name == "crm" else self.hacker_green)
        self.btn_hitachi.configure(fg_color=self.hacker_green_dark if name == "hitachi" else "transparent", 
                                   text_color="black" if name == "hitachi" else self.hacker_green)
        self.btn_join.configure(fg_color=self.hacker_green_dark if name == "join" else "transparent", 
                                   text_color="black" if name == "join" else self.hacker_green)
        self.btn_advanced.configure(fg_color=self.hacker_green_dark if name == "advanced" else "transparent", 
                                   text_color="black" if name == "advanced" else self.hacker_green)

        # Hide all frames first
        frames = {
            "atm": (self.frame_atm, "Analisa ATM"),
            "crm": (self.frame_crm, "Rekap CRM"),
            "hitachi": (self.frame_hitachi, "CRM Hitachi"),
            "join": (self.frame_join, "Join File TXT"),
            "advanced": (self.frame_advanced, "Analisa Lanjutan")
        }

        # Determine which frame is currently active for potential transition effects
        # (Simplified for page flip)
        for frame_key in frames:
            frames[frame_key][0].pack_forget()

        # Show selected frame with Page Flip animation
        selected_frame, title = frames[name]
        self.header_label.configure(text=title)
        self.animate_page_flip(selected_frame)

    def animate_page_flip(self, widget):
        """Animasi membalik halaman buku (slide-in from right with width expansion)"""
        widget.update_idletasks()
        
        # Mulai dari sisi kanan dengan lebar 0
        def flip(step=1.0, width=0.0):
            if width < 1.0:
                # Gerakan: relx berkurang (pindah ke kiri), relwidth bertambah (membuka)
                new_width = width + 0.08
                new_x = 1.0 - new_width
                widget.place(relx=max(0, new_x), rely=0, relwidth=min(1.0, new_width), relheight=1)
                self.after(10, lambda: flip(new_x, new_width))
            else:
                widget.place_forget()
                widget.pack(fill="both", expand=True)

        flip()

    def btn_atm_event(self):
        self.select_frame_by_name("atm")

    def btn_crm_event(self):
        self.select_frame_by_name("crm")

    def btn_hitachi_event(self):
        self.select_frame_by_name("hitachi")

    def btn_join_event(self):
        self.select_frame_by_name("join")

    def btn_advanced_event(self):
        self.select_frame_by_name("advanced")

    def toggle_matrix(self):
        self.matrix_active = not self.matrix_active
        if self.matrix_active:
            self.btn_toggle_matrix.configure(text="Matikan Matrix")
            self.draw_code_scroll()
        else:
            self.btn_toggle_matrix.configure(text="Aktifkan Matrix")
            self.canvas_code.delete("all")
            self.active_lines = []

    def draw_code_scroll(self):
        if not self.matrix_active:
            return

        # Geser semua baris yang ada ke bawah
        for line_id in self.active_lines[:]: 
            self.canvas_code.move(line_id, 0, 15)
            # Cek jika sudah keluar layar bawah (tinggi canvas ~800), hapus
            if self.canvas_code.coords(line_id)[1] > 800:
                self.canvas_code.delete(line_id)
                self.active_lines.remove(line_id)

        # Tambahkan baris kode baru di bagian atas
        if random.random() > 0.4:
            code = random.choice(self.code_snippets)
            color = random.choice(["#003b00", "#008f11", "#00FF41"])
            # Munculkan di y=10 agar mulai dari atas
            line_id = self.canvas_code.create_text(
                10, 10, text=f"> {code}", fill=color, 
                font=("Consolas", 9), anchor="w"
            )
            self.active_lines.append(line_id)
        
        self.after(150, self.draw_code_scroll)

    def auto_detect_initial_balance(self):
        file_path = self.file_path.get()
        if not os.path.exists(file_path):
            return

        self.log_message("--- Mencoba Deteksi Saldo Awal Otomatis ---")
        try:
            # Baca hanya bagian awal file untuk efisiensi (1MB pertama)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1000000)

            detected = False

            # 1. Deteksi Hyosung / Hitachi (WITHDRAW COUNTER / REMAINING NOTES)
            # Fokus mencari blok laporan terbaru, menggunakan regex yang lebih ketat untuk 5 kolom
            withdraw_block = re.search(r'WITHDRAW COUNTER\s+DENOM\s+INIT\s+DIS\s+REJ\s+A_RET(.*?)(?:TOTAL WITHDRAW|----------------)', content, re.DOTALL)
            if withdraw_block:
                table_text = withdraw_block.group(1)
                # Pastikan mencocokkan 5 kolom: DENOM, INIT, DIS, REJ, A_RET
                matches = re.findall(r'^\s*(\d{5,6})\s+(\d{6})\s+(\d{6})\s+(\d{6})\s+(\d{6})', table_text, re.MULTILINE)
                if matches:
                    total_lembar = 0
                    total_rp_calc = 0
                    breakdown = {}
                    for denom, init_val, dis_val, rej_val, aret_val in matches:
                        d_val = int(denom)
                        l_val = int(init_val) # Kolom INIT untuk Saldo Awal
                        total_lembar += l_val
                        total_rp_calc += (d_val * l_val)
                        breakdown[d_val] = breakdown.get(d_val, 0) + l_val
                    
                    if total_lembar > 0:
                        self.lembar_awal.set(str(total_lembar))
                        self.pengisian_awal.set(str(total_rp_calc))
                        self.pengisian_awal_hitachi.set(str(total_rp_calc))
                        
                        breakdown_str = ", ".join([f"Denom {d:,}: {l} lbr" for d, l in sorted(breakdown.items())])
                        self.log_message(f"Berhasil Deteksi (Hitachi WITHDRAW): {total_lembar} Lembar (Rp {total_rp_calc:,})")
                        self.log_message(f" > Rincian Saldo Awal: {breakdown_str}")
                        detected = True

            # 2. Deteksi NCR (CASSETTE / REMAINING)
            # Pola: =TOTAL         08000
            if not detected:
                ncr_total_match = re.findall(r'=TOTAL\s+(\d{5})', content)
                if ncr_total_match:
                    total_ncr = sum(int(x) for x in ncr_total_match)
                    if total_ncr > 0:
                        self.lembar_awal.set(str(total_ncr))
                        # Coba deteksi per kaset jika ada
                        # Tipe 1 & 2 biasanya muncul berpasangan
                        types = re.findall(r'CASSETTE\s+(\d{5})\s+(\d{5})', content)
                        if types and len(types) >= 2:
                            k1, k2 = types[0]
                            k3, k4 = types[1]
                            self.denom_k1.set("100000") # Asumsi umum
                            self.denom_k2.set("100000")
                            self.denom_k3.set("100000")
                            self.denom_k4.set("100000")
                        
                        self.log_message(f"Berhasil Deteksi (NCR): {total_ncr} Lembar.")
                        detected = True

            # 3. Deteksi Pola Alternatif (CASSETTE CNT)
            # Pola: CASSETTE2   100000 1000
            if not detected:
                cnt_match = re.findall(r'CASSETTE\d\s+(\d+)\s+(\d+)', content)
                if cnt_match:
                    total_cnt = 0
                    total_rp_cnt = 0
                    for denom, cnt in cnt_match:
                        d_val = int(denom)
                        c_val = int(cnt)
                        total_cnt += c_val
                        total_rp_cnt += (d_val * c_val)
                    
                    if total_cnt > 0:
                        self.lembar_awal.set(str(total_cnt))
                        self.pengisian_awal.set(str(total_rp_cnt))
                        self.pengisian_awal_hitachi.set(str(total_rp_cnt))
                        self.log_message(f"Berhasil Deteksi (Cassette List): {total_cnt} Lembar (Rp {total_rp_cnt:,}).")
                        detected = True

            # 4. Deteksi Khusus Hyosung CRM/ATM (INIT AMOUNT / ADD CASH)
            # Pola ATM: ADD CASH: \n 1CST:2000 ...
            add_cash_block = re.search(r'ADD CASH:\s*((?:\dCST:\d+\s*)+)', content)
            if add_cash_block:
                cst_matches = re.findall(r'\dCST:(\d+)', add_cash_block.group(1))
                if cst_matches:
                    total_cst = sum(int(c) for c in cst_matches)
                    self.lembar_awal.set(str(total_cst))
                    self.log_message(f"Berhasil Deteksi (Hyosung ATM Add Cash): {total_cst} Lembar.")
                    detected = True

            # Pola Tabel ATM Hyosung: 1 IDR 100K 01999 00001 02000 00000 02000
            if not detected:
                hyo_table_matches = re.findall(r'\d\s+IDR\s+(\d+K)\s+\d{5}\s+\d{5}\s+\d{5}\s+\d{5}\s+(\d{5})', content)
                if hyo_table_matches:
                    total_lbr = 0
                    total_rp = 0
                    for denom_str, total_val in hyo_table_matches:
                        lbr = int(total_val)
                        total_lbr += lbr
                        d_val = 100000 if "100K" in denom_str else 50000
                        total_rp += (d_val * lbr)
                    
                    if total_lbr > 0:
                        self.lembar_awal.set(str(total_lbr))
                        self.pengisian_awal.set(str(total_rp))
                        self.log_message(f"Berhasil Deteksi (Hyosung ATM Table): {total_lbr} Lembar (Rp {total_rp:,}).")
                        detected = True

            # Pola CRM: INIT AMOUNT:        300,000,000 IDR atau ADD CASH: ...
            hyo_match = re.search(r'(?:INIT AMOUNT|ADD CASH):\s*([\d.,]+)\s*IDR', content)
            if hyo_match:
                amt_val = hyo_match.group(1).replace(',', '')
                if '.' in amt_val:
                    amt_val = amt_val.split('.')[0]
                
                self.pengisian_awal.set(amt_val)
                self.pengisian_awal_hitachi.set(amt_val)
                self.log_message(f"Berhasil Deteksi (Hyosung CRM): Rp {int(amt_val):,}")
                detected = True

            # 5. Deteksi Khusus Hitachi CRM / Umum (TOTAL REMAINING)
            # Pola: TOTAL REMAINING:388,300,000.00
            if not detected:
                total_rem = re.search(r'TOTAL REMAINING:([\d.,]+)', content)
                if total_rem:
                    amt = total_rem.group(1).replace(',', '')
                    if '.' in amt:
                        amt = amt.split('.')[0]
                    
                    if int(amt) > 0:
                        self.pengisian_awal.set(amt)
                        self.pengisian_awal_hitachi.set(amt)
                        self.log_message(f"Berhasil Deteksi (Hitachi CRM/Rem): Rp {int(amt):,}")
                        detected = True

            # 6. Deteksi Hitachi Cassette List (Denom x Count)
            # Pola: CASSETTE1    50000 0200
            if not detected:
                hitachi_cassettes = re.findall(r'CASSETTE\d\s+(\d+)\s+(\d{4})', content)
                if hitachi_cassettes:
                    total_rp = 0
                    total_lbr = 0
                    breakdown = {}
                    for denom, cnt in hitachi_cassettes:
                        d_val = int(denom)
                        c_val = int(cnt)
                        total_rp += (d_val * c_val)
                        total_lbr += c_val
                        breakdown[d_val] = breakdown.get(d_val, 0) + c_val
                    
                    if total_rp > 0:
                        self.pengisian_awal.set(str(total_rp))
                        self.pengisian_awal_hitachi.set(str(total_rp))
                        self.lembar_awal.set(str(total_lbr))
                        
                        # Buat pesan breakdown yang cantik
                        breakdown_str = ", ".join([f"Denom {d:,}: {l} lbr" for d, l in sorted(breakdown.items())])
                        self.log_message(f"Berhasil Deteksi (Hitachi Cassette): {total_lbr} Lbr (Rp {total_rp:,})")
                        self.log_message(f" > Rincian: {breakdown_str}")
                        detected = True

            if not detected:
                self.log_message("Saldo awal tidak ditemukan secara otomatis. Silakan input manual.")
            else:
                self.log_message("Variabel input telah diperbarui otomatis.")

        except Exception as e:
            self.log_message(f"Error saat deteksi otomatis: {str(e)}")

    # --- Advanced Logic Implementation ---

    def run_transaction_finder(self):
        file_log = self.file_path.get()
        query = self.search_query.get().strip()
        if not os.path.exists(file_log) or not query:
            messagebox.showerror("Error", "Pilih file log dan masukkan kata kunci pencarian!")
            return
        
        self.clear_log()
        self.log_message(f"--- Mencari Transaksi: {query} ---")
        
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Cari blok yang mengandung kata kunci (bisa TXN NO atau No Kartu)
            # Pisahkan berdasarkan pemisah transaksi umum
            blocks = re.split(r'\[Transaction record\]|-------------------', content)
            found_count = 0
            
            for block in blocks:
                if query in block:
                    found_count += 1
                    clean_block = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', block).strip()
                    self.log_message(f"\n--- DATA DITEMUKAN ({found_count}) ---")
                    self.log_message(clean_block)
                    self.log_message("-" * 40)
            
            if found_count == 0:
                self.log_message("Data tidak ditemukan dalam file log ini.")
            else:
                self.log_message(f"\nSelesai! Berhasil menemukan {found_count} blok data.")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def run_health_check(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", "File log tidak ditemukan!")
            return
        
        self.clear_log()
        self.log_message("--- Menganalisa Kesehatan & Error Mesin ---")
        
        # Kamus Error yang Lebih Luas
        error_patterns = {
            "REJECT BIN FULL": r"REJECT BIN FULL|BIN FULL",
            "PICK ERROR": r"PICK ERROR|FAILED TO PICK",
            "SHUTTER ERROR": r"SHUTTER ERROR|SHUTTER FAULT",
            "SENSOR MALFUNCTION": r"SENSOR ERROR|SENSOR FAULT",
            "CARD READER ERROR": r"CARD READER ERROR|M-STATUS 04",
            "DISPENSER ERROR": r"DISPENSER ERROR|M-STATUS 12",
            "RECEIPT PRINTER ERROR": r"PRINTER ERROR|PAPER JAM",
            "PAPER LOW/OUT": r"PAPER LOW|PAPER OUT|RECEIPT LOW",
            "COMMUNICATION FAILURE": r"COMMUNICATION FAILURE|HOST TIMEOUT|NETWORK ERROR",
            "SECURITY ALERT (DOOR)": r"DOOR OPEN|TAMPER SENSOR|VIBRATION",
            "CASSETTE OUT OF SERVICE": r"CASSETTE\s+\d+\s+OUT OF SERVICE|CASSETTE ERROR",
            "LOW CASH WARNING": r"LOW CASH|CASH LOW"
        }
        
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().upper()
            
            self.log_message("Ringkasan Diagnostik Hardware:")
            found_any = False
            for name, pattern in error_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    # Tampilkan dengan warna berbeda jika error kritis (opsional di log)
                    self.log_message(f" > {name:<25}: {len(matches)} kali")
                    found_any = True
            
            if not found_any:
                self.log_message("Hasil: Mesin dalam kondisi prima (Tidak ditemukan error hardware).")
            
            # Tambahan: Cari Supervisor Mode (Kapan terakhir di-service)
            sv_mode = re.findall(r"SUPERVISOR MODE\s+ENTERED|SETTLEMENT", content)
            if sv_mode:
                self.log_message(f"\nInfo: Supervisor Mode diakses {len(sv_mode)} kali (Indikasi Maintenance/Settlement).")
            
            # Cari status terakhir
            last_status = re.findall(r"M-STATUS\s+([0-9A-F ]+)", content)
            if last_status:
                self.log_message(f"Status Mesin Terakhir: {last_status[-1]}")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def run_anomaly_detection(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", "File log tidak ditemukan!")
            return
        
        self.clear_log()
        self.log_message("--- Mendeteksi Anomali Transaksi ---")
        
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 1. Deteksi Duplikasi Kartu Beruntun (Potensi Fraud/Test)
            cards = re.findall(r"(\d{6}X{6}\d{4})", content)
            self.log_message("Mengecek penarikan berulang...")
            
            card_hits = {}
            for c in cards:
                card_hits[c] = card_hits.get(c, 0) + 1
            
            anomaly_found = False
            for card, count in card_hits.items():
                if count > 3:
                    self.log_message(f" ALERT: Kartu {card} melakukan {count} penarikan!")
                    anomaly_found = True
            
            # 2. Deteksi Cash Not Taken
            not_taken = len(re.findall(r"Cash (?:Not|is) Taken|Returned to Bin", content, re.IGNORECASE))
            if not_taken > 0:
                self.log_message(f" ALERT: Ditemukan {not_taken} uang tidak diambil nasabah (Returned).")
                anomaly_found = True
                
            # 3. Deteksi Transaksi Gagal Masif
            failures = len(re.findall(r"TRANSACTION HAVE A PROBLEM|TRANSACTION FAILED", content, re.IGNORECASE))
            if failures > 5:
                self.log_message(f" ALERT: Tingkat kegagalan tinggi ({failures} transaksi gagal).")
                anomaly_found = True
            
            if not anomaly_found:
                self.log_message("Hasil: Tidak ditemukan anomali yang mencurigakan.")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def run_vault_log(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", "File log tidak ditemukan!")
            return
        
        self.clear_log()
        self.log_message("--- Menganalisa Riwayat Pembukaan Brankas (Vault) ---")
        
        # Pola untuk pintu brankas (Safe/Vault) - Diperluas untuk Hyosung, NCR, Hitachi
        vault_patterns = [
            r"SAFE DOOR OPEN|VAULT OPEN|SAFE OPEN|DOOR OPENED 2",
            r"CASH DISPENSER SAFE DOOR OPEN",
            r"SAFE DOOR OPENED|CABINET DOOR OPENED|SCD DOOR OPEN",
            r"DOOR OPENED 1|SUPERVISOR MODE ENTERED|SUPERVISOR MODE ENTRY",
            r"REPLENISHMENT MODE|CASSETTE DOOR OPENED",
            r"\* DOOR OPENED \*|\[ DOOR OPENED \]|SCD DOOR",
            r"ACCESS MODE ENTERED|M-STATUS 04 1|M-STATUS 04 2",
            r"CASSETTE REMOVED|CASSETTE INSERTED|SUPERVISOR TASK ENTERED"
        ]
        
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Deteksi format tanggal global (MM/DD/YYYY vs DD/MM/YYYY)
            is_mm_dd_global = False
            for line in lines:
                m = re.search(r'(?<!\d)([01]?\d/[0-3]?\d/\d{2,4})', line)
                if m:
                    p = m.group(1).split('/')
                    if len(p) == 3 and int(p[0]) <= 12 and int(p[1]) > 12:
                        is_mm_dd_global = True
                        break

            found_events = []
            seen_events = set()
            current_date = "N/A"
            
            for i, line in enumerate(lines):
                # Bersihkan karakter kontrol dan sisa sequence )1, (I, dll
                clean_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', line)
                clean_line = re.sub(r'\)[0-9]|\([A-Z]', '', clean_line).strip()
                
                def normalize_date(d_str):
                    if not d_str or d_str == "N/A": return "N/A"
                    parts = re.split(r'[/]', d_str)
                    if len(parts) == 3:
                        p1, p2, p3 = parts
                        # Jika terdeteksi format global MM/DD/YYYY, tukar ke DD/MM/YYYY
                        if is_mm_dd_global:
                            return f"{p2.zfill(2)}/{p1.zfill(2)}/{p3}"
                        return f"{p1.zfill(2)}/{p2.zfill(2)}/{p3}"
                    return d_str

                # Update tanggal & jam dari format header NCR: *879*08/05/2025*14:43*
                ncr_header = re.search(r'\*(\d+)\*(\d{1,2}/\d{1,2}/\d{4})\*(\d{1,2}:\d{2})\*', clean_line)
                if ncr_header:
                    current_date = normalize_date(ncr_header.group(2))
                    jam = ncr_header.group(3)
                else:
                    # Update tanggal dari format umum (pastikan tidak ada angka nempel di depan)
                    date_match = re.search(r'(?<!\d)(\d{1,2}/\d{1,2}/\d{2,4})', clean_line)
                    if date_match:
                        raw_date = date_match.group(1)
                        # Tambahkan 20 jika tahun hanya 2 digit
                        if len(raw_date.split('/')[-1]) == 2:
                            d, m, y = raw_date.split('/')
                            raw_date = f"{d}/{m}/20{y}"
                        current_date = normalize_date(raw_date)
                
                # Cek apakah baris mengandung pola pembukaan brankas
                is_vault_open = any(re.search(p, clean_line.upper()) for p in vault_patterns)
                
                if is_vault_open:
                    # Ambil jam dari baris tersebut (HH:MM:SS atau HH:MM)
                    jam_match = re.search(r'(?<!\d)(\d{1,2}:\d{2}(?::\d{2})?)', clean_line)
                    if jam_match:
                        jam = jam_match.group(1)
                    
                    # Jika jam masih N/A, cari di sekitar
                    if jam == "N/A":
                        for offset in range(-3, 4):
                            if 0 <= i + offset < len(lines):
                                nearby_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', lines[i+offset])
                                nearby_line = re.sub(r'\)[0-9]|\([A-Z]', '', nearby_line).strip()
                                j_match = re.search(r'(?<!\d)(\d{1,2}:\d{2}(?::\d{2})?)', nearby_line)
                                if j_match:
                                    jam = j_match.group(1)
                                    break
                    
                    # De-duplikasi: Hanya masukkan jika (tanggal, jam) belum pernah dicatat dalam 1 menit yang sama
                    event_id = f"{current_date}_{jam}"
                    if event_id not in seen_events:
                        found_events.append(f" > [{current_date}] JAM {jam} - STATUS: BRANKAS DIBUKA")
                        seen_events.add(event_id)

            if not found_events:
                self.log_message("Hasil: Tidak ditemukan catatan pembukaan brankas dalam log ini.")
            else:
                self.log_message(f"Total Pembukaan Brankas: {len(found_events)} kali")
                self.log_message("-" * 40)
                for event in found_events:
                    self.log_message(event)
                
                # Simpan juga ke Excel jika perlu
                if messagebox.askyesno("Export", "Apakah Anda ingin menyimpan riwayat ini ke Excel?"):
                    headers = ["TANGGAL", "WAKTU", "STATUS"]
                    rows_excel = []
                    for e in found_events:
                        # e format: " > [12/09/2025] JAM 07:02:14 - STATUS: BRANKAS DIBUKA"
                        tgl = re.search(r'\[(.*?)\]', e).group(1)
                        jm = re.search(r'JAM (.*?) -', e).group(1)
                        rows_excel.append([tgl, jm, "BRANKAS DIBUKA"])
                    self.save_to_excel("Vault_Log", headers, rows_excel)
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def handle_drop_join(self, event):
        path = event.data
        if path.startswith('{') and path.endswith('}'):
            path = path[1:-1]
        
        if os.path.isdir(path):
            self.join_dir.set(path)
            self.log_message(f"Folder dimuat via Drag & Drop: {os.path.basename(path)}")
        elif os.path.isfile(path):
            folder = os.path.dirname(path)
            self.join_dir.set(folder)
            self.log_message(f"Folder terdeteksi dari file: {folder}")
        else:
            messagebox.showwarning("Peringatan", "Hanya file atau folder yang didukung untuk di-drop di sini.")

    def handle_drop(self, event):
        file_path = event.data
        # Bersihkan path jika ada kurung kurawal (biasa di Windows untuk path dengan spasi)
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
        
        if os.path.isfile(file_path):
            self.file_path.set(file_path)
            self.log_message(f"File dimuat via Drag & Drop: {os.path.basename(file_path)}")
            self.auto_detect_initial_balance()
        else:
            messagebox.showwarning("Peringatan", "Hanya file yang didukung untuk di-drop di sini.")

    # --- Business Logic (Preserved from original) ---

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.file_path.set(filename)
            self.auto_detect_initial_balance()

    def browse_join_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.join_dir.set(directory)

    def run_join_files(self):
        source_dir = self.join_dir.get()
        if not source_dir or not os.path.exists(source_dir):
            messagebox.showerror("Error", "Silakan pilih folder yang valid terlebih dahulu.")
            return
        
        # Cari semua file (kita akan memproses semua file kecuali folder)
        all_files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
        
        if not all_files:
            messagebox.showwarning("Peringatan", "Tidak ditemukan file di folder tersebut.")
            return
        
        # Urutkan file agar penggabungan konsisten (penting untuk urutan tanggal log)
        all_files.sort()
        
        # Tanya lokasi file output
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="Hasil_Gabungan_EJ.txt",
            title="Simpan File Hasil Gabungan"
        )
        
        if not output_file:
            return
            
        self.clear_log()
        self.log_message(f"--- Memulai Penggabungan File ({len(all_files)} file) ---")
        
        try:
            count = 0
            with open(output_file, 'w', encoding='utf-8') as outfile:
                for filename in all_files:
                    file_path = os.path.join(source_dir, filename)
                    self.log_message(f"Menggabungkan: {filename}...")
                    # Gunakan errors='ignore' untuk menangani karakter non-utf8 yang sering ada di log EJ
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                        content = infile.read()
                        outfile.write(content)
                        # Tambahkan newline jika file tidak diakhiri newline agar tidak menempel antar log
                        if content and not content.endswith('\n'):
                            outfile.write("\n")
                    count += 1
            
            self.log_message(f"--- Selesai! Berhasil menggabungkan {count} file ---")
            self.log_message(f"Output: {output_file}")
            messagebox.showinfo("Sukses", f"Berhasil menggabungkan {count} file ke:\n{output_file}")
            
            # Set output file sebagai file aktif untuk analisa jika user mau
            if messagebox.askyesno("Info", "Apakah Anda ingin menggunakan file hasil gabungan ini untuk analisa?"):
                self.file_path.set(output_file)
                self.select_frame_by_name("atm")
                
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Gagal menggabungkan file: {str(e)}")

    def log_message(self, message):
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")

    def clear_log(self):
        self.output_text.delete("1.0", "end")

    def open_excel(self):
        if os.path.exists(self.excel_output):
            try:
                os.startfile(self.excel_output)
            except Exception as e:
                messagebox.showerror("Error", f"Gagal membuka file: {str(e)}")
        else:
            messagebox.showwarning("Peringatan", "File hasil belum dibuat. Silakan jalankan analisa terlebih dahulu.")

    def delete_excel(self):
        if os.path.exists(self.excel_output):
            if messagebox.askyesno("Konfirmasi", f"Apakah Anda yakin ingin menghapus file '{self.excel_output}'?"):
                try:
                    os.remove(self.excel_output)
                    self.log_message(f"File '{self.excel_output}' berhasil dihapus.")
                    messagebox.showinfo("Sukses", "File berhasil dihapus.")
                except Exception as e:
                    messagebox.showerror("Error", f"Gagal menghapus file: {str(e)}")
        else:
            messagebox.showwarning("Peringatan", "File hasil tidak ditemukan.")

    def save_to_excel(self, sheet_prefix, headers, data_rows):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sheet_name = f"{sheet_prefix}_{timestamp}"[:31]
        try:
            if os.path.exists(self.excel_output):
                wb = load_workbook(self.excel_output)
            else:
                wb = Workbook()
                if "Sheet" in wb.sheetnames:
                    del wb["Sheet"]
            ws = wb.create_sheet(title=sheet_name)
            ws.append(headers)
            data_end_row = 1
            for row in data_rows:
                is_summary = False
                if isinstance(row, list) and len(row) > 0:
                    if str(row[0]).startswith('---') or 'AWAL' in str(row[0]) or 'SISA' in str(row[0]) or 'TOTAL TERPAKAI' in str(row[0]):
                        is_summary = True
                if not is_summary:
                    data_end_row += 1
                if isinstance(row, str):
                    row_data = [item.strip() for item in row.split('|')]
                else:
                    row_data = row
                processed_row = []
                for item in row_data:
                    if isinstance(item, str):
                        clean_item = item.replace('.','').replace(',','')
                        if clean_item.isdigit():
                            try: processed_row.append(int(clean_item))
                            except: processed_row.append(item)
                        else: processed_row.append(item)
                    else: processed_row.append(item)
                ws.append(processed_row)
            if sheet_prefix in ["CashIn", "Withdraw", "Hitachi_CashIn", "Hitachi_Withdraw"]:
                ws.append(["", "", "", "", "", "GRAND TOTAL", f"=SUM(G2:G{data_end_row})"])
            elif sheet_prefix == "Hyosung":
                ws.append(["", "", "GRAND TOTAL", f"=SUM(D2:D{data_end_row})", f"=SUM(E2:E{data_end_row})"])
            elif sheet_prefix == "NCR":
                ws.append(["", "", "", "", "GRAND TOTAL", f"=SUM(E2:E{data_end_row})"])
            wb.save(self.excel_output)
            self.log_message(f"Data auto-tersimpan di Excel: Sheet '{sheet_name}'")
        except Exception as e:
            self.log_message(f"Gagal menyimpan ke Excel: {str(e)}")
            messagebox.showerror("Excel Error", f"Pastikan file '{self.excel_output}' tidak sedang dibuka di aplikasi lain.")

    def detect_brand(self, file_log):
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(50000)
                if "MACHINE :" in head or "OP Code" in head: return "HYOSUNG"
                elif "ATM ID        :" in head and re.search(r'C\d{3}', head): return "HITACHI"
                elif "notes dispensed" in head.lower() or "CASH IN" in head.upper(): return "HYOSUNG/HITACHI"
            return "HYOSUNG (Asumsi)"
        except: return "UNKNOWN"

    def run_hyosung(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        brand = self.detect_brand(file_log)
        self.log_message(f"--- Memulai Analisa (Merk: {brand}) ---")
        try:
            stok_awal = int(self.lembar_awal.get())
        except ValueError:
            stok_awal = 0
            self.log_message("Peringatan: Lembar Awal tidak valid, dianggap 0.")
        semua_data = []
        grand_total_lembar = 0
        grand_total_rp = 0
        main_denom = 0
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f_log:
                lines = f_log.readlines()
            for i, line in enumerate(lines):
                clean_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', line).strip()
                if "notes dispensed" in clean_line.lower():
                    date_match = re.search(r'(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})', clean_line)
                    tanggal = date_match.group(1) if date_match else "N/A"
                    jam = date_match.group(2) if date_match else "N/A"
                    denom_str = "N/A"
                    lembar_transaksi = 0
                    total_rp_transaksi = 0
                    for j in range(1, 11):
                        if (i + j) >= len(lines): break
                        next_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', lines[i+j]).strip()
                        match_denom = re.search(r'(?:IDR)?(\d+)\*(\d+)', next_line)
                        if match_denom:
                            d_val = int(match_denom.group(1))
                            l_val = int(match_denom.group(2))
                            if main_denom == 0: main_denom = d_val
                            if denom_str == "N/A": denom_str = str(d_val)
                            else: denom_str += f"+{d_val}"
                            lembar_transaksi += l_val
                            total_rp_transaksi += (d_val * l_val)
                        match_total = re.search(r'Total Amount (?:IDR)?\s*(\d+)', next_line, re.IGNORECASE)
                        if match_total:
                            total_rp_transaksi = int(match_total.group(1))
                            break
                        if re.search(r'\d{2}/\d{2}/\d{4}', next_line) and j > 1: break
                    if lembar_transaksi > 0:
                        semua_data.append([tanggal, jam, denom_str, lembar_transaksi, total_rp_transaksi])
                        grand_total_lembar += lembar_transaksi
                        grand_total_rp += total_rp_transaksi
            if not semua_data:
                self.log_message("Tidak ada data Notes Dispensed yang valid.")
                return
            if main_denom == 0: main_denom = 100000
            stok_awal_rp = stok_awal * main_denom
            sisa_lembar = stok_awal - grand_total_lembar
            sisa_rp = stok_awal_rp - grand_total_rp
            semua_data.append(['---']*5)
            semua_data.append(['STOK AWAL', '', f'Denom {main_denom:,}', stok_awal, stok_awal_rp])
            semua_data.append(['TOTAL TERPAKAI', '', '', grand_total_lembar, grand_total_rp])
            semua_data.append(['SISA (ESTIMASI)', '', '', sisa_lembar, sisa_rp])
            headers = ["TANGGAL", "JAM", "DENOM", "LEMBAR", "TOTAL RP"]
            self.save_to_excel("Hyosung", headers, semua_data)
            self.log_message(f"Berhasil! Ditemukan {len(semua_data)-4} transaksi.")
            self.log_message(f"Denom Terdeteksi: {main_denom:,}")
            self.log_message(f"Stok Awal     : {stok_awal:,} lbr (Rp {stok_awal_rp:,})")
            self.log_message(f"Total Terpakai: {grand_total_lembar:,} lbr (Rp {grand_total_rp:,})")
            self.log_message(f"Sisa Estimasi : {sisa_lembar:,} lbr (Rp {sisa_rp:,})")
        except Exception as e: self.log_message(f"Error: {str(e)}")

    def run_ncr(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Memulai Analisa NCR (Akurasi Tinggi) ---")
        try:
            stok_awal = int(self.lembar_awal.get())
            d1 = int(self.denom_k1.get())
            d2 = int(self.denom_k2.get())
            d3 = int(self.denom_k3.get())
            d4 = int(self.denom_k4.get())
        except ValueError:
            messagebox.showerror("Error", "Input Lembar Awal atau Denominasi harus berupa angka.")
            return
        
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            semua_data = []
            total_l_k1 = total_l_k2 = total_l_k3 = total_l_k4 = 0
            total_rp_kaset = total_rp_struk = 0
            
            # State variables
            current_date = "N/A"
            last_notes = None
            last_jam = "N/A"
            
            # Untuk mencari sisa lembar terakhir dari log
            final_remaining = [0, 0, 0, 0]
            found_machine_remaining = False
            
            for i, line in enumerate(lines):
                clean_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', line).strip()
                if not clean_line: continue
                
                # Update tanggal
                date_match = re.search(r'(\d{2}/\d{2}/\d{4})', clean_line)
                if date_match:
                    current_date = date_match.group(1)
                
                # Cari baris NOTES PRESENTED
                # Pola: 06:42:26 NOTES PRESENTED 0,0,1,0
                presented_match = re.search(r'(\d{2}:\d{2}:\d{2})?\s*NOTES PRESENTED\s+([0-9,]+)', clean_line, re.IGNORECASE)
                if presented_match:
                    jam_p = presented_match.group(1) if presented_match.group(1) else "N/A"
                    notes_str = presented_match.group(2)
                    try:
                        last_notes = [int(n) for n in notes_str.split(',')]
                        last_jam = jam_p
                    except: last_notes = None
                
                # Cari konfirmasi CASHTAKEN
                # Jika ketemu CASHTAKEN, kita cari detail transaksi di baris-baris setelahnya
                if "CASHTAKEN" in clean_line.upper() and last_notes:
                    # Cari TXN NO dan AMOUNT di 50 baris ke depan
                    txn_no = "N/A"
                    amount_struk = 0
                    
                    for j in range(1, 60):
                        if (i + j) >= len(lines): break
                        future_line = re.sub(r'[\x00-\x1f\x7f-\xff\x1b]', '', lines[i+j]).strip()
                        
                        # Cari TXN NO
                        t_match = re.search(r'TXN NO\s*:\s*(\d+)', future_line, re.IGNORECASE)
                        if t_match: txn_no = t_match.group(1)
                        
                        # Cari AMOUNT
                        a_match = re.search(r'AMOUNT\s*:\s*([\d.,]+)', future_line, re.IGNORECASE)
                        if a_match:
                            try: amount_struk = int(a_match.group(1).replace('.', '').replace(',', ''))
                            except: pass
                        
                        # Jika sudah ketemu TXN TYPE : CASH WITHDRAWAL, biasanya data struk sudah lengkap
                        if "CASH WITHDRAWAL" in future_line.upper():
                            # Kita tunggu sedikit lagi untuk memastikan amount terbaca
                            pass
                        
                        # Berhenti jika ketemu separator baru atau transaksi baru
                        if "-------------------" in future_line and j > 10: break

                    # Catat transaksi sukses
                    l1, l2, l3, l4 = last_notes
                    total_l = sum(last_notes)
                    rp_kaset = (l1*d1) + (l2*d2) + (l3*d3) + (l4*d4)
                    
                    semua_data.append([current_date, last_jam, txn_no, amount_struk, l1, l2, l3, l4, total_l, rp_kaset])
                    
                    # Akumulasi
                    total_l_k1 += l1; total_l_k2 += l2; total_l_k3 += l3; total_l_k4 += l4
                    total_rp_kaset += rp_kaset
                    total_rp_struk += amount_struk
                    
                    # Reset last_notes agar tidak terhitung dua kali
                    last_notes = None
                
                # Cari data REMAINING mesin (untuk validasi sisa lembar)
                # Pola: REMAINING        00000 00000 01908 00000
                rem_match = re.search(r'REMAINING\s+(\d{5})\s+(\d{5})\s+(\d{5})\s+(\d{5})', clean_line, re.IGNORECASE)
                if rem_match:
                    try:
                        final_remaining = [int(rem_match.group(k)) for k in range(1, 5)]
                        found_machine_remaining = True
                    except: pass

            if not semua_data:
                self.log_message("Tidak ditemukan transaksi CASH WITHDRAWAL yang berstatus Cash Taken.")
                return
            
            total_l_terpakai = total_l_k1 + total_l_k2 + total_l_k3 + total_l_k4
            
            # Gunakan sisa lembar dari mesin jika ditemukan, jika tidak gunakan kalkulasi manual
            if found_machine_remaining:
                sisa_l_fisik = sum(final_remaining)
                self.log_message(f"Info: Ditemukan sisa lembar fisik mesin: {sisa_l_fisik} lbr.")
                sisa_l = sisa_l_fisik
            else:
                sisa_l = stok_awal - total_l_terpakai
            
            stok_awal_rp = stok_awal * d1 # Estimasi
            sisa_rp = sisa_l * d1 # Estimasi
            
            # Ringkasan Excel
            semua_data.append(['---']*10)
            semua_data.append(['RINGKASAN', '', '', 'STRUK RP', 'KASET 1', 'KASET 2', 'KASET 3', 'KASET 4', 'TOTAL LBR', 'TOTAL RP'])
            semua_data.append(['TOTAL', '', '', total_rp_struk, total_l_k1, total_l_k2, total_l_k3, total_l_k4, total_l_terpakai, total_rp_kaset])
            semua_data.append(['STOK AWAL', '', '', '', '', '', '', '', stok_awal, stok_awal_rp])
            semua_data.append(['SISA LEMBAR', '', '', '', '', '', '', '', sisa_l, sisa_rp])
            
            headers = ['TANGGAL', 'JAM', 'TXN NO', 'AMOUNT STRUK', f'K1({d1})', f'K2({d2})', f'K3({d3})', f'K4({d4})', 'TOT LBR', 'TOT RP KASET']
            self.save_to_excel("NCR", headers, semua_data)
            
            self.log_message(f"--- Hasil Analisa Akurasi NCR ---")
            self.log_message(f"Berhasil! Ditemukan {len(semua_data)-5} transaksi sukses (Cash Taken).")
            self.log_message(f"Total Lembar Terpakai: {total_l_terpakai:,} lbr")
            self.log_message(f"Sisa Lembar di Mesin: {sisa_l:,} lbr")
            self.log_message(f"--------------------------------------------------")
            self.log_message(f"Total Nominal Struk: Rp {total_rp_struk:,}")
            self.log_message(f"Total Nominal Kaset: Rp {total_rp_kaset:,}")
            
            if total_rp_struk != total_rp_kaset:
                self.log_message(f"PERINGATAN: Selisih Struk vs Kaset = Rp {total_rp_struk - total_rp_kaset:,}")
            
            messagebox.showinfo("Sukses", f"Analisa Selesai!\nTerpakai: {total_l_terpakai:,} lbr\nSisa: {sisa_l:,} lbr")
            
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Gagal menjalankan analisa NCR: {str(e)}")

    def process_cashin(self, content):
        blocks = re.split(r'\[Jpr contents\]|\[Transaction record\]', content)
        results = []
        for block in blocks:
            if "CASH IN" not in block.upper(): continue
            if "TRANSACTION HAVE A PROBLEM!" in block.upper(): continue
            data = {'ATM ID': None, 'TXN NO': None, 'DATE': None, 'TIME': None, 'TXN TYPE': "CASH IN", 'AMOUNT': 0}
            match_txn = re.search(r'TXN NO\s*:\s*(\d+)', block)
            if not match_txn: match_txn = re.search(r'^\s*(\d+)\s*\*{6,}\s*CASH IN', block, re.MULTILINE)
            if match_txn: data['TXN NO'] = match_txn.group(1)
            match_atm = re.search(r'ATM ID\s*:\s*(\S+)', block)
            if not match_atm: match_atm = re.search(r'ATM_ID:\s*(\S+)', block)
            if match_atm: data['ATM ID'] = match_atm.group(1)
            match_dt = re.search(r'DATE & TIME\s*:\s*(\d{2}/\d{2}/\d{4})\s*(\d{2}:\d{2}:\d{2})', block)
            if not match_dt: match_dt = re.search(r'DATE:\s*(\d{2}/\d{2}/\d{4})\s*(\d{2}:\d{2}:\d{2})', block)
            if match_dt:
                data['DATE'] = match_dt.group(1).replace('/', '-')
                data['TIME'] = match_dt.group(2)
            match_amt = re.search(r'AMOUNT\s*:\s*([\d.,]+)', block, re.IGNORECASE)
            if match_amt:
                amt = int(match_amt.group(1).replace('.', '').replace(',', ''))
                if amt > 0: data['AMOUNT'] = amt
            if data['AMOUNT'] == 0:
                match_rec = re.search(r'Amount\s*\[(\d+)\]', block)
                if match_rec:
                    amt_val = int(match_rec.group(1))
                    if amt_val > 0: data['AMOUNT'] = amt_val
            if data['ATM ID'] and data['TXN NO'] and data['DATE'] and data['AMOUNT'] > 0:
                atm_id = data['ATM ID']
                if not atm_id.startswith('AT'): atm_id = 'AT' + atm_id
                results.append(f"{atm_id}| {data['DATE']}| {data['TIME']}| {data['TXN NO']}| {data['TXN TYPE']}| {data['AMOUNT']}")
        seen_txns = set()
        unique_results = []
        final_grand_total = 0
        for res in results:
            txn_no = res.split('|')[3].strip()
            if txn_no not in seen_txns:
                seen_txns.add(txn_no)
                unique_results.append(res)
                final_grand_total += int(res.split('|')[5].strip())
        return unique_results, final_grand_total

    def run_cashin(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Memulai Rekap Cash In CRM ---")
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            results, grand_total_idr = self.process_cashin(content)
            if not results:
                self.log_message("Tidak ditemukan transaksi Cash In (dengan nominal > 0).")
                return
            results_with_idx = []
            for idx, res in enumerate(results, 1): results_with_idx.append(f"{idx}| {res}")
            headers = ["#", "ATM", "TANGGAL", "WAKTU", "NO.REF", "TRANSAKSI", "TOTAL"]
            self.save_to_excel("CashIn", headers, results_with_idx)
            self.log_message(f"Berhasil merekap {len(results)} transaksi Cash In.")
            self.log_message(f"TOTAL IDR MASUK: {grand_total_idr:,}")
            for res in results_with_idx: self.log_message(res)
        except Exception as e: self.log_message(f"Error: {str(e)}")

    def process_withdraw(self, content):
        blocks = re.split(r'\[Jpr contents\]', content)
        results = []
        for i in range(len(blocks) - 1):
            current_block = blocks[i]
            next_block = blocks[i+1]
            jpr_match = re.search(r'TXN TYPE\s*:\s*(?:CASH WITHDRAWAL|ATM CASH OUT|WITHDRAWAL)', next_block, re.IGNORECASE)
            if not jpr_match: continue
            if "Cash Taken" not in current_block: continue
            data = {'ATM ID': None, 'TXN NO': None, 'DATE': None, 'TIME': None, 'TXN TYPE': "WITHDRAWAL", 'AMOUNT': 0}
            match_txn = re.search(r'TXN NO\s*:\s*(\d+)', next_block)
            if match_txn: data['TXN NO'] = match_txn.group(1)
            match_atm = re.search(r'ATM ID\s*:\s*(\S+)', next_block)
            if match_atm: data['ATM ID'] = match_atm.group(1)
            match_dt = re.search(r'DATE & TIME\s*:\s*(\d{2}/\d{2}/\d{4})\s*(\d{2}:\d{2}:\d{2})', next_block)
            if match_dt:
                data['DATE'] = match_dt.group(1).replace('/', '-')
                data['TIME'] = match_dt.group(2)
            match_amt = re.search(r'AMOUNT\s*:\s*([\d.,]+)', next_block, re.IGNORECASE)
            if match_amt:
                amt = int(match_amt.group(1).replace('.', '').replace(',', ''))
                if amt > 0: data['AMOUNT'] = amt
            if data['AMOUNT'] == 0:
                match_rec = re.search(r'Amount\s*\[(\d+)\]', next_block)
                if match_rec:
                    amt_val = int(match_rec.group(1))
                    if amt_val > 0: data['AMOUNT'] = amt_val
            if data['ATM ID'] and data['TXN NO'] and data['DATE'] and data['AMOUNT'] > 0:
                atm_id = data['ATM ID']
                if not atm_id.startswith('AT'): atm_id = 'AT' + atm_id
                results.append(f"{atm_id}| {data['DATE']}| {data['TIME']}| {data['TXN NO']}| {data['TXN TYPE']}| {data['AMOUNT']}")
        seen_txns = set()
        unique_results = []
        final_grand_total = 0
        for res in results:
            txn_no = res.split('|')[3].strip()
            if txn_no not in seen_txns:
                seen_txns.add(txn_no)
                unique_results.append(res)
                final_grand_total += int(res.split('|')[5].strip())
        return unique_results, final_grand_total

    def run_withdraw(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Memulai Rekap Withdraw CRM (Hanya Cash Taken) ---")
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            results, grand_total_idr = self.process_withdraw(content)
            if not results:
                self.log_message("Tidak ditemukan transaksi Cash Withdrawal dengan status Cash Taken.")
                return
            results_with_idx = []
            for idx, res in enumerate(results, 1): results_with_idx.append(f"{idx}| {res}")
            headers = ["#", "ATM", "TANGGAL", "WAKTU", "NO.REF", "TRANSAKSI", "TOTAL"]
            self.save_to_excel("Withdraw", headers, results_with_idx)
            self.log_message(f"Berhasil merekap {len(results)} transaksi penarikan yang berhasil.")
            self.log_message(f"TOTAL IDR KELUAR: {grand_total_idr:,}")
            for res in results_with_idx: self.log_message(res)
        except Exception as e: self.log_message(f"Error: {str(e)}")

    def process_hitachi_cashin(self, content):
        cycles = content.split('==> Transaction Start')
        results = []
        for cycle in cycles:
            txn_matches = list(re.finditer(r'TXN NO\s*:\s*(\d+)', cycle))
            for i, match in enumerate(txn_matches):
                txn_no = match.group(1)
                start_pos = match.start()
                context = cycle[max(0, start_pos-300) : min(len(cycle), start_pos+500)]
                if "CASH IN" in context.upper():
                    data = {'ATM ID': None, 'TXN NO': txn_no, 'DATE': None, 'TIME': None, 'TXN TYPE': "CASH IN", 'AMOUNT': 0}
                    match_id = re.search(r'ATM ID\s*:\s*(\S+)', context)
                    if match_id: data['ATM ID'] = match_id.group(1)
                    match_dt = re.search(r'DATE & TIME\s*:\s*(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})', context)
                    if match_dt:
                        data['DATE'] = match_dt.group(1).replace('/', '-')
                        data['TIME'] = match_dt.group(2)
                    match_amt = re.search(r'AMOUNT\s*:\s*([\d.,]+)\s*IDR', context)
                    if match_amt: data['AMOUNT'] = int(re.sub(r'[.,]', '', match_amt.group(1)))
                    if data['AMOUNT'] == 0:
                        denom_50 = re.search(r'IDR50000:(\d+)', cycle[start_pos:min(len(cycle), start_pos+2000)])
                        denom_100 = re.search(r'IDR100000:(\d+)', cycle[start_pos:min(len(cycle), start_pos+2000)])
                        val_50 = int(denom_50.group(1)) if denom_50 else 0
                        val_100 = int(denom_100.group(1)) if denom_100 else 0
                        data['AMOUNT'] = (val_50 * 50000) + (val_100 * 100000)
                    if data['ATM ID'] and data['DATE'] and data['AMOUNT'] > 0:
                        results.append(f"{data['ATM ID']}| {data['DATE']}| {data['TIME']}| {data['TXN NO']}| {data['TXN TYPE']}| {data['AMOUNT']}")
        seen = set(); unique_results = []; final_total = 0
        for res in results:
            txn = res.split('|')[3].strip()
            if txn not in seen:
                seen.add(txn); unique_results.append(res)
                final_total += int(res.split('|')[5].strip())
        return unique_results, final_total

    def process_hitachi_withdraw(self, content):
        results = []
        txn_matches = list(re.finditer(r'TXN NO\s*:\s*(\d+)', content))
        for i, match in enumerate(txn_matches):
            txn_no = match.group(1); start_pos = match.start()
            context = content[max(0, start_pos-300) : min(len(content), start_pos+500)]
            data = {'ATM ID': None, 'TXN NO': txn_no, 'DATE': None, 'TIME': None, 'TXN TYPE': "N/A", 'AMOUNT': 0}
            match_id = re.search(r'ATM ID\s*:\s*(\S+)', context)
            if match_id: data['ATM ID'] = match_id.group(1)
            match_dt = re.search(r'DATE & TIME\s*:\s*(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})', context)
            if match_dt:
                data['DATE'] = match_dt.group(1).replace('/', '-')
                data['TIME'] = match_dt.group(2)
            match_type = re.search(r'TXN TYPE\s*:\s*(.*)', context)
            if match_type: data['TXN TYPE'] = match_type.group(1).strip()
            match_amt = re.search(r'AMOUNT\s*:\s*([\d.,]+)\s*IDR', context)
            if match_amt: data['AMOUNT'] = int(re.sub(r'[.,]', '', match_amt.group(1)))
            if "CASH WITHDRAWAL" in data['TXN TYPE'].upper():
                search_end = len(content)
                if i + 1 < len(txn_matches): search_end = txn_matches[i+1].start()
                after_text = content[start_pos : search_end]
                if 'Cash Taken' in after_text:
                    if data['ATM ID'] and data['DATE']:
                        results.append(f"{data['ATM ID']}| {data['DATE']}| {data['TIME']}| {data['TXN NO']}| WITHDRAWAL| {data['AMOUNT']}")
        seen = set(); unique_results = []; final_total = 0
        for res in results:
            txn = res.split('|')[3].strip()
            if txn not in seen:
                seen.add(txn); unique_results.append(res)
                final_total += int(res.split('|')[5].strip())
        return unique_results, final_total

    def run_hitachi_cashin(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Memulai Rekap Cash In HITACHI ---")
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            unique_results, grand_total = self.process_hitachi_cashin(content)
            if not unique_results:
                self.log_message("Tidak ditemukan transaksi Cash In Hitachi.")
                return
            results_with_idx = [f"{idx}| {res}" for idx, res in enumerate(unique_results, 1)]
            headers = ["#", "ATM", "TANGGAL", "WAKTU", "NO.REF", "TRANSAKSI", "TOTAL"]
            self.save_to_excel("Hitachi_CashIn", headers, results_with_idx)
            self.log_message(f"Berhasil merekap {len(unique_results)} transaksi Cash In Hitachi.")
            self.log_message(f"TOTAL IDR MASUK: {grand_total:,}")
            for res in results_with_idx: self.log_message(res)
        except Exception as e: self.log_message(f"Error: {str(e)}")

    def run_hitachi_withdraw(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Memulai Rekap Withdraw HITACHI ---")
        try:
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            unique_results, grand_total = self.process_hitachi_withdraw(content)
            if not unique_results:
                self.log_message("Tidak ditemukan transaksi Withdraw Hitachi dengan Cash Taken.")
                return
            results_with_idx = [f"{idx}| {res}" for idx, res in enumerate(unique_results, 1)]
            headers = ["#", "ATM", "TANGGAL", "WAKTU", "NO.REF", "TRANSAKSI", "TOTAL"]
            self.save_to_excel("Hitachi_Withdraw", headers, results_with_idx)
            self.log_message(f"Berhasil merekap {len(unique_results)} transaksi Withdraw Hitachi.")
            self.log_message(f"TOTAL IDR KELUAR: {grand_total:,}")
            for res in results_with_idx: self.log_message(res)
        except Exception as e: self.log_message(f"Error: {str(e)}")

    def run_hitachi_balance(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Menghitung Saldo Akhir CRM HITACHI ---")
        try:
            try: pengisian = int(self.pengisian_awal_hitachi.get().replace('.', '').replace(',', ''))
            except ValueError:
                pengisian = 0
                self.log_message("Peringatan: Pengisian Awal tidak valid, dianggap 0.")
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            _, total_cashin = self.process_hitachi_cashin(content)
            _, total_withdraw = self.process_hitachi_withdraw(content)
            saldo_akhir = pengisian + total_cashin - total_withdraw
            self.log_message(f"Pengisian Awal : {pengisian:,}")
            self.log_message(f"Total Cash In  : {total_cashin:,} (+)")
            self.log_message(f"Total Withdraw : {total_withdraw:,} (-)")
            self.log_message(f"-----------------------------------")
            self.log_message(f"SALDO AKHIR CRM HITACHI: {saldo_akhir:,}")
            data_ringkasan = [
                ["KETERANGAN", "JUMLAH (Rp)"], ["PENGISIAN AWAL", pengisian],
                ["TOTAL CASH IN (HITACHI)", total_cashin], ["TOTAL WITHDRAW (HITACHI)", total_withdraw],
                ["---", "---"], ["SALDO AKHIR CRM HITACHI", saldo_akhir]
            ]
            self.save_to_excel("SaldoCRM_Hitachi", ["Ringkasan CRM Hitachi", ""], data_ringkasan)
            messagebox.showinfo("Sukses", f"Perhitungan Selesai (Hitachi)!\nSaldo Akhir: Rp {saldo_akhir:,}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Gagal menghitung saldo: {str(e)}")

    def run_crm_balance(self):
        file_log = self.file_path.get()
        if not os.path.exists(file_log):
            messagebox.showerror("Error", f"File '{file_log}' tidak ditemukan.")
            return
        self.clear_log()
        self.log_message(f"--- Menghitung Saldo Akhir CRM ---")
        try:
            try: pengisian = int(self.pengisian_awal.get().replace('.', '').replace(',', ''))
            except ValueError:
                pengisian = 0
                self.log_message("Peringatan: Pengisian Awal tidak valid, dianggap 0.")
            with open(file_log, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            _, total_cashin = self.process_cashin(content)
            _, total_withdraw = self.process_withdraw(content)
            saldo_akhir = pengisian + total_cashin - total_withdraw
            self.log_message(f"Pengisian Awal : {pengisian:,}")
            self.log_message(f"Total Cash In  : {total_cashin:,} (+)")
            self.log_message(f"Total Withdraw : {total_withdraw:,} (-)")
            self.log_message(f"-----------------------------------")
            self.log_message(f"SALDO AKHIR CRM: {saldo_akhir:,}")
            data_ringkasan = [
                ["KETERANGAN", "JUMLAH (Rp)"], ["PENGISIAN AWAL", pengisian],
                ["TOTAL CASH IN", total_cashin], ["TOTAL WITHDRAW", total_withdraw],
                ["---", "---"], ["SALDO AKHIR CRM", saldo_akhir]
            ]
            self.save_to_excel("SaldoCRM", ["Ringkasan CRM", ""], data_ringkasan)
            messagebox.showinfo("Sukses", f"Perhitungan Selesai!\nSaldo Akhir: Rp {saldo_akhir:,}")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Gagal menghitung saldo: {str(e)}")

if __name__ == "__main__":
    def launch_main_app():
        app = AtmLogAnalyzer()
        app.mainloop()

    login = LoginWindow(on_success=launch_main_app)
    login.mainloop()
