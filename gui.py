import tkinter as tk
from tkinter import ttk, filedialog
from collections import Counter
from scapy.all import wrpcap, Ether
import os
import ipaddress
from shared import packet_queue
from collections import Counter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import defaultdict
import time
import smtplib
from email.mime.text import MIMEText
from config import EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER
import requests
from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
from scapy.all import sniff, IP
from shared import packet_queue

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")

# -------- DARK THEME --------
BG_COLOR = "#0f172a"       # dark blue
FG_COLOR = "#e2e8f0"       # light text
ACCENT = "#38bdf8"         # cyan
ALERT_RED = "#ef4444"
OK_GREEN = "#22c55e"
CARD_BG = "#1e293b"

class NIDSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NIDS-Monitor")
        self.root.geometry("1400x800")
        self.root.configure(bg=BG_COLOR)

        self.last_alert_time = 0
        self.last_net_alert = 0
        self.NET_ALERT_COOLDOWN = 30
        self.ALERT_COOLDOWN = 5
            # 🔥 ADD HEADER HERE (TOP)
        header = tk.Frame(self.root, bg=BG_COLOR)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🛡 NIDS Security Dashboard",
            bg=BG_COLOR,
            fg=ACCENT,
            font=("Segoe UI", 14, "bold")
        ).pack(pady=5)

        style = ttk.Style()
        style.theme_use("default")

        style.configure("Treeview",
            background=CARD_BG,
            foreground=FG_COLOR,
            fieldbackground=CARD_BG,
            rowheight=25
        )

        style.configure("Treeview.Heading",
        background=BG_COLOR,
        foreground=ACCENT,
        font=("Segoe UI", 10, "bold")
        )

        style.map("Treeview",
            background=[("selected", "#334155")]
        )

        self.packet_map = {}
        self.all_packets = []
        self.total = 0
        self.traffic_history = []
        self.protocol_counter = Counter()

                # 🔥 ADD HERE (correct place)
        self.attack_counter = Counter()
        self.country_counter = Counter()
        self.alert_timeline = []          # time आधरत
        self.attacker_counter = defaultdict(int)

        self.blink = False
        self.alert_items = set()

        self.auto_scroll = tk.BooleanVar(value=True)

        # SEARCH
        self.filter_text = tk.StringVar()
        tk.Entry(root, textvariable=self.filter_text).pack(fill="x")

        # FILTER BAR
        filter_frame = tk.Frame(root)
        filter_frame.pack(fill="x")

        self.traffic_filter = tk.StringVar(value="ALL")
        self.proto_filter = tk.StringVar(value="ALL")
        self.status_filter = tk.StringVar(value="ALL")

        tk.Label(filter_frame, text="Traffic:").pack(side="left")
        tk.OptionMenu(filter_frame, self.traffic_filter, "ALL", "PUBLIC", "LOCAL").pack(side="left")

        tk.Label(filter_frame, text="Protocol:").pack(side="left")
        tk.OptionMenu(filter_frame, self.proto_filter, "ALL", "TCP", "UDP", "ICMP").pack(side="left")

        tk.Label(filter_frame, text="Status:").pack(side="left")
        tk.OptionMenu(filter_frame, self.status_filter, "ALL", "OK", "ALERT").pack(side="left")

        tk.Checkbutton(filter_frame, text="Auto Scroll", variable=self.auto_scroll).pack(side="left")


        # menu bar
        menu_bar = tk.Menu(self.root)

        # Dashboard Menu
        dashboard_menu = tk.Menu(menu_bar, tearoff=0)
        dashboard_menu.add_command(label="Live Attack Graph", command=self.open_attack_graph)
        dashboard_menu.add_command(label="Country Stats", command=self.open_country_graph)
        dashboard_menu.add_command(label="Full Dashboard",command=self.open_dashboard)

        menu_bar.add_cascade(label="Dashboard", menu=dashboard_menu)

        self.root.config(menu=menu_bar)

        # TABLE
        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True)

        scrollbar = tk.Scrollbar(table_frame)
        scrollbar.pack(side="right", fill="y")

        columns = ("SRC", "DST", "PROTO", "LEN", "STATUS", "COUNTRY", "ATTACK", "CONFIDENCE", "SEVERITY")

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            yscrollcommand=scrollbar.set
        )

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", width=120)

        self.tree.column("COUNTRY", width=200)
        self.tree.column("ATTACK", width=120)
        self.tree.heading("SEVERITY", text="SEVERITY")
        self.tree.column("SEVERITY", width=100)

        self.tree.pack(fill="both", expand=True)
        scrollbar.config(command=self.tree.yview)

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        # 🔥 USER SCROLL → AUTO OFF
        self.tree.bind("<MouseWheel>", self.disable_autoscroll)

        # DETAILS
        self.details = tk.Text(root, height=10, bg="#0d1117", fg="lightgreen")
        self.details.pack(fill="x")

        # BUTTONS
        btn_frame = tk.Frame(root)
        btn_frame.pack()

        self.styled_button(btn_frame, "Export PCAP", self.export_pcap).pack(side="left")
        self.styled_button(btn_frame, "Analysis", self.show_analysis).pack(side="left")
        self.styled_button(btn_frame, "Block IP", self.block_selected_ip).pack(side="left") 
        self.styled_button(btn_frame, "View Blacklist", self.view_blacklist).pack(side="left")
        self.styled_button(btn_frame, "Remove IP", self.remove_blacklist_ip).pack(side="left")
        self.styled_button(btn_frame, "Unblock IP", self.unblock_selected_ip).pack(side="left")

         # COLORS
        self.tree.tag_configure("tcp", foreground="cyan")
        self.tree.tag_configure("udp", foreground="orange")
        self.tree.tag_configure("icmp", foreground="white")
        self.tree.tag_configure("normal", foreground="lightgreen")

        self.tree.tag_configure("alert", background="#7f1d1d")
        self.tree.tag_configure("normal", background=CARD_BG)

        # 🔥 ATTACK COLORS
        self.tree.tag_configure("scan", background="#ffcc00", foreground="black")
        self.tree.tag_configure("flood", background="#ff1a1a", foreground="white")
        self.tree.tag_configure("anomaly", background="#cc00ff", foreground="white")

        self.tree.tag_configure("alert_on", background="#ff1a1a", foreground="white")
        self.tree.tag_configure("alert_off", background="#660000", foreground="white")

        self.tree.tag_configure("high", background="#7f1d1d")     # red
        self.tree.tag_configure("medium", background="#92400e")   # orange
        self.tree.tag_configure("low", background=CARD_BG)

        self.traffic_filter.trace("w", self.refresh_table)

        self.update_gui()
        self.blink_alerts()


    @staticmethod
    def process_packet(pkt):
        print(pkt.summary())

        analyze_packet(pkt)

        if not pkt.haslayer("IP"):
               return

        data = {
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": pkt[IP].proto,
            "len": len(pkt),
            "status": "OK",
            "country_name": "Local",
            "attack_type": "NORMAL",
            "confidence": 0,
            "severity": "Low"
        }

        print("PUT:", data)
        packet_queue.put(data)


    def send_email_alert(self, ip, attack, confidence):
        try:
            msg = MIMEText(f"""
    🚨 NIDS ALERT

    IP: {ip}
    Attack: {attack}
    Confidence: {confidence}%
    """)

            msg["Subject"] = "⚠ NIDS Security Alert"
            msg["From"] = EMAIL_SENDER
            msg["To"] = EMAIL_RECEIVER

            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()

            print("[EMAIL SENT]")
        except Exception as e:
            print("[EMAIL ERROR]", e)

    def send_telegram_alert(self, ip, attack, confidence):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

            message = f"""
    🚨 NIDS ALERT

    IP: {ip}
    Attack: {attack}
    Confidence: {confidence}%
    """

            requests.post(url, data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message
            })

            print("[TELEGRAM SENT]")
        except Exception as e:
            print("[TELEGRAM ERROR]", e)

    def trigger_alert(self, src_ip):
        import time
        now = time.time()

        print("Alert from:", src_ip)

    # 🔥 cooldown check
        if now - self.last_net_alert < self.NET_ALERT_COOLDOWN:
            return

        self.last_alert_time = now

    # 🔊 SOUND
        try:
            import os
            os.system("paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga")
        except:
            print("\a")  # fallback beep

    # 🚨 POPUP
        import tkinter.messagebox as msg

        msg.showwarning(
            "⚠ SECURITY ALERT",
            f"Blocked IP detected:\n{src_ip}"
        )

    def styled_button(self, parent, text, command):  # 🔥 self add कर
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=ACCENT,
            fg="black",
            activebackground="#0ea5e9",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=5
        )

    def open_dashboard(self):
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

        self.db_window = tk.Toplevel(self.root)
        self.db_window.title("Security Dashboard")
        self.db_window.geometry("900x600")
        plt.style.use("dark_background")

        notebook = ttk.Notebook(self.db_window)
        notebook.pack(fill="both", expand=True)

    # -------- TAB 1: ATTACK --------
        attack_tab = tk.Frame(notebook)
        notebook.add(attack_tab, text="Attack")

        self.fig1, self.ax1 = plt.subplots()
        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=attack_tab)
        self.canvas1.get_tk_widget().pack(fill="both", expand=True)

    # -------- TAB 2: COUNTRY --------
        country_tab = tk.Frame(notebook)
        notebook.add(country_tab, text="Country")

        self.fig2, self.ax2 = plt.subplots()
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=country_tab)
        self.canvas2.get_tk_widget().pack(fill="both", expand=True)

    # -------- TAB 3: TRAFFIC --------
        traffic_tab = tk.Frame(notebook)
        notebook.add(traffic_tab, text="Traffic")

        self.fig3, self.ax3 = plt.subplots()
        self.canvas3 = FigureCanvasTkAgg(self.fig3, master=traffic_tab)
        self.canvas3.get_tk_widget().pack(fill="both", expand=True)

    # -------- TAB 4: TIMELINE --------
        timeline_tab = tk.Frame(notebook)
        notebook.add(timeline_tab, text="Timeline")

        self.fig4, self.ax4 = plt.subplots()
        self.canvas4 = FigureCanvasTkAgg(self.fig4, master=timeline_tab)
        self.canvas4.get_tk_widget().pack(fill="both", expand=True)

# -------- TAB 5: TOP ATTACKERS --------
        attacker_tab = tk.Frame(notebook)
        notebook.add(attacker_tab, text="Top Attackers")

        self.fig5, self.ax5 = plt.subplots()
        self.canvas5 = FigureCanvasTkAgg(self.fig5, master=attacker_tab)
        self.canvas5.get_tk_widget().pack(fill="both", expand=True)


    # start update loop
        self.update_dashboard()


        self.ax1.set_facecolor("#020617")
        self.fig1.patch.set_facecolor("#020617")

        self.ax2.set_facecolor("#020617")
        self.fig2.patch.set_facecolor("#020617")

        self.ax3.set_facecolor("#020617")
        self.fig3.patch.set_facecolor("#020617")

    def update_dashboard(self):
        if not hasattr(self, "db_window") or not self.db_window.winfo_exists():
            return

    # -------- ATTACK GRAPH --------
        self.ax1.clear()

        labels = list(self.attack_counter.keys())
        values = list(self.attack_counter.values())

        if labels:
            self.ax1.bar(labels, values)

            self.ax1.set_title("Attack Types")
            self.canvas1.draw()

    # -------- COUNTRY GRAPH --------
        self.ax2.clear()
        labels = list(self.country_counter.keys())
        values = list(self.country_counter.values())

        if labels:
            self.ax2.bar(labels, values)

        self.ax2.set_title("Country Traffic")
        self.canvas2.draw()

    # -------- TRAFFIC RATE --------
        self.ax3.clear()
        self.ax3.plot(self.traffic_history)

        self.ax3.set_title("Traffic Rate")
        self.canvas3.draw()

    # -------- TIMELINE --------
        self.ax4.clear()

    # last 30 events
        times = self.alert_timeline[-30:]

        if times:
            x = list(range(len(times)))
            y = [1]*len(times)

            self.ax4.plot(x, y)

        self.ax4.set_title("Alert Timeline")
        self.canvas4.draw()

    # -------- TOP ATTACKERS --------
        self.ax5.clear()

# top 5 attackers
        top = sorted(self.attacker_counter.items(), key=lambda x: x[1], reverse=True)[:5]

        if top:
            labels = [ip for ip, _ in top]
            values = [count for _, count in top]

            self.ax5.bar(labels, values)

        self.ax5.set_title("Top Attackers")
        self.canvas5.draw()
        self.db_window.after(5000, self.update_dashboard)

    def load_blacklist(self):
        print("LOADING FILE:", BLACKLIST_FILE)
        try:
            with open(BLACKLIST_FILE, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print("ERROR:", e)
            return []


    def save_blacklist(self, ips):
        with open(BLACKLIST_FILE, "a") as f:
            for ip in ips:
                f.write(ip + "\n")
    def view_blacklist(self):
        window = tk.Toplevel(self.root)
        window.title("Blacklist Manager")
        window.geometry("400x500")

        self.auto_refresh_blacklist()
            # 🔍 SEARCH BAR
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(window, textvariable=self.search_var)
        search_entry.pack(fill="x")

        search_entry.bind("<KeyRelease>", self.filter_blacklist)

    # ➕ ADD IP
        add_frame = tk.Frame(window)
        add_frame.pack(fill="x")

        self.new_ip_var = tk.StringVar()
        tk.Entry(add_frame, textvariable=self.new_ip_var).pack(side="left", fill="x", expand=True)

        tk.Button(add_frame, text="Add IP", command=self.add_blacklist_ip).pack(side="right")

    # 📋 LIST
        self.blacklist_listbox = tk.Listbox(window)
        self.blacklist_listbox.pack(fill="both", expand=True)

        self.refresh_blacklist()

    def auto_refresh_blacklist(self):
        if hasattr(self, "blacklist_listbox") and self.blacklist_listbox.winfo_exists():
            self.refresh_blacklist()

        # 🔥 हर 2 sec refresh
            self.blacklist_listbox.after(2000, self.auto_refresh_blacklist)

    def refresh_blacklist(self):
        self.blacklist_listbox.delete(0, tk.END)

        ips = list(set(self.load_blacklist()))

        for ip in ips:
            self.blacklist_listbox.insert(tk.END, ip)

    def add_blacklist_ip(self):
        ip = self.new_ip_var.get().strip()

        if not ip:   # ✅ same level
            return
        ips = self.load_blacklist()

        if ip not in ips:
            ips.append(ip)
            self.save_blacklist(ips)

        # 🔥 instant block
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

            print(f"[MANUAL BLOCK] {ip}")

        self.new_ip_var.set("")
        self.refresh_blacklist()
 
    def filter_blacklist(self, event=None):
        query = self.search_var.get().lower()

        self.blacklist_listbox.delete(0, tk.END)

        ips = self.load_blacklist()

        for ip in ips:
            if query in ip.lower():
                self.blacklist_listbox.insert(tk.END, ip)

    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def remove_blacklist_ip(self):
        try:
            selected = self.blacklist_listbox.get(tk.ACTIVE)

            if not selected:
                return

        # remove from file
            ips = self.load_blacklist()
            ips = [ip for ip in ips if ip != selected]
            self.save_blacklist(ips)

        # remove iptables rule
            os.system(f"sudo iptables -D INPUT -s {selected} -j DROP")

        # refresh list
            self.blacklist_listbox.delete(0, tk.END)
            for ip in ips:
                self.blacklist_listbox.insert(tk.END, ip)

            print(f"[UNBLOCKED + REMOVED] {selected}")

        except Exception as e:
            print("[ERROR]", e)
    # ---------------- SMART SCROLL ----------------
    def disable_autoscroll(self, event):
        self.auto_scroll.set(False)

    # ---------------- BLOCK ----------------
    def block_selected_ip(self):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        ip = pkt["src"]
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"[BLOCKED] {ip}")

    def unblock_selected_ip(self):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        ip = pkt["src"]
        os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
        print(f"[UNBLOCKED] {ip}")

    # ---------------- PRIVATE ----------------
    def is_private(self, ip):
        try:
            return not ipaddress.ip_address(ip).is_global
        except:
            return False

    # ---------------- INSERT ----------------
    def insert_packet(self, data):

        print("INSERT:", data)

        src = data.get("src", "")
        dst = data.get("dst", "")

        if not src or not dst:
            return

        mode = self.traffic_filter.get()

        if mode == "PUBLIC":
            if self.is_private(src) and self.is_private(dst):
                return

        elif mode == "LOCAL":
            if not (self.is_private(src) and self.is_private(dst)):
                return
        if data["status"] == "ALERT" and data["src"] in self.load_blacklist():
            self.trigger_alert(data["src"])

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(data.get("proto", 0), "OTHER")
#        if self.filter_text.get() and self.filter_text.get() not in src:
 #           return
#
 #       if self.proto_filter.get() != "ALL" and proto_name != self.proto_filter.get():
  #          return

   #     if self.status_filter.get() != "ALL" and data["status"] != self.status_filter.get():
    #        return

        name = data.get("country_name", "Local")
        attack = data.get("attack_type", "NORMAL")

        # 🔥 CLEAN TAG LOGIC
        if attack == "SCAN":
            tag = "scan"
        elif attack == "FLOOD":
            tag = "flood"
        elif attack == "ANOMALY":
            tag = "anomaly"
        elif data["proto"] == 6:
            tag = "tcp"
        elif data["proto"] == 17:
            tag = "udp"
        elif data["proto"] == 1:
            tag = "icmp"
        else:
            tag = "normal"

            # 🔥 STEP 4 — TAG LOGIC (ADD HERE)
        severity = data.get("severity", "LOW")

        if severity == "HIGH":
            tag = "high"
        elif severity == "MEDIUM":
            tag = "medium"
        else:
            tag = "low"


        item = self.tree.insert(
            "",
            "end",
            values=(
                data["src"],
                data["dst"],
                data["proto"],
                data["len"],
                data["status"],
                data["country_name"],
                data.get("attack_type", "NORMAL"),
                f"{data.get('confidence',0):.2f}%",
                data.get("severity", "LOW")   # 🔥 ADD THIS
            ), tags=(tag,))

        self.packet_map[item] = data


# conditions
        # conditions
        if (
            data["status"] == "ALERT"
            and data.get("confidence", 0) >= 90
            and data.get("attack_type") != "NORMAL"
        ):
            ip = data["src"]
            attack = data.get("attack_type", "NORMAL")
            confidence = data.get("confidence", 0)

            import threading

            threading.Thread(
                target=self.send_email_alert,
                args=(ip, attack, confidence),
                daemon=True
            ).start()

            threading.Thread(
                target=self.send_telegram_alert,
                args=(ip, attack, confidence),
                daemon=True
            ).start()

 # 🔥 SMART AUTO SCROLL
        if self.auto_scroll.get():
            try:
                bottom = self.tree.yview()[1] >= 0.95
                if bottom:
                    self.tree.see(item)
            except:
                pass

        if data["status"] == "ALERT":
                self.alert_timeline.append(time.time())

# 🔥 ATTACKER COUNT
        src = data["src"]
        self.attacker_counter[src] += 1
    # ---------------- UPDATE ----------------
    def update_gui(self):

        print("UPDATE_GUI RUNNING")

        while not packet_queue.empty():
            print("QUEUE:", packet_queue.qsize())
            data = packet_queue.get()
            self.all_packets.append(data)

            self.total += 1
            self.protocol_counter[data["proto"]] += 1
            self.attack_counter[data.get("attack_type", "NORMAL")] += 1
            self.country_counter[data.get("country_name", "Unknown")] += 1

            self.traffic_history.append(self.total)

# limit size
            if len(self.traffic_history) > 50:

                self.all_packets.pop(0)
                print("QUEUE:", packet_queue.qsize())
            self.insert_packet(data)

        self.root.after(200, self.update_gui)
    def update_graph_window(self):
        if not hasattr(self, "graph_window") or not self.graph_window.winfo_exists():
            return   # window बंद → stop update

        self.ax.clear()

        labels = list(self.attack_counter.keys())
        values = list(self.attack_counter.values())

        if labels:
            self.ax.bar(labels, values)

        self.ax.set_title("Live Attack Stats")
        self.ax.set_xlabel("Attack Type")
        self.ax.set_ylabel("Count")

        self.canvas.draw()

    # 🔥 refresh हर 5 sec
        self.graph_window.after(5000, self.update_graph_window)

    def open_attack_graph(self):
        self.graph_window = tk.Toplevel(self.root)
        self.graph_window.title("Live Attack Graph")
        self.graph_window.geometry("600x400")

    # figure
        self.fig, self.ax = plt.subplots()

        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_window)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    # start live update
        self.update_graph_window()

    def open_country_graph(self):
        window = tk.Toplevel(self.root)
        window.title("Country Stats")

        labels = list(self.country_counter.keys())
        values = list(self.country_counter.values())

        fig, ax = plt.subplots()
        ax.bar(labels, values)

        ax.set_title("Traffic by Country")
        ax.set_xlabel("Country")
        ax.set_ylabel("Packets")

        plt.xticks(rotation=45)

        plt.show()
    # ---------------- REFRESH ----------------
    def refresh_table(self, *args):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for data in self.all_packets:
            self.insert_packet(data)

    # ---------------- BLINK ----------------
    def blink_alerts(self):
        self.blink = not self.blink

        for item in list(self.alert_items):
            if not self.tree.exists(item):
                continue

            tags = list(self.tree.item(item, "tags"))
            tags = [t for t in tags if t not in ("alert_on", "alert_off")]
            tags.append("alert_on" if self.blink else "alert_off")

            self.tree.item(item, tags=tags)

        self.root.after(400, self.blink_alerts)

    # ---------------- DETAILS ----------------
    def show_details(self, event):
        selected = self.tree.focus()
        if not selected:
            return

        pkt = self.packet_map.get(selected)
        if not pkt:
            return

        text = f"""
SRC: {pkt['src']}
DST: {pkt['dst']}
PROTO: {pkt['proto']}
LEN: {pkt['len']}
STATUS: {pkt['status']}
ATTACK: {pkt.get('attack_type', 'NORMAL')}
"""

        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)

    # ---------------- EXPORT ----------------
    def export_pcap(self):
        file = filedialog.asksaveasfilename(defaultextension=".pcap")
        if not file:
            return

        packets = []
        for pkt in self.all_packets:
            try:
                packets.append(Ether(bytes.fromhex(pkt.get("raw", ""))))
            except:
                pass

        wrpcap(file, packets)

    # ---------------- ANALYSIS ----------------
    def show_analysis(self):
        top_ip = Counter([p["src"] for p in self.all_packets]).most_common(1)

        text = f"""
Total Packets: {self.total}
Top Attacker: {top_ip}
Protocol Stats: {dict(self.protocol_counter)}
"""

        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)




def start_gui():
    root = tk.Tk()
    app = NIDSGUI(root)
    root.mainloop()
