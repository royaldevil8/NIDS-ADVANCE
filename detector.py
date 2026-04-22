from scapy.all import IP, TCP
from logger import log_alert
from shared import packet_queue
from geoip_utils import init_geoip, get_country_info
from collections import defaultdict, deque
import time
import os
import ipaddress

# ---------------- CONFIG ----------------
CONFIDENCE_BLOCK = 85
BLOCKED_COUNTRIES = {"China", "Russia"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")

# ---------------- TRACKING ----------------
packet_times = defaultdict(deque)
packet_sizes = defaultdict(list)
port_set = defaultdict(set)

scan_dict = {}
syn_count = {}
icmp_count = {}
last_seen = {}

blocked_ips = set()
block_time = {}

BLOCK_DURATION = 60
RESET_TIME = 30

WHITELIST_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "192.168.0.1",
    "10.0.2.15",
}

# ---------------- INIT ----------------
init_geoip()

# ---------------- HELPERS ----------------
def is_private(ip):
    try:
        return not ipaddress.ip_address(ip).is_global
    except:
        return True


def is_safe_ip(ip):
    return (
        ip.startswith("10.") or
        ip.startswith("192.168") or
        ip.startswith("127.") or
        ip.startswith("172.")
    )


def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except:
        return set()


def save_blacklist(ip):
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")


# ---------------- BLOCK ----------------
def block_ip(ip):
    if ip not in blocked_ips:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        blocked_ips.add(ip)
        block_time[ip] = time.time()
        save_blacklist(ip)
        print(f"[BLOCKED] {ip}")


def unblock_ip(ip):
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    blocked_ips.discard(ip)
    block_time.pop(ip, None)
    print(f"[UNBLOCKED] {ip}")


# ---------------- RESET ----------------
def reset_if_needed(src):
    now = time.time()

    if src not in last_seen:
        last_seen[src] = now

    if now - last_seen[src] > RESET_TIME:
        syn_count[src] = 0
        icmp_count[src] = 0
        scan_dict[src] = set()
        last_seen[src] = now


# ---------------- MAIN ----------------
def analyze_packet(pkt):
    try:
        if not pkt.haslayer(IP):
            return None

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)

        # 🔥 AUTO UNBLOCK
        now = time.time()
        for ip in list(blocked_ips):
            if now - block_time.get(ip, 0) > BLOCK_DURATION:
                unblock_ip(ip)

        # 🔥 WHITELIST FIX
        if src in WHITELIST_IPS:
            return {
                "src": src,
                "dst": dst,
                "proto": proto,
                "len": length,
                "status": "SAFE",
                "country_name": "Local",
                "attack_type": "NORMAL",
                "confidence": 0,
                "severity": "LOW",
                "raw": ""
            }

        blacklist = load_blacklist()

        if src in blacklist:
            block_ip(src)
            return None

        reset_if_needed(src)

        status = "OK"
        attack_type = "NORMAL"
        confidence = 0

        # ---------------- RULES ----------------
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            scan_dict.setdefault(src, set()).add(dport)

            if len(scan_dict[src]) > 20:
                status = "ALERT"
                attack_type = "SCAN"
                log_alert(f"[ALERT] Port Scan from {src}")

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x02:
                syn_count[src] = syn_count.get(src, 0) + 1

                if syn_count[src] > 50:
                    status = "ALERT"
                    attack_type = "FLOOD"

                if syn_count[src] > 120:
                    block_ip(src)

        if proto == 1:
            icmp_count[src] = icmp_count.get(src, 0) + 1

    # 🔥 tight detection
            if icmp_count[src] > 30:
                status = "ALERT"
                attack_type = "FLOOD"

    # 🔥 fast block
            if icmp_count[src] > 80:
                block_ip(src)

        # ---------------- ML ----------------
        try:
            from ml_model import predict_with_confidence

            packet_times[src].append(now)
            packet_sizes[src].append(length)

            while packet_times[src] and now - packet_times[src][0] > 5:
                packet_times[src].popleft()

            rate = len(packet_times[src])
            avg_size = sum(packet_sizes[src]) / len(packet_sizes[src])
            ports = len(scan_dict[src])

            features = [rate, avg_size, ports]

            ml_label, confidence = predict_with_confidence(features)

            if attack_type == "NORMAL" and ml_label != "NORMAL":
                attack_type = ml_label

            # ✅ sirf jab ML attack bole tab ALERT
            if ml_label != "NORMAL" and confidence >= 70:
                status = "ALERT"
                attack_type = ml_label

            if attack_type != "NORMAL" and confidence >= CONFIDENCE_BLOCK:
                if not is_safe_ip(src):
                    block_ip(src)

        except Exception as e:
            print("[ML ERROR]", e)
        # FORCE ATTACK TYPE IF ALERT
        if status == "ALERT" and attack_type == "NORMAL":
            attack_type = "ANOMALY"

        # ---------------- GEO ----------------
        if not is_private(src):
            ip_geo = src
        elif not is_private(dst):
            ip_geo = dst
        else:
            ip_geo = None

        if ip_geo:
            code, name = get_country_info(ip_geo)
        else:
            name = "Local"

        # ---------------- SEVERITY ----------------
        if status == "ALERT" and attack_type != "NORMAL":
            severity = "HIGH"
        elif status == "ALERT":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # ---------------- RAW ----------------
        try:
            raw = bytes(pkt)[:100].hex()
        except:
            raw = ""

        # ---------------- FINAL ----------------
        data = {
            "src": src,
            "dst": dst,
            "proto": proto,
            "len": length,
            "status": status,
            "country_name": name,
            "attack_type": attack_type,
            "confidence": confidence,
            "severity": severity,
            "raw": raw
        }

        print("RETURN:", data)
        return data

    except Exception as e:
        print("[DETECTOR ERROR]", e)
        return None
