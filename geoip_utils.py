import geoip2.database
import geoip2.errors
import os
import ipaddress
import requests
from threading import Lock

# 📍 Database path
DB_PATH = "GeoLite2-Country.mmdb"

# 🌍 Global reader + lock
reader = None
reader_lock = Lock()

# 🌐 Cache public IP country (1 time fetch)
PUBLIC_COUNTRY = ("??", "Unknown")


def init_geoip():
    global reader, PUBLIC_COUNTRY

    with reader_lock:
        if reader is not None:
            return

        if not os.path.exists(DB_PATH):
            print(f"[GeoIP ERROR] Database not found: {DB_PATH}")
            return

        try:
            reader = geoip2.database.Reader(DB_PATH)
            print("[GeoIP] Database loaded successfully")
        except Exception as e:
            print(f"[GeoIP ERROR] Failed to load DB: {e}")
            reader = None

    # 🔥 Detect YOUR PUBLIC IP COUNTRY (important)
    try:
        res = requests.get("https://ipinfo.io/json", timeout=3).json()
        code = res.get("country", "??")
        name = res.get("country", "Unknown")
        PUBLIC_COUNTRY = (code, name)
        print(f"[GeoIP] Public Country Detected: {code}")
    except:
        PUBLIC_COUNTRY = ("IN", "India")  # fallback


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        # ONLY true private ranges
        return (
            ip_obj.is_private and not ip_obj.is_global
        )

    except:
        return False


def get_country_info(ip):

    print(f"IP: {ip}, Private: {is_private_ip(ip)}")  # debug 1

    if reader is None:
        return "??", "GeoIP-Off"

    if is_private_ip(ip):
        return "", "Local"

    try:
        print("Geo lookup:", ip)   # 👈 YAH ADD KARO (IMPORTANT)

        response = reader.country(ip)

        code = response.country.iso_code or "??"
        name = response.country.names.get("en", "Unknown")

        return code, name

    except geoip2.errors.AddressNotFoundError:
        return "??", "NotFound"

    except Exception as e:
        print(f"GeoIP ERROR: {e}")
        return "??", "Error"

def close_geoip():
    global reader

    with reader_lock:
        if reader:
            reader.close()
            reader = None
