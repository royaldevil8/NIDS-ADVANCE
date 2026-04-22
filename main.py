import threading
from sniffer import start_sniffing
from gui import start_gui
from geoip_utils import init_geoip
from ml_auto import auto_retrain

if __name__ == "__main__":
    init_geoip()

    # sniff thread
    t1 = threading.Thread(target=start_sniffing)
    t1.daemon = True
    t1.start()

    # ML thread
    t2 = threading.Thread(target=auto_retrain)
    t2.daemon = True
    t2.start()

    # GUI main thread
    start_gui()
