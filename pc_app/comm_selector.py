# comm_selector.py
import importlib

from pc_app.tls.tls_server import run_wifi
from pc_app.usb.usb_pair import run_usb


def select_comm():
    print("=== Communication Selector ===")
    method = input("Select communication method [usb / wifi]: ").strip().lower()
    if method == "wifi":
        return run_wifi()
    elif method == "usb":
        return run_usb()
    else:
        print("Unknown method.")
        return None

if __name__ == "__main__":
    select_comm()
