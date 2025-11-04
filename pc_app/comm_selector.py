# comm_selector.py
import importlib

def run_wifi():
    mod = importlib.import_module("pc_app.tls.tls_server")
    mod.main()

def run_usb():
    mod = importlib.import_module("pc_app.usb.usb_pair")
    mod.run()

def main():
    print("=== Communication Selector ===")
    method = input("Select communication method [usb / wifi]: ").strip().lower()
    if method == "wifi":
        run_wifi()
    elif method == "usb":
        run_usb()
    else:
        print("Unknown method.")

if __name__ == "__main__":
    main()
