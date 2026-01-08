import os


class MyMacVendorLookup:
    def __init__(self, data_file: str = None):
        if data_file is None:
            data_file = os.path.join(os.path.dirname(__file__), "data", "mac-vendors.txt")

        self.mac_dict = {}
        self.load_vendors(data_file)

    def load_vendors(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Vendor file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                prefix, vendor = line.split(":", 1)
                self.mac_dict[prefix.upper()] = vendor.strip()

    def lookup(self, mac: str) -> str:
        if not mac:
            return ""
        clean_mac = mac.replace(":", "").replace("-", "").upper()
        prefix = clean_mac[:6]
        return self.mac_dict.get(prefix, "")
