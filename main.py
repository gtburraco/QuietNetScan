import os
import sys
from typing import List

from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QMainWindow
from scapy.all import conf

from utils.ip_utils import get_local_network_prefix, is_valid_ip_range, generate_ip_list, MAX_IP_SCAN
from utils.messages import show_warning, show_question
from view.main_window_ui import Ui_MainWindow
from viewmodels.network_table_viewmodel import NetworkTableViewModel
from workers.network_scanner import MultiThreadScannerWorker


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        local_network_prefix = get_local_network_prefix()
        self.from_ip_lineedit.setText(f"{local_network_prefix}1")
        self.to_ip_lineedit.setText(f"{local_network_prefix}254")

        # --- ViewModel ---
        self.network_table_viewmodel = NetworkTableViewModel(self)
        self.network_table_view.setModel(self.network_table_viewmodel)

        # --- Scanner thread placeholder ---
        self.scanner = None

        # --- Button connections ---
        self.start_scan_button.clicked.connect(self.start_scan)
        self.stop_scan_button.clicked.connect(self.stop_scan)

        # --- Progress bar setup ---
        self.scan_progress_bar.setMinimum(0)
        self.scan_progress_bar.setMaximum(100)
        self.scan_progress_bar.setValue(0)
        self.scan_progress_bar.setTextVisible(True)
        self.stop_scan_button.setEnabled(False)
        self.statusBar().showMessage(f"PCAP backend: {conf.L2socket}")

        self.ip_list: List[str] = []

    def start_scan(self):
        if self.scanner and self.scanner.isRunning():
            show_warning(self, "Scan already running")
            return

        from_ip = self.from_ip_lineedit.text()
        to_ip = self.to_ip_lineedit.text()

        if not is_valid_ip_range(from_ip, to_ip):
            show_warning(self, "Invalid IP range")
            return

        ip_list = generate_ip_list(from_ip, to_ip)
        if len(ip_list) > MAX_IP_SCAN:
            show_warning(self, f"Range {len(ip_list)} IPs, Max: {MAX_IP_SCAN}")
            return

        self.stop_scan_button.setEnabled(True)
        self.start_scan_button.setEnabled(False)

        self.network_table_viewmodel.clear()
        self.scan_progress_bar.setValue(0)

        self.scan_progress_bar.setMaximum(len(ip_list))
        self.scan_progress_bar.setMinimum(0)
        self.scan_progress_bar.setValue(0)

        print(f"Start scanning {len(ip_list)} IPs")
        self.statusBar().showMessage(f"Start scanning {len(ip_list)} IPs")
        # Configura scanner

        self.scanner = MultiThreadScannerWorker(ip_list=ip_list, max_threads=10,
                                                vendor_file=resource_path("data/mac-vendors.txt"))
        self.scanner.network_object_found.connect(self.network_table_viewmodel.add_network_object)
        self.scanner.scan_finished.connect(self.scan_finished)
        self.scanner.progress.connect(self.update_progress_bar)
        self.scanner.start()

    def update_progress_bar(self, value: int):
        new_val = self.scan_progress_bar.value() + value
        self.scan_progress_bar.setValue(new_val)
        self.statusBar().showMessage(f"Scanned {new_val} of {self.scan_progress_bar.maximum()} IPs")

    def stop_scan(self):
        self.statusBar().showMessage(f"Stopping scanning")
        QApplication.processEvents()
        if self.scanner and self.scanner.isRunning():
            self.scanner.stop()
            # self.scanner.wait()

    def scan_finished(self):
        self.statusBar().showMessage(f"Scanning finished")
        self.scan_progress_bar.setValue(self.scan_progress_bar.maximum())
        self.start_scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)

    def closeEvent(self, event: QCloseEvent):
        if self.scanner and self.scanner.isRunning():
            reply = show_question(
                self,
                self.tr("A scan is still running.\nDo you really want to quit?")
            )
            if not reply:
                event.ignore()
                return

            self.statusBar().showMessage("Stopping scan...")
            self.scanner.stop()

            try:
                self.scanner.network_object_found.disconnect()
                self.scanner.progress.disconnect()
                self.scanner.scan_finished.disconnect()
            except Exception:
                pass

        event.accept()


def resource_path(relative_path: str) -> str:
    try:
        # PyInstaller crea questa variabile temporanea per i file esterni
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Network Scanner")
    app.setApplicationVersion("v1.1")
    print("PCAP backend:", conf.L2socket)
    window = MainWindow()
    window.setWindowTitle(app.applicationName() + " " + app.applicationVersion())
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
