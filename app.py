# app.py - SecureFileVaultPro Professional GUI
import sys, os, json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QMessageBox, QProgressBar, QLineEdit, QTextEdit, QDialog,
    QTabWidget
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from crypto_backend import stream_encrypt_file, stream_decrypt_file
from utils import ensure_dirs, log_activity, log_metadata, safe_output_name

ensure_dirs()

# -------- Worker Threads ----------
class WorkerEncrypt(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, in_path, out_path, password):
        super().__init__()
        self.in_path, self.out_path, self.password = in_path, out_path, password
    def run(self):
        try:
            stream_encrypt_file(self.in_path, self.out_path, self.password)
            self.progress.emit(100)
            self.finished.emit(self.out_path)
        except Exception as e:
            self.error.emit(str(e))

class WorkerDecrypt(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    def __init__(self, enc_path, out_path, password):
        super().__init__()
        self.enc_path, self.out_path, self.password = enc_path, out_path, password
    def run(self):
        try:
            stream_decrypt_file(self.enc_path, self.out_path, self.password)
            self.progress.emit(100)
            self.finished.emit(self.out_path)
        except Exception as e:
            self.error.emit(str(e))

# -------- Master Password Dialog ----------
class MasterPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Master Password 🔒")
        self.setModal(True)
        self.password = None
        self.setFixedSize(350, 130)
        self.init_ui()
    def init_ui(self):
        v = QVBoxLayout()
        lbl = QLabel("Enter master password to unlock vault:")
        lbl.setFont(QFont("Segoe UI", 11))
        v.addWidget(lbl)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setFont(QFont("Consolas", 10))
        v.addWidget(self.pw)
        btn_box = QHBoxLayout()
        ok = QPushButton("Unlock 🔓")
        ok.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        ok.clicked.connect(self.accepted)
        cancel = QPushButton("Exit ❌")
        cancel.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        cancel.clicked.connect(self.reject)
        btn_box.addWidget(ok)
        btn_box.addWidget(cancel)
        v.addLayout(btn_box)
        self.setLayout(v)
    def accepted(self):
        val = self.pw.text().strip()
        if not val:
            QMessageBox.warning(self, "Required", "Master password is required.")
            return
        self.password = val
        self.accept()

# -------- Main Window ----------
class MainWindow(QWidget):
    def __init__(self, master_password):
        super().__init__()
        self.master_password = master_password
        self.selected = None
        self.setWindowTitle("🔒 SecureFileVaultPro")
        self.resize(900, 550)
        self.setAcceptDrops(True)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10,10,10,10)
        layout.setSpacing(10)

        title = QLabel("SecureFileVaultPro")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self.tabs)

        # ---------- Tab 1: Encrypt/Decrypt ----------
        self.tab_ed = QWidget()
        v1 = QVBoxLayout()
        v1.setSpacing(10)

        # File selection
        self.file_label = QLabel("Drag & drop file here or click Browse")
        self.file_label.setFont(QFont("Consolas", 10))
        browse_btn = QPushButton("Browse 🔍")
        browse_btn.clicked.connect(self.browse_file)
        v1.addWidget(self.file_label)
        v1.addWidget(browse_btn)

        # Action buttons
        btn_h = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt 🔒")
        encrypt_btn.clicked.connect(self.encrypt_file)
        decrypt_btn = QPushButton("Decrypt 🔓")
        decrypt_btn.clicked.connect(self.decrypt_file)
        btn_h.addWidget(encrypt_btn)
        btn_h.addWidget(decrypt_btn)
        v1.addLayout(btn_h)

        # Progress & status
        self.progress = QProgressBar()
        self.status = QLabel("Status: Idle")
        v1.addWidget(self.progress)
        v1.addWidget(self.status)
        self.tab_ed.setLayout(v1)
        self.tabs.addTab(self.tab_ed, "Encrypt / Decrypt")

        # ---------- Tab 2: Logs ----------
        self.tab_logs = QWidget()
        v2 = QVBoxLayout()
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        refresh_btn = QPushButton("Refresh Logs 📜")
        refresh_btn.clicked.connect(self.view_logs)
        v2.addWidget(self.logs_text)
        v2.addWidget(refresh_btn)
        self.tab_logs.setLayout(v2)
        self.tabs.addTab(self.tab_logs, "Logs & Metadata")

        # ---------- Tab 3: File Viewer ----------
        self.tab_viewer = QWidget()
        v3 = QVBoxLayout()
        self.view_file_label = QLabel("No file selected")
        self.file_preview = QTextEdit()
        self.file_preview.setReadOnly(True)
        btn_layout = QHBoxLayout()
        select_enc = QPushButton("Open Encrypted")
        select_enc.clicked.connect(lambda: self.load_file("encrypted"))
        select_dec = QPushButton("Open Decrypted")
        select_dec.clicked.connect(lambda: self.load_file("decrypted"))
        btn_layout.addWidget(select_enc)
        btn_layout.addWidget(select_dec)
        v3.addLayout(btn_layout)
        v3.addWidget(self.view_file_label)
        v3.addWidget(self.file_preview)
        self.tab_viewer.setLayout(v3)
        self.tabs.addTab(self.tab_viewer, "File Viewer")

        self.setLayout(layout)

    # ---------- Drag & Drop ----------
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls(): e.accept()
        else: e.ignore()
    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.selected = path
            size = os.path.getsize(path)
            self.file_label.setText(f"{path} ({size} bytes)")

    # ---------- File browsing ----------
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            self.selected = path
            size = os.path.getsize(path)
            self.file_label.setText(f"{path} ({size} bytes)")

    # ---------- Encryption ----------
    def encrypt_file(self):
        if not self.selected:
            QMessageBox.warning(self, "Select file", "Please choose a file first.")
            return
        out_path = os.path.join("encrypted", safe_output_name(self.selected) + ".sfv.json")
        self.status.setText("Encrypting...")
        self.worker = WorkerEncrypt(self.selected, out_path, self.master_password)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(lambda path: [self.on_finish(path, "Encryption"), self.view_logs()])
        self.worker.error.connect(self.on_error)
        self.worker.start()

    # ---------- Decryption ----------
    def decrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select encrypted file", "encrypted", "JSON Files (*.json)")
        if not path: return
        out_name, _ = QFileDialog.getSaveFileName(self, "Save decrypted file", "decrypted/" + os.path.basename(path).replace(".sfv.json",""))
        if not out_name: return
        self.status.setText("Decrypting...")
        self.worker = WorkerDecrypt(path, out_name, self.master_password)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(lambda path: [self.on_finish(path, "Decryption"), self.view_logs()])
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def on_finish(self, path, action):
        self.progress.setValue(100)
        self.status.setText(f"{action} complete ✅")
        log_activity(action.upper(), os.path.basename(path))
        log_metadata(action.upper(), os.path.basename(path), os.path.getsize(path))
        QMessageBox.information(self, "Success", f"{action} -> {path}")

    def on_error(self, msg):
        self.progress.setValue(0)
        self.status.setText("Error ❌")
        QMessageBox.critical(self, "Error", msg)

    # ---------- Logs ----------
    def view_logs(self):
        """Load activity and metadata logs dynamically."""
        activity_file = "activity_log.txt"
        metadata_file = "metadata_log.txt"
        logs = ""

        if os.path.exists(activity_file):
            logs += "=== Activity Log ===\n"
            with open(activity_file, "r") as f:
                logs += f.read() + "\n"
        else:
            logs += "=== Activity Log ===\nNo activity yet.\n\n"

        if os.path.exists(metadata_file):
            logs += "=== Metadata Log ===\n"
            with open(metadata_file, "r") as f:
                logs += f.read() + "\n"
        else:
            logs += "=== Metadata Log ===\nNo metadata yet.\n"

        self.logs_text.setPlainText(logs)

    # ---------- File Viewer ----------
    def load_file(self, folder):
        path, _ = QFileDialog.getOpenFileName(self, f"Select file from {folder}", folder, "All Files (*)")
        if not path: return
        self.view_file_label.setText(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                try: content = json.dumps(json.load(f), indent=4)
                except: content = f.read()
            self.file_preview.setPlainText(content)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Cannot open file: {e}")

# ---------- Main ----------
def main():
    app = QApplication(sys.argv)
    dlg = MasterPasswordDialog()
    if dlg.exec_() != QDialog.Accepted:
        sys.exit(0)
    master_password = dlg.password
    win = MainWindow(master_password)
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
