import sys
import time
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QLineEdit, QMessageBox
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QPixmap, QFont

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VPN Login")
        self.setGeometry(400, 300, 450, 180)

        # Track login attempts
        self.locked = False
        self.attempts = 0
        self.max_attempts = 3

        # Security image
        self.lock_label = QLabel()
        pixmap = QPixmap("security.jpg")
        pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.lock_label.setPixmap(pixmap)
        self.lock_label.setAlignment(Qt.AlignCenter)
        self.lock_label.setFixedSize(130, 130)

        # Password input
        self.label = QLabel("Enter Password:")
        self.label.setFont(QFont("Arial", 12))
        self.label.setAlignment(Qt.AlignLeft)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setFixedHeight(30)
        self.password_input.setFont(QFont("Arial", 11))

        self.connect_button = QPushButton("Connect")
        self.connect_button.setFixedHeight(35)
        self.connect_button.clicked.connect(self.check_password)
        self.connect_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #66BB6A;
            }
        """)

        password_layout = QVBoxLayout()
        password_layout.addWidget(self.label)
        password_layout.addWidget(self.password_input)
        password_layout.addSpacing(10)
        password_layout.addWidget(self.connect_button)
        password_layout.addStretch()

        # Layout setup
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.lock_label)
        main_layout.addLayout(password_layout)
        self.setLayout(main_layout)

    def check_password(self):
        if self.locked:
            QMessageBox.warning(self, "Locked", "Too many failed attempts. Try again later.")
            return

        password = self.password_input.text()
        if not password.strip():
            QMessageBox.warning(self, "Invalid", "Password cannot be empty.")
            return

        if password == "vpn123":
            self.accept_login()
        else:
            self.attempts += 1
            if self.attempts >= self.max_attempts:
                self.locked = True
                QMessageBox.critical(self, "Locked", "Too many failed attempts.")
            else:
                QMessageBox.critical(self, "Access Denied", f"Wrong password. Attempts left: {self.max_attempts - self.attempts}")

    def accept_login(self):
        self.close()
        self.vpn_window = VPNClient()
        self.vpn_window.show()

class VPNClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VPN Client GUI")
        self.setGeometry(300, 200, 350, 220)

        self.vpn_connected = False
        self.start_time = None
        self.client_process = None

        self.status_label = QLabel("Status: Disconnected")
        self.status_label.setFont(QFont("Arial", 12))
        self.status_label.setStyleSheet("color: red")
        self.status_label.setAlignment(Qt.AlignCenter)

        self.ip_label = QLabel("VPN IP: Not Connected")
        self.ip_label.setFont(QFont("Arial", 11))
        self.ip_label.setAlignment(Qt.AlignCenter)

        self.time_label = QLabel("Time Connected: 00:00:00")
        self.time_label.setFont(QFont("Arial", 11))
        self.time_label.setAlignment(Qt.AlignCenter)

        self.toggle_button = QPushButton("Turn ON")
        self.toggle_button.setFixedHeight(40)
        self.toggle_button.clicked.connect(self.toggle_connection)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                font-weight: bold;
                font-size: 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #42A5F5;
            }
        """)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time_label)

        layout = QVBoxLayout()
        layout.addWidget(self.status_label)
        layout.addWidget(self.ip_label)
        layout.addWidget(self.time_label)
        layout.addSpacing(15)
        layout.addWidget(self.toggle_button)
        self.setLayout(layout)

    def toggle_connection(self):
        self.vpn_connected = not self.vpn_connected
        if self.vpn_connected:
            self.on_connect()
        else:
            self.on_disconnect()

    def on_connect(self):
        if self.client_process is None:
            try:
                self.client_process = subprocess.Popen([sys.executable, 'client.py'])
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to start VPN client: {e}")
                self.vpn_connected = False
                return

        self.status_label.setText("Status: Connected")
        self.status_label.setStyleSheet("color: green")
        self.ip_label.setText("VPN IP: 10.8.0.2")
        self.toggle_button.setText("Turn OFF")
        self.start_time = time.time()
        self.timer.start(1000)

    def on_disconnect(self):
        if self.client_process:
            self.client_process.terminate()
            self.client_process.wait()
            self.client_process = None

        self.status_label.setText("Status: Disconnected")
        self.status_label.setStyleSheet("color: red")
        self.ip_label.setText("VPN IP: Not Connected")
        self.time_label.setText("Time Connected: 00:00:00")
        self.toggle_button.setText("Turn ON")
        self.timer.stop()

    def update_time_label(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            h, rem = divmod(elapsed, 3600)
            m, s = divmod(rem, 60)
            self.time_label.setText(f"Time Connected: {h:02}:{m:02}:{s:02}")

def main():
    app = QApplication(sys.argv)
    login = LoginWindow()
    login.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
