#
# main.py - DARX PASS™ Secure Password Manager
# Author: DARX Tech
# CREATED BY ABDULLAHUSIEN **0b0d3**
#
# Requirements:
# pip install PySide6 cryptography
#
# Optional for extended Windows clipboard functionality (not used in this cross-platform implementation):
# pip install pywin32
#
# Note on Fonts:
# This application attempts to use the "Inter" font. If not installed, it will fall back to
# system default sans-serif fonts like "Segoe UI". For the best visual experience,
# please install the Inter font family.
#

import sys
import os
import json
import hashlib
import hmac
import re
from typing import Callable

from cryptography.fernet import Fernet, InvalidToken

from PySide6.QtCore import (
    Qt, QSize, QTimer, Slot, QPoint
)
from PySide6.QtGui import (
    QIcon, QAction, QCloseEvent
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFrame, QStackedWidget, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QDialog, QFormLayout,
    QMessageBox, QGraphicsDropShadowEffect, QButtonGroup, QDialogButtonBox,
    QSpacerItem, QSizePolicy, QAbstractItemView, QTextEdit
)

# --- Configuration Constants ---
VAULT_FILE = "vault_data.json"
KEY_FILE = "key.key"
MASTER_HASH_FILE = "master.hash"
WINDOW_SIZE = QSize(1080, 720)
SIDEBAR_WIDTH = 220
TABLE_ROW_HEIGHT = 45

# CREATED BY ABDULLAHUSIEN **0b0d3**
# --- Custom Widgets ---
class PasswordTableWidget(QTableWidget):
    """A QTableWidget that clears selection when an empty area is clicked."""
    def mousePressEvent(self, event: QPoint) -> None:
        # If the user clicks on an item, the default behavior is fine.
        # If they click outside of any item, we clear the selection.
        if self.itemAt(event.pos()) is None:
            self.clearSelection()
        super().mousePressEvent(event)


# --- STYLESHEETS ---
def get_stylesheet() -> str:
    """Returns the QSS stylesheet for the application."""
    return """
    /* Dark Theme - DARX VAULT */
    QWidget {
        background-color: #2C2F36; color: #B0BEC5; font-family: Inter, Segoe UI, sans-serif; font-size: 10pt;
    }
    QMainWindow { background-color: #2C2F36; }
    QFrame#Sidebar { background-color: #23252B; border-right: 1px solid #3A3E48; }
    QLabel { color: #B0BEC5; }
    QLabel#Header { font-size: 16pt; font-weight: bold; color: #FFFFFF; }
    QLabel#FooterLabel { font-size: 8pt; color: #78909C; }
    QPushButton { border: 1px solid #4A4E5A; border-radius: 6px; padding: 8px 12px; background-color: #373B44; color: #FFFFFF; font-weight: 500; }
    QPushButton:hover { background-color: #424651; }
    QPushButton:pressed { background-color: #31353E; }
    QPushButton#PrimaryButton { background-color: #2979FF; color: #ffffff; font-weight: bold; border: none; }
    QPushButton#PrimaryButton:hover { background-color: #5393FF; }
    QPushButton#PrimaryButton:pressed { background-color: #1C64F2; }
    QPushButton#DangerButton { background-color: #f43f5e; color: #ffffff; font-weight: bold; border: none; }
    QPushButton#DangerButton:hover { background-color: #e11d48; }
    QPushButton#DangerButton:pressed { background-color: #be123c; }
    QPushButton#SidebarButton { background-color: transparent; border: none; padding: 12px; color: #FFFFFF; text-align: left; border-radius: 6px; font-size: 11pt; }
    QPushButton#SidebarButton:hover { background-color: #373B44; }
    QPushButton#SidebarButton:checked { background-color: #2979FF; font-weight: bold; }
    QTableWidget { background-color: #23252B; border: 1px solid #3A3E48; border-radius: 6px; gridline-color: #3A3E48; color: #B0BEC5; }
    QHeaderView::section { background-color: #373B44; padding: 4px; border-style: none; border-bottom: 1px solid #4A4E5A; font-weight: bold; color: #FFFFFF; }
    QTableWidget::item { padding: 5px; border-bottom: 1px solid #3A3E48; vertical-align: middle; }
    QTableWidget::item:selected { background-color: #2979FF; color: #FFFFFF; }
    QLineEdit, QTextEdit { background-color: #23252B; border: 1px solid #3A3E48; padding: 8px; border-radius: 6px; color: #FFFFFF; }
    QLineEdit:focus, QTextEdit:focus { border: 1px solid #2979FF; }
    QDialog { background-color: #2C2F36; }
    QScrollBar:vertical { border: none; background: #23252B; width: 8px; margin: 0px; }
    QScrollBar::handle:vertical { background: #373B44; min-height: 20px; border-radius: 4px; }
    QToolTip { color: #ffffff; background-color: #23252B; border: 1px solid #3A3E48; border-radius: 4px; padding: 5px; }
    """

# CREATED BY ABDULLAHUSIEN **0b0d3**
# --- Authentication & Dialogs ---
class CreateMasterPasswordDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create Master Password")
        self.setModal(True)
        self.setMinimumWidth(400)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)

        layout = QFormLayout(self)
        layout.addRow("New Master Password:", self.password_input)
        layout.addRow("Confirm Password:", self.confirm_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Create & Lock")
        buttons.button(QDialogButtonBox.Ok).setObjectName("PrimaryButton")
        buttons.accepted.connect(self.verify)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def verify(self) -> None:
        p1 = self.password_input.text()
        p2 = self.confirm_input.text()
        if not p1:
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        self.accept()

    def get_password(self) -> str:
        return self.password_input.text()

# CREATED BY ABDULLAHUSIEN **0b0d3**
class LoginDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Unlock DARX PASS™")
        self.setModal(True)
        self.setMinimumWidth(400)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        layout = QFormLayout(self)
        layout.addRow("Master Password:", self.password_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Unlock")
        buttons.button(QDialogButtonBox.Ok).setObjectName("PrimaryButton")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_password(self) -> str:
        return self.password_input.text()

# CREATED BY ABDULLAHUSIEN **0b0d3**
class MasterPasswordPromptDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Identity")
        self.setModal(True)
        self.setMinimumWidth(350)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        layout = QFormLayout(self)
        layout.addRow(QLabel("Enter your Master Password to save changes."))
        layout.addRow("Master Password:", self.password_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Confirm")
        buttons.button(QDialogButtonBox.Ok).setObjectName("PrimaryButton")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_password(self) -> str:
        return self.password_input.text()

# CREATED BY ABDULLAHUSIEN **0b0d3**
class EditPasswordDialog(QDialog):
    def __init__(self, entry: dict, verification_callback: Callable[[str], bool], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Edit Entry: {entry.get('site', '')}")
        self.setMinimumWidth(500)
        self.setModal(True)

        self.original_entry = entry.copy()
        self.verification_callback = verification_callback
        self.has_unsaved_changes = False

        layout = QFormLayout(self)
        layout.setSpacing(15)

        self.site_input = QLineEdit(entry.get('site', ''))
        self.username_input = QLineEdit(entry.get('username', ''))
        self.password_input = QLineEdit(entry.get('password', ''))
        self.notes_input = QTextEdit(entry.get('notes', ''))
        self.notes_input.setFixedHeight(100)

        self.site_input.textChanged.connect(self.on_field_changed)
        self.username_input.textChanged.connect(self.on_field_changed)
        self.password_input.textChanged.connect(self.on_field_changed)
        self.notes_input.textChanged.connect(self.on_field_changed)

        self.password_input.setEchoMode(QLineEdit.Password)
        self.pw_visibility_action = self.password_input.addAction(QIcon(), QLineEdit.TrailingPosition)
        self.pw_visibility_action.setToolTip("Show/Hide Password")
        self.pw_visibility_action.setCheckable(True)
        self.pw_visibility_action.toggled.connect(self.toggle_password_visibility)
        self.update_eye_icon()

        layout.addRow("Site:", self.site_input)
        layout.addRow("Username:", self.username_input)
        layout.addRow("Password:", self.password_input)
        layout.addRow("Notes:", self.notes_input)

        self.button_box = QDialogButtonBox()
        self.save_button = self.button_box.addButton("Save Changes", QDialogButtonBox.AcceptRole)
        self.save_button.setObjectName("PrimaryButton")
        self.save_button.setVisible(False)
        self.cancel_button = self.button_box.addButton(QDialogButtonBox.Cancel)

        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addRow(self.button_box)

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def on_field_changed(self) -> None:
        current_data = self.get_data()
        is_modified = any(current_data[key] != self.original_entry.get(key, '') for key in current_data)
        self.has_unsaved_changes = is_modified
        self.save_button.setVisible(is_modified)

    def trigger_save_workflow(self) -> bool:
        prompt = MasterPasswordPromptDialog(self)
        prompt.setStyleSheet(self.styleSheet())
        if prompt.exec() == QDialog.Accepted:
            master_password = prompt.get_password()
            if self.verification_callback(master_password):
                self.has_unsaved_changes = False
                return True
            else:
                QMessageBox.warning(self, "Authentication Failed", "Incorrect Master Password. Changes were not saved.")
                return False
        return False

    def accept(self) -> None:
        if self.trigger_save_workflow():
            super().accept()

    def reject(self) -> None:
        if self.has_unsaved_changes:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                         "Do you want to save your changes?",
                                         QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                                         QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                if self.trigger_save_workflow():
                    super().accept()
            elif reply == QMessageBox.No:
                super().reject()
        else:
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.reject()
        event.ignore()

    def get_data(self) -> dict:
        return {
            "site": self.site_input.text().strip(),
            "username": self.username_input.text().strip(),
            "password": self.password_input.text(),
            "notes": self.notes_input.toPlainText().strip()
        }

    def toggle_password_visibility(self, is_checked: bool) -> None:
        self.password_input.setEchoMode(QLineEdit.Normal if is_checked else QLineEdit.Password)
        self.update_eye_icon()

    def update_eye_icon(self) -> None:
        icon_text = "👁️" if self.password_input.echoMode() == QLineEdit.Password else "🙈"
        self.pw_visibility_action.setText(icon_text)

# CREATED BY ABDULLAHUSIEN **0b0d3**
class AddPasswordDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add New Password")
        self.setMinimumWidth(450)
        self.setModal(True)

        layout = QFormLayout(self)
        self.site_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.check_password_strength)

        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("e.g., Main email account...")
        self.notes_input.setAcceptRichText(False)
        self.notes_input.setFixedHeight(80)

        self.pwd_visibility_action = self.password_input.addAction(QIcon(), QLineEdit.TrailingPosition)
        self.pwd_visibility_action.setToolTip("Show/Hide Password")
        self.pwd_visibility_action.setCheckable(True)
        self.pwd_visibility_action.toggled.connect(self.toggle_password_visibility)
        self.update_eye_icon()

        layout.addRow("Site URL/Name:", self.site_input)
        layout.addRow("Username/Email:", self.username_input)
        layout.addRow("Password:", self.password_input)
        layout.addRow("Notes:", self.notes_input)

        self.strength_label = QLabel("")
        self.strength_label.setAlignment(Qt.AlignCenter)
        layout.addRow(self.strength_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Save).setObjectName("PrimaryButton")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def check_password_strength(self, password: str) -> None:
        score = 0
        if not password:
            self.strength_label.setText("")
            return
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if re.search(r'[a-z]', password): score += 1
        if re.search(r'[A-Z]', password): score += 1
        if re.search(r'\d', password): score += 1
        if re.search(r'[^a-zA-Z0-9]', password): score += 1

        if score < 3:
            self.strength_label.setText("Weak")
            self.strength_label.setStyleSheet("color:#f43f5e; font-weight:bold;")
        elif score < 5:
            self.strength_label.setText("Medium")
            self.strength_label.setStyleSheet("color:#f97316; font-weight:bold;")
        else:
            self.strength_label.setText("Strong")
            self.strength_label.setStyleSheet("color:#10b981; font-weight:bold;")

    def toggle_password_visibility(self, is_checked: bool) -> None:
        self.password_input.setEchoMode(QLineEdit.Normal if is_checked else QLineEdit.Password)
        self.update_eye_icon()

    def update_eye_icon(self) -> None:
        icon = "👁️" if self.password_input.echoMode() == QLineEdit.Password else "🙈"
        self.pwd_visibility_action.setText(icon)

    def get_data(self) -> dict:
        return {"site": self.site_input.text().strip(),
                "username": self.username_input.text().strip(),
                "password": self.password_input.text(),
                "notes": self.notes_input.toPlainText().strip()}

# CREATED BY ABDULLAHUSIEN **0b0d3**
class LoadingScreen(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setModal(True)
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setFixedSize(400, 150)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setAlignment(Qt.AlignCenter)

        title_label = QLabel("DARX PASS™")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size:16pt; font-weight:bold; color:#FFFFFF;")

        self.status_label = QLabel("Establishing secure connection...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size:10pt; color:#B0BEC5;")

        layout.addWidget(title_label)
        layout.addSpacing(10)
        layout.addWidget(self.status_label)

        self.loading_steps = [
            (500, "Initializing vault...", 23),
            (700, "Encrypting core modules...", 45),
            (800, "Generating secure containers...", 82),
            (500, "Finalizing...", 100)
        ]
        self.current_step_index = 0
        QTimer.singleShot(500, self.run_next_step)

    def run_next_step(self) -> None:
        if self.current_step_index >= len(self.loading_steps):
            self.accept()
            return
        delay, text, percent = self.loading_steps[self.current_step_index]
        self.status_label.setText(f"{text} ----- {percent}%")
        self.current_step_index += 1
        QTimer.singleShot(delay, self.run_next_step)

# CREATED BY ABDULLAHUSIEN **0b0d3**
# --- Main Application Window ---
class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("DARX PASS™ – Secure Password Manager")
        self.setFixedSize(WINDOW_SIZE)

        self.fernet: Fernet | None = None
        self.passwords: list[dict] = []
        self.active_shadow_button: QPushButton | None = None
        self.shadow_effect: QGraphicsDropShadowEffect | None = None
        self.table: PasswordTableWidget | None = None

        self.init_crypto()
        self.init_ui()
        self.apply_stylesheet()
        self.load_passwords_to_table()

    def verify_master_password(self, password_attempt: str) -> bool:
        if not os.path.exists(MASTER_HASH_FILE):
            return False
        with open(MASTER_HASH_FILE, 'rb') as f:
            stored_hash = f.read()
        entered_hash = hashlib.sha256(password_attempt.encode('utf-8')).digest()
        return hmac.compare_digest(stored_hash, entered_hash)

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def init_crypto(self) -> None:
        try:
            if os.path.exists(KEY_FILE):
                with open(KEY_FILE, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(KEY_FILE, 'wb') as f:
                    f.write(key)
            self.fernet = Fernet(key)
        except Exception as e:
            self.show_critical_error(f"Failed to load/generate security key: {e}")

        if not os.path.exists(KEY_FILE):
            self.show_critical_error(f"FATAL: Key file '{KEY_FILE}' not found.")
        if os.path.exists(VAULT_FILE):
            try:
                with open(VAULT_FILE, 'rb') as f:
                    encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    self.passwords = json.loads(decrypted_data)
            except InvalidToken:
                self.show_critical_error("Decryption failed: key is invalid or data is corrupt.")
            except Exception as e:
                self.show_critical_error(f"Failed to load vault: {e}")

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def init_ui(self) -> None:
        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        self.setCentralWidget(main_widget)

        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)

        self.pages = QStackedWidget()
        self.create_passwords_page()
        self.create_settings_page()
        main_layout.addWidget(self.pages)

        # Ensure first button is checked and has shadow
        self.btn_passwords.setChecked(True)
        self.update_sidebar_shadow(self.btn_passwords)

    def create_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(SIDEBAR_WIDTH)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        app_title = QLabel("DARX PASS™")
        app_title.setAlignment(Qt.AlignCenter)
        app_title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #ffffff; margin-bottom: 10px;")

        self.sidebar_button_group = QButtonGroup(self)
        self.sidebar_button_group.setExclusive(True)
        self.sidebar_button_group.idClicked.connect(self.switch_page)

        self.btn_passwords = self.create_sidebar_button("🔐 My Passwords", 0)
        btn_add = self.create_sidebar_button("➕ Add Password")
        btn_add.clicked.connect(self.open_add_password_dialog)
        self.btn_settings = self.create_sidebar_button("⚙️ Settings", 1)

        spacer = QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding)
        btn_quit = self.create_sidebar_button("🚪 Quit")
        btn_quit.clicked.connect(self.close)

        footer_label = QLabel("DARX PASS™ – 2025 © | GitHub: @0b0d3")
        footer_label.setObjectName("FooterLabel")
        footer_label.setWordWrap(True)
        footer_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(app_title)
        layout.addWidget(self.btn_passwords)
        layout.addWidget(btn_add)
        layout.addSpacing(20)
        layout.addWidget(self.btn_settings)
        layout.addSpacerItem(spacer)
        layout.addWidget(btn_quit)
        layout.addSpacing(5)
        layout.addWidget(footer_label)
        return sidebar

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def create_sidebar_button(self, text: str, page_id: int | None = None) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("SidebarButton")
        button.setCheckable(page_id is not None)
        button.clicked.connect(lambda: self.update_sidebar_shadow(button))
        if page_id is not None:
            self.sidebar_button_group.addButton(button, page_id)
        return button

    @Slot(int)
    def switch_page(self, page_id: int) -> None:
        self.pages.setCurrentIndex(page_id)

    def create_passwords_page(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        header = QLabel("My Passwords")
        header.setObjectName("Header")
        layout.addWidget(header)

        self.table = PasswordTableWidget()  # Use custom widget
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Password", "Notes", "Copy", "Delete"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.cellDoubleClicked.connect(self.edit_password_entry)
        layout.addWidget(self.table)
        self.pages.addWidget(page)

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def create_settings_page(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        header = QLabel("Settings")
        header.setObjectName("Header")
        layout.addWidget(header)
        self.vault_info_label = QLabel()
        layout.addWidget(self.vault_info_label)
        danger_label = QLabel("🚨 Danger Zone")
        danger_label.setStyleSheet("font-size:12pt;font-weight:bold;margin-top:20px;color:#f43f5e;")
        layout.addWidget(danger_label)
        btn_delete_all = QPushButton("Delete ALL Passwords")
        btn_delete_all.setObjectName("DangerButton")
        btn_delete_all.setFixedWidth(200)
        btn_delete_all.clicked.connect(self.delete_all_passwords)
        layout.addWidget(btn_delete_all)
        layout.addStretch()
        self.pages.addWidget(page)
        self.update_settings_info()

    # CREATED BY ABDULLAHUSIEN **0b0d3**
    def update_settings_info(self) -> None:
        self.vault_info_label.setText(
            f"<b>Vault Location:</b> {os.path.abspath(VAULT_FILE)}\n"
            f"<b>Number of Entries:</b> {len(self.passwords)}")

    @staticmethod
    def create_button_cell_widget(button: QPushButton) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.addWidget(button)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(5, 3, 5, 3)
        return widget

    def load_passwords_to_table(self) -> None:
        self.table.setRowCount(0)
        for idx, entry in enumerate(self.passwords):
            self.table.insertRow(idx)
            self.table.setRowHeight(idx, TABLE_ROW_HEIGHT)

            site_item = QTableWidgetItem(entry.get("site", ""))
            user_item = QTableWidgetItem(entry.get("username", ""))
            pass_item = QTableWidgetItem("******")
            notes = entry.get("notes", "")
            notes_item = QTableWidgetItem(notes)
            if notes:
                notes_item.setToolTip(notes)

            self.table.setItem(idx, 0, site_item)
            self.table.setItem(idx, 1, user_item)
            self.table.setItem(idx, 2, pass_item)
            self.table.setItem(idx, 3, notes_item)

            btn_copy = QPushButton("Copy")
            btn_copy.setObjectName("PrimaryButton")
            btn_copy.clicked.connect(lambda checked=False, r=idx: self.copy_password(r))

            btn_delete = QPushButton("Delete")
            btn_delete.setObjectName("DangerButton")
            btn_delete.clicked.connect(lambda checked=False, r=idx: self.delete_password(r))

            self.table.setCellWidget(idx, 4, self.create_button_cell_widget(btn_copy))
            self.table.setCellWidget(idx, 5, self.create_button_cell_widget(btn_delete))

        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        for i in [4, 5]:
            self.table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.update_settings_info()

    def copy_password(self, row_index: int) -> None:
        password = self.passwords[row_index]['password']
        QApplication.clipboard().setText(password)
        cell_widget = self.table.cellWidget(row_index, 4)
        if cell_widget and (button := cell_widget.findChild(QPushButton)):
            button.setText("Copied!")
            button.setEnabled(False)
            QTimer.singleShot(2000, lambda: (button.setText("Copy"), button.setEnabled(True)))
        QTimer.singleShot(10000, lambda: self.clear_clipboard_if_match(password))

    def clear_clipboard_if_match(self, password_to_clear: str) -> None:
        if QApplication.clipboard().text() == password_to_clear:
            QApplication.clipboard().clear()

    def delete_password(self, row_index: int) -> None:
        site = self.passwords[row_index]['site']
        reply = QMessageBox.warning(self, "Confirm Deletion", f"Delete password for <b>{site}</b>?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            del self.passwords[row_index]
            self.save_vault_data()
            self.load_passwords_to_table()

    def open_add_password_dialog(self) -> None:
        dialog = AddPasswordDialog(self)
        dialog.setStyleSheet(self.styleSheet())
        if dialog.exec():
            data = dialog.get_data()
            if not all(data.get(key) for key in ["site", "username", "password"]):
                QMessageBox.warning(self, "Incomplete Data", "Site, Username, and Password are required.")
                return
            self.passwords.append(data)
            self.save_vault_data()
            self.load_passwords_to_table()
            self.pages.setCurrentIndex(0)
            self.btn_passwords.setChecked(True)

    def edit_password_entry(self, row: int, column: int) -> None:
        if not (0 <= row < len(self.passwords)):
            return

        dialog = EditPasswordDialog(self.passwords[row], self.verify_master_password, self)
        dialog.setStyleSheet(self.styleSheet())

        if dialog.exec():
            self.passwords[row] = dialog.get_data()
            self.save_vault_data()
            self.load_passwords_to_table()
            self.table.clearSelection() # Clear selection after edit

    def delete_all_passwords(self) -> None:
        reply = QMessageBox.critical(self, "DELETE ALL DATA", "<b>DANGER!</b><br>Delete ALL passwords?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.passwords.clear()
            self.save_vault_data()
            self.load_passwords_to_table()
            QMessageBox.information(self, "Success", "All passwords have been deleted.")

    def apply_stylesheet(self) -> None:
        self.setStyleSheet(get_stylesheet())
        self.shadow_effect = QGraphicsDropShadowEffect(self)
        self.shadow_effect.setBlurRadius(20)
        self.shadow_effect.setColor("#2979FF")
        self.shadow_effect.setOffset(0, 0)
        self.update_sidebar_shadow(self.active_shadow_button)

    def update_sidebar_shadow(self, button: QPushButton) -> None:
        if self.active_shadow_button:
            self.active_shadow_button.setGraphicsEffect(None)
        self.active_shadow_button = None
        if button and button.isCheckable() and button.isChecked():
            button.setGraphicsEffect(self.shadow_effect)
            self.active_shadow_button = button

    def show_critical_error(self, message: str, fatal: bool = True) -> None:
        msg_box = QMessageBox(QMessageBox.Critical, "Critical Error", message)
        msg_box.setStyleSheet(get_stylesheet())
        msg_box.exec()
        if fatal:
            sys.exit(1)


# --- Application Startup ---
def handle_authentication() -> bool:
    is_authenticated = False
    dialog_style = get_stylesheet()
    if not os.path.exists(MASTER_HASH_FILE):
        dialog = CreateMasterPasswordDialog()
        dialog.setStyleSheet(dialog_style)
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            with open(MASTER_HASH_FILE, 'wb') as f:
                f.write(hashlib.sha256(password.encode('utf-8')).digest())
            is_authenticated = True
    else:
        with open(MASTER_HASH_FILE, 'rb') as f:
            stored_hash = f.read()
        dialog = LoginDialog()
        dialog.setStyleSheet(dialog_style)
        if dialog.exec() == QDialog.Accepted:
            password = dialog.get_password()
            entered_hash = hashlib.sha256(password.encode('utf-8')).digest()
            if hmac.compare_digest(stored_hash, entered_hash):
                is_authenticated = True
            else:
                msg_box = QMessageBox(QMessageBox.Critical, "Login Failed", "Incorrect master password.")
                msg_box.setStyleSheet(dialog_style)
                msg_box.exec()
    return is_authenticated


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    if not handle_authentication():
        sys.exit(0)

    loading_screen = LoadingScreen()
    loading_screen.setStyleSheet(get_stylesheet())
    loading_screen.exec()

    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())
    # CREATED BY ABDULLAHUSIEN **0b0d3**