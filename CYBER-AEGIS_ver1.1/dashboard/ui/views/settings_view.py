# CYBER-AEGIS/dashboard/ui/views/settings_view.py

import os
import glob
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QTextEdit, 
                             QPushButton, QFormLayout, QGroupBox,
                             QMessageBox, QCheckBox, QApplication)
from PyQt6.QtCore import Qt
from src.utils.config_manager import ConfigManager

class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config_manager = ConfigManager()
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        
        # --- UI要素の定義（変更なし） ---
        auto_defense_group = QGroupBox("自動防御設定")
        auto_defense_layout = QVBoxLayout()
        self.auto_defense_checkbox = QCheckBox("CRITICALな脅威を自動でブロック / 隔離する")
        auto_defense_layout.addWidget(self.auto_defense_checkbox)
        auto_defense_group.setLayout(auto_defense_layout)
        main_layout.addWidget(auto_defense_group)
        
        file_monitor_group = QGroupBox("ファイル監視 除外設定")
        form_layout = QFormLayout()
        self.excluded_dirs_edit = QTextEdit()
        self.excluded_dirs_edit.setPlaceholderText("例: C:/Users/YourUser/AppData/, C:/Windows/")
        form_layout.addRow(QLabel("除外ディレクトリ (カンマ区切り):"), self.excluded_dirs_edit)
        self.excluded_exts_edit = QTextEdit()
        self.excluded_exts_edit.setPlaceholderText("例: .log, .tmp, .bak")
        form_layout.addRow(QLabel("除外拡張子 (カンマ区切り):"), self.excluded_exts_edit)
        file_monitor_group.setLayout(form_layout)
        main_layout.addWidget(file_monitor_group)

        data_clear_group = QGroupBox("データ管理")
        data_clear_layout = QVBoxLayout()
        self.clear_data_button = QPushButton("全データクリア（次回起動時）とアプリケーションの終了")
        self.clear_data_button.setStyleSheet("background-color: #d32f2f; color: white;")
        self.clear_data_button.clicked.connect(self.confirm_clear_data)
        data_clear_layout.addWidget(QLabel("警告：次回の起動時にすべてのデータベースとログが削除されます。\nこの操作は元に戻せません。"))
        data_clear_layout.addWidget(self.clear_data_button)
        data_clear_group.setLayout(data_clear_layout)
        main_layout.addWidget(data_clear_group)

        main_layout.addStretch()

        self.save_button = QPushButton("設定を保存")
        self.save_button.clicked.connect(self.save_settings)
        main_layout.addWidget(self.save_button)

    def load_settings(self):
        auto_defense_enabled = self.config_manager.get_boolean('Automation', 'auto_defense_enabled', fallback=False)
        self.auto_defense_checkbox.setChecked(auto_defense_enabled)
        excluded_dirs = self.config_manager.get_list('FileMonitorExclusions', 'directories')
        self.excluded_dirs_edit.setText(", ".join(excluded_dirs))
        excluded_exts = self.config_manager.get_list('FileMonitorExclusions', 'extensions')
        self.excluded_exts_edit.setText(", ".join(excluded_exts))

    def save_settings(self):
        self.config_manager.set('Automation', 'auto_defense_enabled', str(self.auto_defense_checkbox.isChecked()))
        self.config_manager.set('FileMonitorExclusions', 'directories', self.excluded_dirs_edit.toPlainText())
        self.config_manager.set('FileMonitorExclusions', 'extensions', self.excluded_exts_edit.toPlainText())
        self.config_manager.save()
        QMessageBox.information(self, "成功", "設定を保存しました。")

    def confirm_clear_data(self):
        reply = QMessageBox.warning(self, "最終確認", 
                                      "次回の起動時にすべてのデータを削除するように予約し、アプリケーションを終了しますか？",
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                      QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.schedule_cleanup_and_exit()

    def schedule_cleanup_and_exit(self):
        """
        クリーンアップ予約ファイルを作成し、アプリケーションを終了する。
        """
        try:
            # プロジェクトのルートディレクトリに予約ファイルを作成
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            flag_file_path = os.path.join(base_path, ".cleanup_on_next_start")
            
            with open(flag_file_path, 'w') as f:
                f.write('scheduled') # ファイルの中身は何でも良い
            
            QMessageBox.information(self, "予約完了", 
                                      "データ削除を予約しました。\nアプリケーションを終了します。次回起動時にデータがクリアされます。")
            QApplication.instance().quit()

        except Exception as e:
            QMessageBox.critical(self, "エラー", f"クリーンアップの予約中にエラーが発生しました: {e}")