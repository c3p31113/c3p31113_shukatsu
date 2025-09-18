import sys
import os
import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout,
    QSplitter, QListWidget, QLabel, QListWidgetItem, QPushButton,
    QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# プロジェクトのルートをパスに追加
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dashboard.ui.views.dashboard_view import DashboardView
from dashboard.ui.views.file_monitor_view import FileMonitorView
from dashboard.ui.views.log_monitor_view import LogMonitorView
from dashboard.ui.views.settings_view import SettingsView
from dashboard.ui.views.vulnerability_view import VulnerabilityView
from dashboard.ui.views.sns_threat_watcher_view import SnsThreatWatcherView
from dashboard.ui.views.ai_advisor_view import AIAdvisorView
from dashboard.ui.views.trinity_ai_view import TrinityAIView  # 【追加】
from src.core.intelligence_manager import IntelligenceManager
from src.database.db_manager import DBManager

class TitleWorker(QThread):
    title_ready = pyqtSignal(int, str)
    def __init__(self, manager, conv_id, user_msg, ai_msg):
        super().__init__()
        self.manager = manager
        self.conv_id = conv_id
        self.user_msg = user_msg
        self.ai_msg = ai_msg
    def run(self):
        title = self.manager.generate_conversation_title(self.user_msg, self.ai_msg)
        self.title_ready.emit(self.conv_id, title)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CYBER-AEGIS - Autonomous AI Security Ecosystem")
        self.setGeometry(100, 100, 1600, 900)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setDocumentMode(True)
        self.tab_widgets = {}
        self.tab_layouts = {}
        
        self.db_manager = DBManager()
        self.current_conversation_id = None
        self.title_worker = None
        self.intelligence_manager = IntelligenceManager() 

        # 【修正】タブ名リストに「三位一体AI演習」を追加
        tab_names = ["メインダッシュボード", "ファイル監視", "ログ監視", "SNS Threat Watcher", 
                     "AI Security Advisor", "三位一体AI演習", "自己脆弱性診断", "設定"]
        
        for i, name in enumerate(tab_names):
            container_widget = QWidget()
            container_layout = QVBoxLayout(container_widget)
            container_layout.setContentsMargins(0, 0, 0, 0)
            self.tabs.addTab(container_widget, name)
            self.tab_layouts[i] = container_layout
        
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.layout.addWidget(self.tabs)
        self.on_tab_changed(0) 

    def on_tab_changed(self, index):
        if self.tab_layouts[index].count() > 0: return
        tab_name = self.tabs.tabText(index)
        if tab_name == "AI Security Advisor":
            self.setup_advisor_tab(index)
        else:
            self.setup_other_tab(tab_name, index)

    def setup_advisor_tab(self, index):
        advisor_container = QWidget()
        advisor_layout = QVBoxLayout(advisor_container)
        advisor_layout.setContentsMargins(10, 10, 10, 10)
        title_label = QLabel("AI Security Advisor")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        new_chat_button = QPushButton("＋ 新規チャット")
        new_chat_button.clicked.connect(self.start_new_conversation)
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("QListWidget { border: 1px solid #444; }")
        
        self.history_list.itemDoubleClicked.connect(self.on_history_item_double_clicked)
        self.history_list.currentItemChanged.connect(self.on_history_switch)

        left_layout.addWidget(new_chat_button)
        left_layout.addWidget(self.history_list)
        self.ai_advisor_view = AIAdvisorView(self)
        self.ai_advisor_view.message_added.connect(self.save_message_to_history)
        splitter.addWidget(left_panel)
        splitter.addWidget(self.ai_advisor_view)
        splitter.setSizes([280, 720])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        advisor_layout.addWidget(title_label, 0)
        advisor_layout.addWidget(splitter, 1)
        self.tab_layouts[index].addWidget(advisor_container)
        self.tab_widgets[index] = self.ai_advisor_view
        
        self.load_all_conversations_from_db()

    def setup_other_tab(self, tab_name, index):
        view_widget = None
        if tab_name == "メインダッシュボード": view_widget = DashboardView(self)
        elif tab_name == "ファイル監視": view_widget = FileMonitorView(self)
        elif tab_name == "ログ監視": view_widget = LogMonitorView(self)
        elif tab_name == "SNS Threat Watcher": view_widget = SnsThreatWatcherView(self)
        elif tab_name == "三位一体AI演習": view_widget = TrinityAIView(self)  # 【追加】
        elif tab_name == "自己脆弱性診断": view_widget = VulnerabilityView(self)
        elif tab_name == "設定": view_widget = SettingsView(self)
        if view_widget:
            self.tab_layouts[index].addWidget(view_widget)
            self.tab_widgets[index] = view_widget
            
    def load_all_conversations_from_db(self):
        self.history_list.clear()
        conversations = self.db_manager.get_all_conversations()
        if conversations:
            for conv in conversations:
                item = QListWidgetItem(conv["title"])
                item.setData(Qt.ItemDataRole.UserRole, conv["id"])
                self.history_list.addItem(item)
            self.history_list.setCurrentRow(0)
        else:
            self.start_new_conversation()

    def start_new_conversation(self):
        title = f"新しいチャット {datetime.datetime.now().strftime('%H:%M')}"
        conv_id = self.db_manager.create_conversation(title)
        
        if conv_id:
            self.current_conversation_id = conv_id
            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, conv_id)
            self.history_list.insertItem(0, item)
            self.history_list.setCurrentItem(item)
            self.ai_advisor_view.load_conversation([])

    def on_history_switch(self, current, previous):
        if current is None or not self.ai_advisor_view.isVisible(): return
        
        conv_id = current.data(Qt.ItemDataRole.UserRole)
        if self.current_conversation_id == conv_id: return

        self.current_conversation_id = conv_id
        messages = self.db_manager.get_messages_for_conversation(conv_id)
        self.ai_advisor_view.load_conversation(messages)
        
    def on_history_item_double_clicked(self, item):
        conv_id = item.data(Qt.ItemDataRole.UserRole)
        title = item.text()
        
        reply = QMessageBox.question(self, '削除の確認', 
            f"本当に会話「{title}」を削除しますか？\nこの操作は元に戻せません。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
            QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            success = self.db_manager.delete_conversation(conv_id)
            if success:
                row = self.history_list.row(item)
                self.history_list.takeItem(row)
                if self.history_list.count() == 0:
                    self.start_new_conversation()
                else:
                    self.history_list.setCurrentRow(0)

    def save_message_to_history(self, message_data):
        if not self.current_conversation_id: return
        
        self.db_manager.add_message_to_conversation(self.current_conversation_id, message_data)
        
        messages = self.db_manager.get_messages_for_conversation(self.current_conversation_id)
        if len(messages) == 2:
            self.request_title_generation(self.current_conversation_id, messages)

    def request_title_generation(self, conv_id, messages):
        user_msg = messages[0]['text']
        ai_msg = messages[1]['text']
        self.title_worker = TitleWorker(self.intelligence_manager, conv_id, user_msg, ai_msg)
        self.title_worker.title_ready.connect(self.update_conversation_title)
        self.title_worker.start()

    def update_conversation_title(self, conv_id, title):
        self.db_manager.update_conversation_title(conv_id, title)
        for i in range(self.history_list.count()):
            item = self.history_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == conv_id:
                item.setText(title)
                break

    def closeEvent(self, event):
        """ウィンドウが閉じられる際に呼び出され、サービスに終了シグナルを送る"""
        print("[MainWindow] 終了シグナルを送信しています...")
        try:
            # 'shutdown.flag' ファイルを作成して、サービスに終了を通知
            with open('shutdown.flag', 'w') as f:
                pass
            print("[MainWindow] 終了シグナルを送信しました。")
        except Exception as e:
            print(f"[MainWindow] 終了シグナルの送信に失敗しました: {e}")
        
        # 元々あった内部のシャットダウン処理も呼び出す
        for tab in self.tab_widgets.values():
            if hasattr(tab, 'shutdown'):
                tab.shutdown()
        
        # 親クラスのcloseEventを呼び出して、ウィンドウを正常に閉じる
        super().closeEvent(event)