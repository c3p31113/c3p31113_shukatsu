import sys
import os
import json
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableView, QHeaderView, 
                             QPushButton, QHBoxLayout, QAbstractItemView,
                             QMessageBox, QSplitter, QLabel, QTextEdit)
from PyQt6.QtCore import QAbstractTableModel, Qt, QTimer, pyqtSignal, QThread, QItemSelectionModel
from PyQt6.QtGui import QColor, QFont

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, project_root)

from src.database.db_manager import get_session
from src.database.models import SigmaMatch
from src.core_ai.ollama_manager import OllamaManager
from src.utils.config_manager import ConfigManager
from src.reporting.pdf_generator import PDFGenerator
from src.defense_matrix.real_defense import RealDefense # 防御機能のためにインポート

class AIWorker(QThread):
    result = pyqtSignal(tuple)
    finished = pyqtSignal()
    def __init__(self, prompt, system_message, context_data, model_name):
        super().__init__()
        self.prompt = prompt
        self.system_message = system_message
        self.context_data = context_data
        self.model_name = model_name
    
    def run(self):
        try:
            ai_manager = OllamaManager(model=self.model_name)
            report = ai_manager.generate_response(self.prompt, self.system_message)
            self.result.emit((report, self.context_data))
        except Exception as e:
            print(f"AIWorker Error: {e}")
        finally:
            self.finished.emit()

class SigmaTableModel(QAbstractTableModel):
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self._data = data
        self.headers = ["ID", "検知時刻", "ルールタイトル", "脅威レベル"]

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid(): return None
        
        row_data = self._data[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return f"LOG-{row_data.id:04d}"
            if col == 1: return row_data.timestamp.strftime('%Y-%m-%d %H:%M:%S') if row_data.timestamp else ""
            if col == 2: return row_data.rule_title
            # --- ▼▼▼【修正点①】▼▼▼ ---
            # テーブルに表示する深刻度を大文字に変換
            if col == 3: return row_data.rule_level.upper() if row_data.rule_level else ""
            # --- ▲▲▲ 修正ここまで ▲▲▲ ---
            return None

        if role == Qt.ItemDataRole.BackgroundRole and col == 3:
            threat_colors = {"low": QColor("#2ecc71"), "medium": QColor("#f1c40f"), "high": QColor("#e67e22"), "critical": QColor("#c0392b")}
            severity = str(row_data.rule_level).lower()
            return threat_colors.get(severity, QColor("gray"))
        
        if role == Qt.ItemDataRole.ForegroundRole and col == 3:
                 return QColor("white")
        
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def get_match_by_index(self, index):
        if index.isValid() and 0 <= index.row() < len(self._data):
            return self._data[index.row()]
        return None

class LogMonitorView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.session = get_session()
        self.config = ConfigManager()
        self.pdf_generator = PDFGenerator()
        self.real_defense = RealDefense() # 防御機能のインスタンス
        self.model_name = self.config.get('AI', 'model', fallback='gemma3:latest')
        self.ai_thread = None
        self.current_selected_context = None
        self.current_ai_report = None
        self.initUI()
        self.load_data()

    def initUI(self):
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        self.table_view = QTableView()
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setSortingEnabled(True)
        self.table_view.clicked.connect(self.on_log_event_selected)

        self.model = SigmaTableModel([])
        self.table_view.setModel(self.model)

        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        self.refresh_button = QPushButton("手動更新")
        self.refresh_button.clicked.connect(self.load_data)

        left_layout.addWidget(self.table_view)
        left_layout.addWidget(self.refresh_button)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        report_label = QLabel("AI分析レポート")
        report_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.report_space = QTextEdit()
        self.report_space.setReadOnly(True)
        self.report_space.setPlaceholderText("検知イベントを選択すると、AIによる分析が開始されます。")
        
        action_button_layout = QHBoxLayout()
        self.pdf_button = QPushButton("PDF形式で出力")
        self.pdf_button.setEnabled(False)
        self.pdf_button.clicked.connect(self.on_pdf_button_clicked)
        
        self.block_button = QPushButton("インジケーターをブロック")
        self.block_button.setEnabled(False)
        self.block_button.clicked.connect(self.on_block_button_clicked)
        
        action_button_layout.addWidget(self.pdf_button)
        action_button_layout.addWidget(self.block_button)
        
        right_layout.addWidget(report_label)
        right_layout.addWidget(self.report_space)
        right_layout.addLayout(action_button_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([800, 400])

        main_layout.addWidget(splitter)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.load_data)
        self.timer.start(15000)

    def load_data(self):
        try:
            self.session.expire_all()
            matches = self.session.query(SigmaMatch).order_by(SigmaMatch.timestamp.desc()).all()
            
            current_selection = self.table_view.selectionModel().currentIndex()
            
            self.model = SigmaTableModel(matches)
            self.table_view.setModel(self.model)
            
            if current_selection.isValid() and current_selection.row() < self.model.rowCount():
                self.table_view.selectionModel().setCurrentIndex(current_selection, QItemSelectionModel.SelectionFlag.Select)

        except Exception as e:
            QMessageBox.critical(self, "データベースエラー", f"データベースからデータを読み込めませんでした: {e}")

    def on_log_event_selected(self, index):
        if self.ai_thread and self.ai_thread.isRunning(): return

        match_index = self.table_view.model().index(index.row(), 0)
        match = self.model.get_match_by_index(match_index)

        if match:
            self.current_selected_context = {
                "検知ID": f"LOG-{match.id:04d}",
                "タイムスタンプ": match.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "ルールタイトル": match.rule_title,
                # --- ▼▼▼【修正点②】▼▼▼ ---
                # AIに渡す情報も大文字に統一
                "深刻度": match.rule_level.upper() if match.rule_level else "",
                # --- ▲▲▲ 修正ここまで ▲▲▲ ---
                "元ログ": match.log_entry
            }
            self.start_ai_analysis()
        else:
            self.current_selected_context = None

    def start_ai_analysis(self):
        if not self.current_selected_context: return
        
        self.report_space.setText(f"AIがイベントID: {self.current_selected_context['検知ID']} の分析を開始しました...")
        self.pdf_button.setEnabled(False)
        self.block_button.setEnabled(False)

        prompt = f"""
        <TASK>
        以下のSIGMA検知イベントの情報を分析し、脅威の詳細な分析レポートをHTML形式で生成してください。
        </TASK>

        <RULES>
        1. `<h3>`タグを使用して、「脅威の概要」「考えられるリスク」「推奨される対処法」の3つのセクションを必ず作成してください。
        2. 「推奨される対処法」は必ず`<ul>`と`<li>`タグを使用した箇条書きにしてください。
        3. 一般的な説明だけでなく、元ログの具体的な情報（コマンド、ファイルパス、IPアドレスなど）に言及し、なぜそれが脅威なのかを専門的に解説してください。
        </RULES>

        <TASK_INPUT>
        - ルールタイトル: {self.current_selected_context['ルールタイトル']}
        - 深刻度: {self.current_selected_context['深刻度']}
        - 元ログ: {self.current_selected_context['元ログ']}
        </TASK_INPUT>
        """
        system_message = "あなたはサイバーセキュリティ専門のアナリストです。提示されたインシデントデータを基に、専門的かつ具体的で、示唆に富むHTML形式の分析レポートを作成してください。"
        
        self.ai_thread = AIWorker(prompt, system_message, self.current_selected_context, self.model_name)
        self.ai_thread.result.connect(self.update_report_space)
        self.ai_thread.start()

    def update_report_space(self, result_tuple):
        report, context_data = result_tuple
        if self.current_selected_context and context_data["検知ID"] == self.current_selected_context["検知ID"]:
            self.current_ai_report = report
            # --- ▼▼▼【修正点③】▼▼▼ ---
            # 'mediun' -> 'medium' のタイポを修正し、小文字に変換して色を正しく引けるようにする
            threat_level_lower = context_data['深刻度'].lower()
            threat_color_map = {"low": "#2ecc71", "medium": "#f1c40f", "high": "#e67e22", "critical": "#c0392b"}
            threat_color = threat_color_map.get(threat_level_lower, "gray")
            # --- ▲▲▲ 修正ここまで ▲▲▲ ---
            
            full_html = f"""
            <html><head><style>
            body {{ font-family: 'Segoe UI', 'Meiryo UI', sans-serif; color: #f0f0f0; line-height: 1.6; }}
            h2 {{ color: #575fcf; border-bottom: 2px solid #575fcf; padding-bottom: 5px; }}
            h3 {{ color: #aab0b8 !important; border-left: 5px solid #444a59; padding-left: 10px; margin-top: 20px; }}
            p, ul {{ margin-left: 15px; }} li {{ margin-bottom: 5px; }}
            .threat-level {{ font-weight: bold; color: {threat_color}; }}
            </style></head><body>
            <h2>イベント分析レポート</h2>
            <p><strong>ID:</strong> {context_data['検知ID']}<br>
            <strong>ルール:</strong> {context_data['ルールタイトル']}<br>
            <strong>深刻度:</strong> <span class="threat-level">{context_data['深刻度']}</span></p><hr>
            {self.current_ai_report}
            </body></html>
            """
            self.report_space.setHtml(full_html)
            self.pdf_button.setEnabled(True)
            self.block_button.setEnabled(True)

    def on_pdf_button_clicked(self):
        if not self.current_ai_report: return
        html_content = self.report_space.toHtml()
        success, message = self.pdf_generator.generate_pdf_from_html(html_content, self)
        if success: QMessageBox.information(self, "成功", f"PDFレポートが正常に保存されました。\\nパス: {message}")
        else: QMessageBox.critical(self, "失敗", f"PDFの生成に失敗しました。\\nエラー: {message}")

    def on_block_button_clicked(self):
        if not self.current_selected_context: return
        
        log_content = self.current_selected_context.get('元ログ', '')
        ip_addresses = re.findall(r'\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b', log_content)
        
        if not ip_addresses:
            QMessageBox.warning(self, "エラー", "ログからブロック可能なIPアドレスが見つかりませんでした。")
            return
        
        ip_to_block = ip_addresses[0]
        if self.real_defense.add_to_blocklist(ip_to_block):
            QMessageBox.information(self, "防御実行", f"IPアドレス {ip_to_block} をブロックリストに追加しました。")
        else:
            QMessageBox.information(self, "情報", f"IPアドレス {ip_to_block} は既にブロックリストに存在するか、ブロックに失敗しました。")

    def closeEvent(self, event):
        self.session.close()
        super().closeEvent(event)