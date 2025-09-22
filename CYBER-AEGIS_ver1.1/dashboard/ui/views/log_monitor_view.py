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
from src.defense_matrix.real_defense import RealDefense

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
            if col == 3: return row_data.rule_level.upper() if row_data.rule_level else ""
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
        self.real_defense = RealDefense()
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
            selected_id = None
            current_index = self.table_view.selectionModel().currentIndex()
            if current_index.isValid():
                match = self.model.get_match_by_index(current_index)
                if match:
                    selected_id = match.id

            self.session.expire_all()
            matches = self.session.query(SigmaMatch).order_by(SigmaMatch.timestamp.desc()).all()
            
            self.model = SigmaTableModel(matches)
            self.table_view.setModel(self.model)
            
            if selected_id is not None:
                for row, match in enumerate(self.model._data):
                    if match.id == selected_id:
                        new_index = self.model.index(row, 0)
                        self.table_view.selectionModel().setCurrentIndex(new_index, QItemSelectionModel.SelectionFlag.SelectRows)
                        break

        except Exception as e:
            print(f"データベースエラー: データを読み込めませんでした: {e}")

    def on_log_event_selected(self, index):
        if self.ai_thread and self.ai_thread.isRunning():
            QMessageBox.information(self, "情報", "AI分析が実行中です。完了するまでお待ちください。")
            return

        match_index = self.table_view.model().index(index.row(), 0)
        match = self.model.get_match_by_index(match_index)

        if match:
            self.current_selected_context = {
                "検知ID": f"LOG-{match.id:04d}",
                "タイムスタンプ": match.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "ルールタイトル": match.rule_title,
                "深刻度": match.rule_level.upper() if match.rule_level else "",
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
        self.table_view.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.timer.stop()

        system_message = "あなたはサイバーセキュリティ専門のアナリストです。あなたの役割は、提示されたインシデントデータを基に、専門的かつ具体的で、示唆に富むHTML形式の分析レポートを作成することです。一般的で使い回しのできる助言や情報の繰り返しは絶対に避けてください。"
        
        prompt = f"""<ROLE>
あなたは、提供されたセキュリティイベントのデータと、私が与える厳格な指示とフォーマットに基づいて、HTML形式の分析レポートを生成する専門家です。
</ROLE>
<TASK>
以下の<TASK_INPUT>の情報を分析し、脅威の詳細な分析レポートをHTML形式で生成してください。
</TASK>
<RULES>
1.  **思考プロセス:**
    -   まず、`<TASK_INPUT>`の`深刻度`と`ルールタイトル`を確認する。
    -   次に、`元ログ`の内容を深く分析し、攻撃の兆候や手法を特定する。
    -   これらの情報に基づき、提供された`<EXAMPLE>`の中から**最も一致するシナリオを一つだけ選び**、その構造とトーンを**完璧に模倣**する。
2.  **出力フォーマット:**
    -   出力は必ず`<h3>`タグから始まり、「推奨される対処法」の`</ul>`で終わる単一のHTMLブロックでなければならない。
    -   `<html>`, `<body>`, `<div>`, `<h1>`, `<style>`などの余計なタグは絶対に含めてはならない。
    -   「推奨される対応」セクションは、**必ず**`<ul>`と`<li>`タグを使用する。
3.  **禁止事項:**
    -   `{{ variable }}`のようなテンプレート構文や、英語、中国語など、日本語以外の言語を絶対に使用してはならない。
    -   <TASK_INPUT>の情報をただ繰り返すだけの、価値のない文章を生成してはならない。
</RULES>
<EXAMPLE>
TASK_INPUT: {{'検知ID': 'LOG-0001', 'ルールタイトル': 'Suspicious PowerShell Command', '深刻度': 'HIGH', '元ログ': 'powershell -enc JABjAGwA...'}}
OUTPUT:
<h3>イベント概要</h3>
<p>難読化されたPowerShellコマンドの実行が検知されました。これは、攻撃者が自身の活動を隠蔽し、システム上で不正なコードを実行しようとする際によく用いられる手法であり、脅威度は<b>HIGH (高)</b>と評価されます。</p>
<h3>リスク分析</h3>
<p>エンコードされたコマンドは、ファイルレスマルウェアのダウンロードや実行、永続化メカニズムの確立、横展開（ラテラルムーブメント）など、様々な悪意のある活動の起点となる可能性があります。難読化されているため、具体的な動作を即座に特定することは困難ですが、セキュリティ製品による検知を回避する意図は明らかです。</p>
<h3>推奨される対処法</h3>
<ul>
    <li><b>コマンドのデコード:</b> まず、エンコードされたPowerShellコマンドをデコードし、実行されようとしていた具体的な処理内容を特定してください。</li>
    <li><b>プロセスの親子関係の調査:</b> このPowerShellプロセスを起動した親プロセスを特定し、攻撃の侵入経路や連鎖を調査することが重要です。</li>
    <li><b>関連通信の確認:</b> 当該時刻付近のネットワークログを確認し、不審な外部IPアドレスへの通信が発生していないか調査してください。</li>
</ul>
</EXAMPLE>
<EXAMPLE>
TASK_INPUT: {{'検知ID': 'LOG-0002', 'ルールタイトル': 'Successful User Logon', '深刻度': 'LOW', '元ログ': 'Audit Success, User: admin, Logon Type: 2'}}
OUTPUT:
<h3>イベント概要</h3>
<p>ユーザー 'admin' による成功したログインが記録されました。これは日常的な操作である可能性が高く、脅威度は<b>LOW (低)</b>と評価されます。</p>
<h3>リスク分析</h3>
<p>成功したログイン自体は脅威ではありません。しかし、もしこのログインが深夜帯や休日に記録されている、あるいは通常とは異なる場所からアクセスされている場合、正規のアカウントが乗っ取られた可能性も考慮する必要があります。</p>
<h3>推奨される対処法</h3>
<ul>
    <li><b>心当たりの確認:</b> このログイン操作に心当たりがあるか、担当者に確認してください。</li>
    <li><b>時刻と場所の確認:</b> 業務時間外や、通常アクセスしない場所からのログインであった場合は、追加の調査を検討してください。</li>
    <li><b>不審な操作の有無:</b> このログイン後の操作ログを確認し、不審なアクティビティがないかを確認してください。</li>
</ul>
</EXAMPLE>
<TASK_INPUT>
{self.current_selected_context}
</TASK_INPUT>
"""
        
        self.ai_thread = AIWorker(prompt, system_message, self.current_selected_context, self.model_name)
        self.ai_thread.result.connect(self.update_report_space)
        self.ai_thread.finished.connect(self.on_ai_analysis_finished)
        self.ai_thread.start()

    def on_ai_analysis_finished(self):
        self.table_view.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.timer.start(15000)

        if self.ai_thread:
            self.ai_thread.deleteLater()
            self.ai_thread = None

    def update_report_space(self, result_tuple):
        report, context_data = result_tuple
        if self.current_selected_context and context_data["検知ID"] == self.current_selected_context["検知ID"]:
            
            # ▼▼▼【ここから修正】▼▼▼
            clean_report = report.strip()
            if "```html" in clean_report:
                clean_report = clean_report.split("```html", 1)[-1]
            if "```" in clean_report:
                clean_report = clean_report.rsplit("```", 1)[0]
            self.current_ai_report = clean_report.strip()
            # ▲▲▲【ここまで修正】▲▲▲
            
            threat_level_lower = context_data['深刻度'].lower()
            threat_color_map = {"low": "#2ecc71", "medium": "#f1c40f", "high": "#e67e22", "critical": "#c0392b"}
            threat_color = threat_color_map.get(threat_level_lower, "gray")
            
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
