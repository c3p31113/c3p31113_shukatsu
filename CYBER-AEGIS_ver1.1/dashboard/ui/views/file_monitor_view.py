# CYBER-AEGIS/dashboard/ui/views/file_monitor_view.py
import os
import datetime
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QTableView,
                             QAbstractItemView, QLabel, QTextEdit, QPushButton,
                             QHeaderView, QMessageBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor

from src.data_integrators.file_monitor import MonitorThread
from src.defense_matrix.real_defense import RealDefense
from src.database.db_manager import DBManager
from dashboard.ui.views.dashboard_view import AIWorker, HistoryLoaderWorker
from src.utils.notifier import notifier
from src.utils.config_manager import ConfigManager
from src.threat_intel.threat_scoring_engine import ThreatScoringEngine

class FileMonitorView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.model_name = "gemma3:latest"
        self.real_defense = RealDefense()
        self.db_manager = DBManager()
        self.config_manager = ConfigManager()
        self.scoring_engine = ThreatScoringEngine()
        self.ai_thread = None
        self.monitor_thread = None
        self.history_thread = None
        self.current_request_id = None
        self.current_selected_context = None
        self.event_id_counter = 1
        self.init_ui()
        self.load_historical_data()
        self.start_monitoring()

    def get_latest_event_id(self):
        events = self.db_manager.get_all_file_events(limit=1)
        if not events: return 1
        try:
            latest_id_str = events[0].get('id', 'FILE-0000')
            num_part = int(latest_id_str.split('-')[1])
            return num_part + 1
        except (IndexError, ValueError):
            return 1

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        left_layout = QVBoxLayout()
        self.event_table = QTableView()
        self.event_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.event_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.event_table.verticalHeader().setVisible(False)
        self.event_table.setSortingEnabled(True)
        self.event_table.clicked.connect(self.on_event_selected)
        
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["ID", "イベントタイプ", "ファイルパス", "検知時刻", "脅威レベル"])
        self.event_table.setModel(self.model)
        
        header = self.event_table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        left_layout.addWidget(self.event_table)
        
        right_layout = QVBoxLayout()
        report_label = QLabel("AIアナリシス・レポート")
        report_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        
        self.report_space = QTextEdit()
        self.report_space.setReadOnly(True)
        self.report_space.setPlaceholderText("ファイルイベントを選択すると、ここにAIによる分析結果が表示されます。")
        
        button_layout = QHBoxLayout()
        self.pdf_button = QPushButton("PDF形式で出力")
        self.quarantine_button = QPushButton("ファイルを隔離")
        self.pdf_button.setEnabled(False)
        self.quarantine_button.setEnabled(False)
        button_layout.addWidget(self.pdf_button)
        button_layout.addWidget(self.quarantine_button)
        
        right_layout.addWidget(report_label)
        right_layout.addWidget(self.report_space)
        right_layout.addLayout(button_layout)
        
        main_layout.addLayout(left_layout, 2)
        main_layout.addLayout(right_layout, 1)
        
        self.quarantine_button.clicked.connect(self.on_quarantine_button_clicked)

    def load_historical_data(self):
        self.event_table.setEnabled(False)
        self.history_thread = HistoryLoaderWorker(self.db_manager.get_all_file_events)
        self.history_thread.result.connect(self.process_historical_data)
        self.history_thread.finished.connect(lambda: self.event_table.setEnabled(True))
        self.history_thread.start()

    def process_historical_data(self, events):
        if not events:
            return
        for event in reversed(events):
            self.add_event_to_ui_table(event)
        self.event_id_counter = self.get_latest_event_id()

    def start_monitoring(self):
        if self.monitor_thread and self.monitor_thread.isRunning():
            return
        paths_to_watch = []
        home_dir = os.path.expanduser('~')
        possible_base_dirs = [home_dir, os.path.join(home_dir, 'OneDrive')]
        folder_name_map = {
            'desktop': ['Desktop', 'デスクトップ'],
            'downloads': ['Downloads', 'ダウンロード'],
            'documents': ['Documents', 'ドキュメント']
        }
        for key, names in folder_name_map.items():
            found = False
            for base in possible_base_dirs:
                for name in names:
                    path = os.path.join(base, name)
                    if os.path.exists(path) and path not in paths_to_watch:
                        paths_to_watch.append(path)
                        found = True
                        break
                if found: break
        try:
            raw_paths_from_config = self.config_manager.get_list('FileMonitorSettings', 'monitored_directories')
            if raw_paths_from_config:
                additional_paths = [os.path.expanduser(os.path.expandvars(p)) for p in raw_paths_from_config]
                for path in additional_paths:
                    if os.path.exists(path) and path not in paths_to_watch:
                        paths_to_watch.append(path)
        except Exception as e:
            print(f"config.iniからのパス読み込み中にエラーが発生しました: {e}")
        if not paths_to_watch:
            QMessageBox.warning(self, "監視エラー", "監視対象のフォルダが見つかりませんでした。config.iniを確認してください。")
            return
        print(f"ファイル監視を開始します。対象: {paths_to_watch}")
        self.monitor_thread = MonitorThread(paths_to_watch=paths_to_watch)
        self.monitor_thread.file_event_detected.connect(self.on_file_event)
        self.monitor_thread.start()

    def on_file_event(self, event_data):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        yara_matches = event_data.get('yara_matches', [])
        current_id = self.event_id_counter
        
        final_event_context = {
            "id": f"FILE-{current_id:04d}", "time": timestamp,
            "event_type": event_data['event_type'], "path": event_data['path'],
        }
        if yara_matches:
            matched_rules = ", ".join([match['rule'] for match in yara_matches])
            final_event_context['event_type'] = f"YARA検知 ({event_data['event_type']})"
            final_event_context['threat_level'] = 'CRITICAL'
            final_event_context['description'] = f"YARA rule(s) matched: {matched_rules}"
            notifier.show_notification(
                title="🚨 CRITICALなファイル脅威を検知",
                message=f"ファイル '{os.path.basename(final_event_context['path'])}' から脅威を検知しました。"
            )
        else:
            final_event_context['threat_level'] = self.scoring_engine.score_file_event(event_data)
            final_event_context['description'] = f"ファイルイベント '{event_data['event_type']}' が発生しました。"
        
        auto_defense_enabled = self.config_manager.get_boolean('Automation', 'auto_defense_enabled')
        if final_event_context["threat_level"] == "CRITICAL" and auto_defense_enabled:
            success, message = self.real_defense.quarantine_file(final_event_context['path'])
            if success:
                notifier.show_notification(
                    title="🛡️ ファイル脅威を自動隔離しました",
                    message=f"ファイル '{os.path.basename(final_event_context['path'])}' を隔離しました。"
                )
        
        self.db_manager.add_file_event(final_event_context)
        self.add_event_to_ui_table(final_event_context)
        self.event_id_counter += 1

    def add_event_to_ui_table(self, event_data):
        path_item = QStandardItem(event_data.get("path", event_data.get("file_path", "")))
        path_item.setToolTip(event_data.get("path", event_data.get("file_path", "")))
        threat_colors = {"LOW": QColor("#2ecc71"), "MEDIUM": QColor("#f1c40f"), "HIGH": QColor("#e67e22"), "CRITICAL": QColor("#e74c3c")}
        row_items = [
            QStandardItem(str(event_data.get("id", event_data.get("event_id")))),
            QStandardItem(event_data.get("event_type")),
            path_item,
            QStandardItem(event_data.get("time", event_data.get("event_time"))),
            QStandardItem(event_data.get("threat_level"))
        ]
        threat_item = row_items[4]
        threat_item.setForeground(QColor("white"))
        threat_item.setBackground(threat_colors.get(event_data.get("threat_level"), QColor("gray")))
        self.model.insertRow(0, row_items)

    def on_event_selected(self, index):
        if self.ai_thread and self.ai_thread.isRunning(): return
        row_data = {self.model.headerData(col, Qt.Orientation.Horizontal): self.model.item(index.row(), col).text() for col in range(self.model.columnCount())}
        self.current_request_id = row_data['イベントID']
        self.current_selected_context = row_data
        
        full_event_data = self.db_manager.get_event_by_id(self.current_request_id)
        
        yara_details_prompt = ""
        if full_event_data and 'description' in full_event_data and "YARA" in full_event_data.get('description', ''):
            raw_description = full_event_data.get('description')
            if "matched: " in raw_description:
                rules_str = raw_description.split("matched: ")[1]
                matched_rules = rules_str.split(", ")
                yara_details_prompt = (
                    "<YARA_ANALYSIS>\n"
                    "YARAはマルウェアの特徴を定義したパターンファイルです。\n"
                    f"今回、以下のYARAルールに一致しました:\n"
                    f"- {', '.join([f'**{r.strip()}**' for r in matched_rules])}\n"
                    "これらのルール名が示唆する脅威を専門的に分析してください。\n"
                    "</YARA_ANALYSIS>\n"
                )

        system_message = "あなたはサイバーセキュリティ専門のアナリストです。あなたの役割は、提示されたインシデントデータを基に、専門的かつ具体的で、示唆に富むHTML形式の分析レポートを作成することです。一般的で使い回しのできる助言や情報の繰り返しは絶対に避けてください。"
        
        prompt = f"""<ROLE>
あなたは、提供されたセキュリティイベントのデータと、私が与える厳格な指示とフォーマットに基づいて、HTML形式の分析レポートを生成する専門家です。
</ROLE>

<TASK>
以下の<TASK_INPUT>と<YARA_ANALYSIS>（もしあれば）の情報を分析し、脅威の詳細な分析レポートをHTML形式で生成してください。
</TASK>

<RULES>
1.  **思考プロセス:**
    -   まず、`<TASK_INPUT>`の`脅威レベル`を確認する。
    -   次に、`<YARA_ANALYSIS>`ブロックの**有無**を確認する。
    -   これらの情報に基づき、提供された`<EXAMPLE>`の中から**最も一致するシナリオを一つだけ選び**、その構造とトーンを**完璧に模倣**する。
2.  **出力フォーマット:**
    -   出力は必ず`<div>`タグから始まり、`</div>`タグで終わる単一のHTMLブロックでなければならない。
    -   `<html>`, `<body>`, `<h1>`, `<style>`などの余計なタグは絶対に含めてはならない。
    -   「推奨される対応」セクションは、**必ず**`<ul>`と`<li>`タグを使用する。
3.  **禁止事項:**
    -   `<YARA_ANALYSIS>`ブロックが**存在しない**場合、レポート内に「YARA」「マルウェア」「シグネチャ」「ウイルス」といった単語を**絶対に使用してはならない**。これは最も重要なルールです。
    -   `{{ variable }}`のようなテンプレート構文や、英語、中国語など、日本語以外の言語を絶対に使用してはならない。
    -   <TASK_INPUT>の情報をただ繰り返すだけの、価値のない文章を生成してはならない。
</RULES>

<EXAMPLE>
TASK_INPUT: {{'イベントID': 'FILE-9999', 'イベントタイプ': 'YARA検知 (作成)', 'ファイルパス': 'C:\\...\\test_virus.txt', '脅威レベル': 'CRITICAL'}}
YARA_ANALYSIS: YARAは...(**ここにYARA情報が入る**)
OUTPUT:
<div>
<h3>イベント概要</h3>
<p>監視対象の<b>デスクトップフォルダ</b>で作成されたファイル「<b>test_virus.txt</b>」から、既知のマルウェアシグネチャが検出されました。このイベントは<b>CRITICAL (深刻)</b>な脅威と評価されます。</p>
<h3>リスク分析</h3>
<p>検出されたシグネチャ<b>「EICAR_Test_String」</b>は、アンチウイルス製品の動作をテストするための標準的なテストパターンです。ファイル自体に直接的な破壊活動を行う能力はありませんが、このパターンが意図せず出現したことは、何者かが外部からファイルの書き込みに成功したことを意味します。これは、より悪質なマルウェアが送り込まれる前兆である可能性も考慮すべきです。自動防御システムにより、このファイルは既に隔離されています。</p>
<h3>推奨される対応</h3>
<ul>
    <li><b>隔離の確認:</b> ファイルが正常に隔離されていることを確認してください。</li>
    <li><b>出所の特定:</b> このファイルが意図せず作成されたものである場合、その侵入経路（例: メール添付、不正なWebサイトからのダウンロード）を特定することが重要です。</li>
</ul>
</div>
</EXAMPLE>

<EXAMPLE>
TASK_INPUT: {{'イベントID': 'FILE-0010', 'イベントタイプ': '作成', 'ファイルパス': 'C:\\Users\\...\\Documents\\o.txt', '脅威レベル': 'LOW'}}
OUTPUT:
<div>
<h3>イベント概要</h3>
<p>ドキュメントフォルダに「<b>o.txt</b>」という名前のテキストファイルが作成されました。これは日常的な操作であり、脅威の可能性は低い<b>LOW (低)</b>と評価されます。</p>
<h3>リスク分析</h3>
<p>テキストファイルの作成は通常、安全なイベントです。しかし、あらゆるファイルには、意図せず機密情報が含まれてしまうリスクや、フィッシング攻撃の一環として送られてきたものである可能性がゼロではありません。</p>
<h3>推奨される対応</h3>
<ul>
    <li><b>心当たりの確認:</b> ご自身が作成したファイルであれば、特別な対応は不要です。</li>
    <li><b>内容への注意:</b> ファイルを開く際は、本文中に不審なURLなどが含まれていないか、基本的な注意を払ってください。</li>
</ul>
</div>
</EXAMPLE>

<TASK_INPUT>
{row_data}
</TASK_INPUT>
{yara_details_prompt}
"""
        
        self.report_space.setText(f"AIがイベントID: {self.current_request_id} の分析を開始しました...")
        self.ai_thread = AIWorker(prompt, system_message, row_data, self.model_name)
        self.ai_thread.result.connect(self.display_ai_report_as_html)
        self.ai_thread.start()

    def on_quarantine_button_clicked(self):
        if not self.current_selected_context:return
        file_path_to_quarantine=self.current_selected_context.get('ファイルパス','')
        if not file_path_to_quarantine:
            QMessageBox.warning(self, "警告", "ファイルパスが選択されていません。")
            return
        success,message=self.real_defense.quarantine_file(file_path_to_quarantine)
        if success:QMessageBox.information(self,"成功",message)
        else:QMessageBox.critical(self,"失敗",message)
    
    def display_ai_report_as_html(self,result_tuple):
        ai_html_report,context_data=result_tuple
        if context_data['イベントID']!=self.current_request_id:return
        self.pdf_button.setEnabled(True)
        self.quarantine_button.setEnabled(True)
        clean_report=ai_html_report.strip()
        if"```html"in clean_report:clean_report=clean_report.split("```html",1)[-1]
        if"```"in clean_report:clean_report=clean_report.rsplit("```",1)[0]
        clean_report=clean_report.strip()
        threat_level=context_data['脅威レベル']
        threat_color_map={"LOW":"#2ecc71","MEDIUM":"#f1c40f","HIGH":"#e67e22","CRITICAL":"#e74c3c"}
        threat_color=threat_color_map.get(threat_level,"gray")
        full_html=f"""<html><head><style>
        body{{font-family:'Segoe UI','Meiryo UI',sans-serif;color:#f0f0f0;line-height:1.6;}}
        h2{{color:#575fcf;border-bottom:2px solid #575fcf;padding-bottom:5px;}}
        h3{{color:#aab0b8 !important;border-left:5px solid #444a59;padding-left:10px;margin-top:20px;}}
        p,ul{{margin-left:15px;}}
        li{{margin-bottom:5px;}}
        .threat-level{{font-weight:bold;color:{threat_color};}}
        </style></head><body>
        <h2>イベント分析レポート</h2>
        <p><strong>ID:</strong> {context_data['イベントID']}<br>
        <strong>イベント:</strong> {context_data['イベントタイプ']}<br>
        <strong>パス:</strong> {context_data['ファイルパス']}<br>
        <strong>脅威レベル:</strong> <span class="threat-level">{threat_level}</span></p><hr>
        {clean_report if clean_report else"<p>AIからの応答がありませんでした。</p>"}
        </body></html>"""
        self.report_space.setHtml(full_html)

    def closeEvent(self, event):
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
            self.monitor_thread.wait()
        super().closeEvent(event)