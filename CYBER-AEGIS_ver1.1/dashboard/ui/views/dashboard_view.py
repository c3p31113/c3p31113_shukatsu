import os
import json
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QTableView,
                             QAbstractItemView, QLabel, QTextEdit, QPushButton,
                             QHeaderView, QMessageBox, QSplitter)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor

from src.data_integrators.network_monitor import NetworkMonitor
from src.core_ai.ollama_manager import OllamaManager
from src.defense_matrix.real_defense import RealDefense
from src.database.db_manager import DBManager
from src.reporting.pdf_generator import PDFGenerator
from src.utils.notifier import notifier
from src.utils.config_manager import ConfigManager
from src.threat_intel.orion_investigator import OrionInvestigator

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
        finally:
            self.finished.emit()

class NetworkWorker(QThread):
    result = pyqtSignal(list)
    finished = pyqtSignal()
    def __init__(self, network_monitor):
        super().__init__()
        self.network_monitor = network_monitor
    def run(self):
        try:
            connections = self.network_monitor.get_active_connections()
            self.result.emit(connections)
        finally:
            self.finished.emit()

class HistoryLoaderWorker(QThread):
    result = pyqtSignal(list)
    def __init__(self, db_manager_method):
        super().__init__()
        self.db_manager_method = db_manager_method
    def run(self):
        history = self.db_manager_method()
        self.result.emit(history)

class OrionWorker(QThread):
    result_ready = pyqtSignal(dict)
    def __init__(self, investigator, target):
        super().__init__()
        self.investigator = investigator
        self.target = target

    def run(self):
        results = {}
        target_to_check = self.target.split(':')[0]

        if '.' in target_to_check and not target_to_check.replace('.', '').isdigit():
            results['whois'] = self.investigator.get_whois_info(target_to_check)
        else:
            results['whois'] = {"info": "ターゲットはIPアドレスのため、WHOIS調査をスキップしました。"}
        
        url_to_check = target_to_check
        if not url_to_check.startswith(('http://', 'https://')):
            url_to_check = 'http://' + url_to_check
        results['google_safeBrowse'] = self.investigator.check_google_safeBrowse(url_to_check)
        self.result_ready.emit(results)


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.network_monitor = NetworkMonitor()
        self.real_defense = RealDefense()
        self.db_manager = DBManager()
        self.pdf_generator = PDFGenerator()
        self.config_manager = ConfigManager()
        self.investigator = OrionInvestigator()
        self.model_name = "gemma:2b"
        self.ai_thread = None
        self.network_thread = None
        self.history_thread = None
        self.orion_thread = None
        self.current_request_id = None
        self.current_selected_context = None
        self.network_id_counter = self.get_latest_network_id()
        self.current_ai_report = None
        self.current_orion_report = None
        
        self.init_ui()
        self.load_historical_data()
        self.auto_refresh_timer = QTimer(self)
        self.auto_refresh_timer.setInterval(15000)
        self.auto_refresh_timer.timeout.connect(self.load_network_data)
        self.auto_refresh_timer.start()
        
    def get_latest_network_id(self):
        incidents = self.db_manager.get_all_network_incidents(limit=1)
        if not incidents: return 1
        try:
            return int(incidents[0]['id'].split('-')[1]) + 1
        except (IndexError, ValueError):
            return 1

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        self.incident_table = QTableView()
        self.incident_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.incident_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.incident_table.verticalHeader().setVisible(False)
        self.incident_table.setSortingEnabled(True)
        self.incident_table.clicked.connect(self.on_incident_selected)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["ID", "名称", "検知時刻", "接続先", "脅威レベル", "対応状況"])
        self.incident_table.setModel(self.model)
        header = self.incident_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.refresh_button = QPushButton("手動更新")
        self.refresh_button.clicked.connect(self.load_network_data)
        left_layout.addWidget(self.incident_table)
        left_layout.addWidget(self.refresh_button)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        report_label = QLabel("AIアナリシス・レポート")
        report_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        self.report_space = QTextEdit()
        self.report_space.setReadOnly(True)
        self.report_space.setPlaceholderText("インシデントを選択すると、ここにAIによる分析とOrionによる調査結果が表示されます。")
        button_layout = QHBoxLayout()
        self.pdf_button = QPushButton("PDF形式で出力")
        self.block_button = QPushButton("この通信をブロック")
        self.pdf_button.setEnabled(False)
        self.block_button.setEnabled(False)
        button_layout.addWidget(self.pdf_button)
        button_layout.addWidget(self.block_button)
        right_layout.addWidget(report_label)
        right_layout.addWidget(self.report_space)
        right_layout.addLayout(button_layout)
        
        main_splitter.addWidget(left_widget)
        main_splitter.addWidget(right_widget)
        main_splitter.setSizes([800, 500])
        main_layout.addWidget(main_splitter)

        self.block_button.clicked.connect(self.on_block_button_clicked)
        self.pdf_button.clicked.connect(self.on_pdf_button_clicked)

    def load_historical_data(self):
        self.incident_table.setEnabled(False)
        self.history_thread = HistoryLoaderWorker(self.db_manager.get_all_network_incidents)
        self.history_thread.result.connect(lambda incidents: self.update_table_data(incidents, clear_existing=True))
        self.history_thread.finished.connect(lambda: self.incident_table.setEnabled(True))
        self.history_thread.start()

    def load_network_data(self):
        if self.network_thread and self.network_thread.isRunning(): return
        self.refresh_button.setEnabled(False)
        self.refresh_button.setText("更新中...")
        self.network_thread = NetworkWorker(self.network_monitor)
        self.network_thread.result.connect(self.update_table_data)
        self.network_thread.finished.connect(lambda: (self.refresh_button.setEnabled(True), self.refresh_button.setText("手動更新")))
        self.network_thread.start()

    def update_table_data(self, connections, clear_existing=False):
        if clear_existing: self.model.removeRows(0, self.model.rowCount())
        threat_colors = {"LOW": QColor("#2ecc71"), "MEDIUM": QColor("#f1c40f"), "HIGH": QColor("#e67e22"), "CRITICAL": QColor("#c0392b")}
        auto_defense_enabled = self.config_manager.get_boolean('Automation', 'auto_defense_enabled')
        for conn in reversed(connections):
            is_new_event = 'id' not in conn
            if is_new_event:
                conn['id'] = f"NET-{self.network_id_counter:04d}"
                self.network_id_counter += 1
                if conn.get("threat_level") == "CRITICAL" and auto_defense_enabled:
                    destination = conn.get('destination', '')
                    ip_to_block = destination.split(':')[0]
                    if ip_to_block and not self.real_defense.is_blocked(ip_to_block):
                        self.real_defense.add_to_blocklist(ip_to_block)
                        conn['status'] = "自動ブロック済み"
                        notifier.show_notification(title=f"🛡️ ネットワーク脅威を自動ブロックしました", message=f"プロセス '{conn.get('name')}' から '{ip_to_block}' への通信をブロックリストに追加しました。")
                elif conn.get("threat_level") == "CRITICAL":
                    notifier.show_notification(title=f"🚨 CRITICALなネットワーク脅威を検知", message=f"プロセス '{conn.get('name')}' が '{conn.get('destination')}' へ接続しました。")
                self.db_manager.add_network_incident(conn)
            
            row = [QStandardItem(conn.get("id", "N/A")), QStandardItem(conn.get("name", "N/A")), QStandardItem(conn.get("time")), QStandardItem(conn.get("destination")), QStandardItem(conn.get("threat_level")), QStandardItem(conn.get("status"))]
            threat_item = row[4]
            threat_item.setForeground(QColor("white"))
            threat_item.setBackground(threat_colors.get(conn.get("threat_level"), QColor("gray")))
            if clear_existing: self.model.appendRow(row)
            else: self.model.insertRow(0, row)
        if not clear_existing: self.incident_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)

    def on_incident_selected(self, index):
        if (self.ai_thread and self.ai_thread.isRunning()) or (self.orion_thread and self.orion_thread.isRunning()): return
        row_data = {self.model.headerData(col, Qt.Orientation.Horizontal): self.model.item(index.row(), col).text() for col in range(self.model.columnCount())}
        self.current_request_id = row_data['ID']
        self.current_selected_context = row_data
        
        self.current_ai_report, self.current_orion_report = None, None
        self.report_space.setText(f"インシデントID: {self.current_request_id} の分析を開始しました...\nAIアナリストとOrion調査官が同時に調査中です。")
        self.pdf_button.setEnabled(False); self.block_button.setEnabled(False)

        system_message = "あなたはプロのAIセキュリティアナリストです。あなたの唯一の役割は、与えられたインシデントデータを分析し、HTML形式でレポートを生成することです。会話は不要です。日本語のHTMLレポートのみを生成してください。"
        prompt = f"""<INSTRUCTION>
以下の<TASK_INPUT>のデータを分析し、脅威レベルに応じてHTMLレポートを生成してください。
提示された<EXAMPLE>の形式とトーンに厳密に従ってください。
</INSTRUCTION>
<EXAMPLE No.1: CRITICALな脅威>
TASK_INPUT: ID: NET-9999, プロセス名: malware.exe, 接続先: 198.51.100.23:666, 脅威レベル: CRITICAL
OUTPUT:
<div><h3>インシデント概要</h3><p>プロセス「malware.exe」から、既知のC2サーバーであるIPアドレス「198.51.100.23」への不審な通信が検知されました。</p><h3>潜在的リスク</h3><p>CRITICALレベルの脅威です。PCがマルウェアに感染し、外部の攻撃者によって遠隔操作される危険性が極めて高い状態です。情報漏洩や更なる攻撃の踏み台にされる可能性があります。</p><h3>推奨される対応</h3><ul><li>直ちにPCをネットワークから物理的に切断してください。</li><li>セキュリティ管理者に報告し、指示を仰いでください。</li><li>このPCでの作業をすべて中断してください。</li></ul></div>
</EXAMPLE>
<EXAMPLE No.2: LOWな脅威（正規のアプリケーション）>
TASK_INPUT: ID: NET-0100, プロセス名: Zoom.exe, 接続先: 170.114.4.156:443, 脅威レベル: LOW
OUTPUT:
<div><h3>インシデント概要</h3><p>正規のビデオ会議アプリケーション「Zoom.exe」から、Zoomのサーバーへの通常の通信が確認されました。</p><h3>潜在的リスク</h3><p>LOWレベルの脅威であり、この通信自体にリスクはほとんどありません。正規のアプリケーションによる正当な通信です。</p><h3>推奨される対応</h3><ul><li>ご自身の操作（ビデオ会議など）によるものであれば、特別な対応は不要です。</li><li>身に覚えのない通信である場合は、アプリケーションが最新の状態であるか確認してください。</li></ul></div>
</EXAMPLE>
<TASK_INPUT>
ID: {row_data['ID']}, プロセス名: {row_data['名称']}, 接続先: {row_data['接続先']}, 脅威レベル: {row_data['脅威レベル']}
</TASK_INPUT>
"""
        self.ai_thread = AIWorker(prompt, system_message, row_data, self.model_name)
        self.ai_thread.result.connect(self.on_ai_result_ready)
        self.ai_thread.start()

        target = row_data.get('接続先')
        if target:
            self.orion_thread = OrionWorker(self.investigator, target)
            self.orion_thread.result_ready.connect(self.on_orion_result_ready)
            self.orion_thread.start()
        else:
            self.current_orion_report = {"info": "接続先情報が取得できなかったため、Orion調査はスキップされました。"}
            self.update_final_report()

    def on_ai_result_ready(self, result_tuple):
        ai_html_report, context_data = result_tuple
        if context_data['ID'] != self.current_request_id: return
        self.current_ai_report = ai_html_report
        self.update_final_report()

    def on_orion_result_ready(self, results):
        self.current_orion_report = results
        self.update_final_report()

    def update_final_report(self):
        if self.current_ai_report is not None and self.current_orion_report is not None:
            context_data = self.current_selected_context
            clean_ai_report = self.current_ai_report.strip()
            if "```html" in clean_ai_report: clean_ai_report = clean_ai_report.split("```html",1)[-1]
            if "```" in clean_ai_report: clean_ai_report = clean_ai_report.rsplit("```",1)[0]
            clean_ai_report = clean_ai_report.strip()

            orion_report_html = "<h3>Orion 外部インテリジェンス調査</h3>"
            gsb = self.current_orion_report.get('google_safeBrowse', {})
            gsb_status = gsb.get('判定', '不明')
            gsb_color = "#e74c3c" if gsb_status == '危険' else "#2ecc71"
            orion_report_html += f"<p><b>Google Safe Browse:</b> <span style='color:{gsb_color}; font-weight:bold;'>{gsb_status}</span>"
            if gsb_status == '危険':
                details = gsb.get('詳細', [{}])
                if details: orion_report_html += f" - {details[0].get('threatType', 'N/A')}"
            orion_report_html += "</p>"

            whois = self.current_orion_report.get('whois', {})
            orion_report_html += "<ul>"
            if 'error' in whois: orion_report_html += f"<li><b>WHOIS:</b> {whois['error']}</li>"
            elif 'info' in whois: orion_report_html += f"<li><b>WHOIS:</b> {whois['info']}</li>"
            else:
                orion_report_html += f"<li><b>登録業者:</b> {whois.get('登録業者', 'N/A')}</li>"
                orion_report_html += f"<li><b>作成日時:</b> {whois.get('作成日時', 'N/A')}</li>"
                orion_report_html += f"<li><b>有効期限:</b> {whois.get('有効期限', 'N/A')}</li>"
                orion_report_html += f"<li><b>国:</b> {whois.get('国', 'N/A')}</li>"
            orion_report_html += "</ul>"
            
            threat_level=context_data['脅威レベル']; threat_color_map={"LOW":"#2ecc71","MEDIUM":"#f1c40f","HIGH":"#e67e22","CRITICAL":"#c0392b"}; threat_color=threat_color_map.get(threat_level,"gray")
            full_html=f"""<html><head><style>
            body{{font-family:'Segoe UI','Meiryo UI',sans-serif;color:#f0f0f0;line-height:1.6;}}
            h2{{color:#575fcf;border-bottom:2px solid #575fcf;padding-bottom:5px;}}
            h3{{color:#aab0b8 !important;border-left:5px solid #444a59;padding-left:10px;margin-top:20px;}}
            p,ul{{margin-left:15px;}}li{{margin-bottom:5px;}} pre{{white-space:pre-wrap;}}
            .threat-level{{font-weight:bold;color:{threat_color};}}
            </style></head><body>
            <h2>インシデント分析レポート</h2><p><strong>ID:</strong> {context_data['ID']}<br>
            <strong>プロセス名:</strong> {context_data['名称']}<br>
            <strong>接続先:</strong> {context_data['接続先']}<br>
            <strong>脅威レベル:</strong> <span class="threat-level">{threat_level}</span></p><hr>
            {clean_ai_report if clean_ai_report else"<p>AIからの応答がありませんでした。</p>"}
            <hr>
            {orion_report_html}
            </body></html>"""
            self.report_space.setHtml(full_html)
            self.pdf_button.setEnabled(True)
            self.block_button.setEnabled(True)
    
    def on_block_button_clicked(self):
        if not self.current_selected_context:return
        destination=self.current_selected_context.get('接続先',''); ip_to_block=destination.split(':')[0]
        if ip_to_block:
            if self.real_defense.add_to_blocklist(ip_to_block):
                msg_box=QMessageBox();msg_box.setIcon(QMessageBox.Icon.Warning);msg_box.setText(f"IPアドレス {ip_to_block} をブロックリストに追加しました。");msg_box.setWindowTitle("防御実行");msg_box.setStandardButtons(QMessageBox.StandardButton.Ok);msg_box.exec();
            else: QMessageBox.information(self, "情報", f"IPアドレス {ip_to_block} は既にブロックリストに存在します。")
        else: QMessageBox.warning(self,"エラー","有効なIPアドレスが見つかりませんでした。")

    def on_pdf_button_clicked(self):
        html_content = self.report_space.toHtml()
        success, message = self.pdf_generator.generate_pdf_from_html(html_content, self)
        if success: QMessageBox.information(self, "成功", f"PDFレポートが正常に保存されました。\nパス: {message}")
        else: QMessageBox.critical(self, "失敗", f"PDFの生成に失敗しました。\nエラー: {message}")

    def shutdown(self):
        print("[DashboardView] Shutting down all background resources...")
        if self.auto_refresh_timer.isActive(): self.auto_refresh_timer.stop()
        for thread in [self.ai_thread, self.network_thread, self.history_thread, self.orion_thread]:
            if thread and thread.isRunning():
                thread.quit(); thread.wait(1000)