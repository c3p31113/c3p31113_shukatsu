import json
import re
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, 
                             QPushButton, QTableView, QHeaderView, QAbstractItemView, 
                             QMessageBox, QSplitter, QLineEdit, QListWidget, 
                             QListWidgetItem, QTabWidget, QCheckBox, QSlider)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, QUrl, Qt
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QDesktopServices, QColor

from service.sns_manager import SNSManager
from src.collectors.github_collector import GithubCollector
from src.core_ai.ollama_manager import OllamaManager
from src.utils.config_manager import ConfigManager

class ScanWorker(QThread):
    finished = pyqtSignal()
    def __init__(self, sns_manager, keywords_map):
        super().__init__()
        self.sns_manager = sns_manager
        self.keywords_map = keywords_map
    def run(self):
        self.sns_manager.scan_all_sources(self.keywords_map)
        self.finished.emit()

class AiAnalysisWorker(QThread):
    result_ready = pyqtSignal(str, dict)
    def __init__(self, leak_item, model_name):
        super().__init__()
        self.leak_item = leak_item
        self.ai_manager = OllamaManager(model=model_name, timeout=3000)
        # GitHubのファイル内容取得でのみ必要
        if self.leak_item.get('id', '').startswith('gh-'):
            self.github_collector = GithubCollector()
        else:
            self.github_collector = None
            
    def _get_analysis_context(self):
        source_id = self.leak_item.get('id', '')
        keyword = self.leak_item.get('keyword')
        
        if source_id.startswith('gh-') and self.github_collector:
            file_content, _ = self.github_collector.get_file_content(self.leak_item['repository'], self.leak_item['file_path'])
            if file_content:
                lines = file_content.splitlines()
                for i, line in enumerate(lines):
                    if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                        start, end = max(0, i - 10), min(len(lines), i + 11)
                        return "\n".join(lines[start:end]), "GitHubのファイル"
                return file_content[:2000], "GitHubのファイル"
            return "\n".join(self.leak_item.get('matches', [])), "GitHubの検索結果"
        elif source_id.startswith('x-'):
            return self.leak_item.get('tweet_text', ''), "X(Twitter)の投稿"
        elif source_id.startswith('dsc-'):
            return f"サーバー: {self.leak_item.get('server')}\nチャンネル: #{self.leak_item.get('channel')}\n投稿者: {self.leak_item.get('author')}\n\n{self.leak_item.get('message_text')}", "Discordの投稿"
        elif source_id.startswith('pst-'):
            return f"タイトル: {self.leak_item.get('title')}\n\n{self.leak_item.get('content_preview', '')}", "Pastebinの投稿"
            
        return "コンテキスト情報なし", "不明"

    def _perform_programmatic_analysis(self, context, keyword, source_type):
        risk, confidence, reason = "MEDIUM", 0.5, "公開情報で秘密情報らしきキーワードが検出されました。"
        if source_type.startswith("GitHub") and "AKIA" in keyword.upper() and re.search(r'AKIA[0-9A-Z]{16}', context):
                risk, confidence, reason = "CRITICAL", 0.9, "AWSのアクセスキーIDのフォーマットに完全に一致しています。"
        elif any(indicator in context.lower() for indicator in ['test', 'example', 'dummy', 'sample', 'demo']):
                risk, confidence, reason = "LOW", 0.3, "テスト用の情報である可能性が高いです。"
        return {"risk": risk, "confidence": confidence, "reason": reason}

    def run(self):
        unified_id = self.leak_item['id']
        try:
            context_text, source_type = self._get_analysis_context()
            programmatic_result = self._perform_programmatic_analysis(context_text, self.leak_item['keyword'], source_type)
            system_prompt = "あなたは、提供された情報を基に、サイバーセキュリティのリスクを評価し、4つの項目でレポートを作成する専門家です。"
            user_prompt_1 = f"""以下の情報を分析し、4つの項目でレポートを作成してください。\n\n# 分析対象情報\n- 情報源: {source_type}\n- キーワード: {self.leak_item['keyword']}\n- コンテンツ:\n```\n{context_text}\n```\n- プログラムによる一次評価: 危険度「{programmatic_result['risk']}」、理由「{programmatic_result['reason']}」\n\n# 作成するレポートの4項目\n1. 概要:\n2. 脅威の分析:\n3. 利用者への直接的な害:\n4. 将来的なリスク:"""
            free_text_report = self.ai_manager.generate_response(user_prompt_1, system_prompt)
            if not free_text_report.strip(): raise ValueError("ステージ1: AIが空の応答を返しました。")
            system_prompt_2 = "あなたは、与えられた文章を、指定されたJSON形式に変換するAIです。応答にはJSON以外のテキストを一切含めないでください。"
            user_prompt_2 = f"""以下の「レポート文章」を読み、内容を4つのキー（summary, threat_summary, direct_harm, future_harm）を持つJSONオブジェクトに変換してください。\n\n# レポート文章\n{free_text_report}\n\n# JSON出力形式\n{{ "summary": "...", "threat_summary": "...", "direct_harm": "...", "future_harm": "..." }}"""
            json_response_text = self.ai_manager.generate_response(user_prompt_2, system_prompt_2)
            match = re.search(r'\{.*\}', json_response_text, re.DOTALL)
            if not match: raise json.JSONDecodeError("ステージ2: AIの応答からJSONが見つかりません。", json_response_text, 0)
            ai_answers = json.loads(match.group(0))
            final_result = {"risk_level": programmatic_result['risk'], "confidence": programmatic_result['confidence'], "report_data": {"repository_summary": ai_answers.get('summary', 'N/A'),"threat_summary": ai_answers.get('threat_summary', 'N/A'), "direct_harm": ai_answers.get('direct_harm', 'N/A'), "future_harm": ai_answers.get('future_harm', 'N/A')}}
        except Exception as e:
            error_report = {"error_report": f"AIサマリー生成中にエラーが発生: {e}"}
            final_result = {"risk_level": "UNKNOWN", "confidence": 0.0, "report_data": error_report}
        self.result_ready.emit(unified_id, final_result)


class SnsThreatWatcherView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.sns_manager = SNSManager()
        self.db_manager = self.sns_manager.db
        self.ai_workers = {}
        config = ConfigManager()
        self.ai_model_name = config.get('AI_CONFIG', 'sns_model', fallback='gemma2:latest')
        self.cooldown_timer = QTimer(self); self.cooldown_seconds = 0
        self.cooldown_timer.timeout.connect(self.update_cooldown)
        self.init_ui()
        self.load_keywords_to_ui()
        self.load_detected_leaks()
        self.auto_scan_timer = QTimer(self)
        self.auto_scan_timer.timeout.connect(self.start_scan)
        self.auto_scan_timer.start(3600 * 1000)

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        left_splitter = QSplitter(Qt.Orientation.Vertical)
        table_widget = QWidget(); table_layout = QVBoxLayout(table_widget)
        title_label = QLabel(f"SNS Threat Watcher (統合監視) | Model: {self.ai_model_name}")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        
        self.leaks_table = QTableView(); self.leaks_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.leaks_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.leaks_table.verticalHeader().setVisible(False)
        self.leaks_model = QStandardItemModel(); self.leaks_model.setHorizontalHeaderLabels(["検知日時", "関連度", "ソース", "ステータス", "信頼度", "キーワード", "場所 / タイトル"])
        self.leaks_table.setModel(self.leaks_model)
        header = self.leaks_table.horizontalHeader()
        for i, width in enumerate([140, 60, 70, 100, 60, 100, 250]):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch if i == 6 else QHeaderView.ResizeMode.Interactive)
            if i != 6 : header.resizeSection(i, width)
        self.leaks_table.clicked.connect(self.on_row_selected); self.leaks_table.doubleClicked.connect(self.on_row_double_clicked)
        
        action_layout = QHBoxLayout(); self.scan_button = QPushButton("分析サイクル開始"); self.refresh_button = QPushButton("表示更新")
        self.status_label = QLabel("待機中..."); action_layout.addWidget(self.scan_button); action_layout.addWidget(self.refresh_button)
        action_layout.addStretch(); action_layout.addWidget(self.status_label)
        
        filter_layout = QHBoxLayout(); self.relevance_filter_checkbox = QCheckBox("関連度でソート/フィルタ"); self.relevance_filter_checkbox.setChecked(True)
        self.relevance_filter_checkbox.stateChanged.connect(self.load_detected_leaks); self.threshold_slider = QSlider(Qt.Orientation.Horizontal)
        self.threshold_slider.setRange(0, 100); self.threshold_slider.setValue(10); self.threshold_slider.valueChanged.connect(self.update_threshold_label)
        self.threshold_slider.sliderReleased.connect(self.load_detected_leaks); self.threshold_label = QLabel(f"関連度 {self.threshold_slider.value()}% 以上")
        filter_layout.addWidget(self.relevance_filter_checkbox); filter_layout.addWidget(self.threshold_slider); filter_layout.addWidget(self.threshold_label); filter_layout.addStretch()

        table_layout.addWidget(title_label); table_layout.addLayout(filter_layout); table_layout.addWidget(self.leaks_table); table_layout.addLayout(action_layout)

        keyword_mgmt_widget = QWidget(); keyword_mgmt_layout = QVBoxLayout(keyword_mgmt_widget)
        self.keyword_tabs = QTabWidget(); self.keyword_widgets = {}
        for key, name in [('github', 'GitHub'), ('x', 'X'), ('discord', 'Discord'), ('pastebin', 'Pastebin')]:
            widget = QWidget(); layout = QVBoxLayout(widget); list_widget = QListWidget()
            list_widget.itemDoubleClicked.connect(lambda item, k=key: self.remove_keyword(k, item)); input_layout = QHBoxLayout()
            input_box = QLineEdit(); input_box.setPlaceholderText(f"{name}のキーワードを追加..."); add_button = QPushButton("追加")
            add_button.clicked.connect(lambda _, k=key, i=input_box: self.add_keyword(k, i)); input_box.returnPressed.connect(lambda k=key, i=input_box: self.add_keyword(k, i))
            input_layout.addWidget(input_box); input_layout.addWidget(add_button); layout.addWidget(list_widget); layout.addLayout(input_layout)
            self.keyword_tabs.addTab(widget, name); self.keyword_widgets[key] = {'list': list_widget, 'input': input_box}
        keyword_mgmt_layout.addWidget(self.keyword_tabs)
        
        left_splitter.addWidget(table_widget); left_splitter.addWidget(keyword_mgmt_widget); left_splitter.setSizes([700, 300])

        right_widget = QWidget(); right_layout = QVBoxLayout(right_widget)
        report_label = QLabel("AIサマリー"); report_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        self.report_area = QTextEdit(); self.report_area.setReadOnly(True); right_layout.addWidget(report_label); right_layout.addWidget(self.report_area)
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal); main_splitter.addWidget(left_splitter); main_splitter.addWidget(right_widget)
        main_splitter.setSizes([800, 400]); main_layout.addWidget(main_splitter)
        self.scan_button.clicked.connect(self.start_scan); self.refresh_button.clicked.connect(self.load_detected_leaks)

    def load_detected_leaks(self):
        self.status_label.setText("情報を読込・分析中...")
        should_sort = self.relevance_filter_checkbox.isChecked()
        all_leaks = self.sns_manager.get_all_leaks_unified(sort_by_relevance=should_sort)
        threshold = self.threshold_slider.value() if should_sort else -1
        filtered_leaks = [l for l in all_leaks if l.get('relevance_score', 0) >= threshold]
        self.leaks_model.removeRows(0, self.leaks_model.rowCount())
        for leak in filtered_leaks:
            status_item = QStandardItem(self.get_display_status(leak)); self.set_status_item_color(status_item, self.get_display_status(leak))
            relevance_item = QStandardItem(f"{leak.get('relevance_score', 0)}%"); self.set_relevance_item_color(relevance_item, leak.get('relevance_score', 0))
            display_source, location_text = self.get_source_and_location(leak)
            items = [QStandardItem(self.format_timestamp(leak.get('timestamp'))), relevance_item, QStandardItem(display_source), status_item, QStandardItem(f"{leak.get('confidence', 0):.0%}" if leak.get('confidence') is not None else "-"), QStandardItem(leak.get('keyword', 'N/A')), QStandardItem(location_text)]
            items[0].setData(leak, Qt.ItemDataRole.UserRole); self.leaks_model.appendRow(items)
        self.status_label.setText(f"待機中 ({len(filtered_leaks)}/{len(all_leaks)}件表示)")
    
    def get_source_and_location(self, leak):
        source_prefix = leak['id'].split('-', 1)[0]
        source_map = {'gh': 'GitHub', 'x': 'X', 'dsc': 'Discord', 'pst': 'Pastebin'}
        display_source = source_map.get(source_prefix, '不明')
        
        if source_prefix == 'gh': location = leak.get('repository', 'N/A')
        elif source_prefix == 'x': location = f"@{leak.get('author', 'N/A')}"
        elif source_prefix == 'dsc': location = f"{leak.get('server', 'N/A')} / #{leak.get('channel', 'N/A')}"
        elif source_prefix == 'pst': location = leak.get('title', 'No Title')
        else: location = 'N/A'
        
        return display_source, location

    def on_row_selected(self, index):
        if not index.isValid(): return
        leak_data = self.leaks_model.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        self.display_ai_report(leak_data)
        
        # ★★★ 修正箇所 ★★★
        # ステータスが'NEW'の場合、シングルクリックで分析を開始する
        if leak_data and leak_data.get('status') == 'NEW':
            self.start_single_ai_analysis(leak_data)

    def get_display_status(self, leak):
        status, risk = leak.get('status'), leak.get('risk_level')
        return {'NEW': '未分析', 'PENDING': '分析中...'}.get(status, risk or '不明') # 表示を分かりやすく変更

    def set_status_item_color(self, item, status_text):
        colors = {"LOW":"#2ecc71", "MEDIUM":"#f1c40f", "HIGH":"#e67e22", "CRITICAL":"#e74c3c", "SAFE":"#3498db", "不明":"#95a5a6", "未分析": "#bdc3c7"}
        if status_text in colors: item.setBackground(QColor(colors[status_text]))
        if status_text in ["CRITICAL", "HIGH"]: item.setForeground(QColor("white"))
    
    def set_relevance_item_color(self, item, score):
        if score > 70: item.setBackground(QColor("#e74c3c")); item.setForeground(QColor("white"))
        elif score > 40: item.setBackground(QColor("#f1c40f"))
    
    def format_timestamp(self, ts_str):
        if not ts_str: return "N/A"
        try: return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
        except: return str(ts_str).split(' ')[0]

    def update_threshold_label(self, value): self.threshold_label.setText(f"関連度 {value}% 以上")
    
    def load_keywords_to_ui(self):
        keywords_map = self.sns_manager.get_keywords()
        for source, keywords in keywords_map.items():
            if source in self.keyword_widgets: self.keyword_widgets[source]['list'].clear(); self.keyword_widgets[source]['list'].addItems(keywords)
    
    def save_keywords_from_ui(self):
        keywords_map = {};
        for source, widgets in self.keyword_widgets.items(): keywords_map[source] = [widgets['list'].item(i).text() for i in range(widgets['list'].count())]
        self.sns_manager.save_keywords(keywords_map)
    
    def add_keyword(self, source, input_widget):
        keyword = input_widget.text().strip()
        if keyword:
            list_widget = self.keyword_widgets[source]['list']
            if not list_widget.findItems(keyword, Qt.MatchFlag.MatchExactly): list_widget.addItem(keyword); self.save_keywords_from_ui()
            input_widget.clear()
    
    def remove_keyword(self, source, item):
        list_widget = self.keyword_widgets[source]['list']; list_widget.takeItem(list_widget.row(item)); self.save_keywords_from_ui()
    
    def start_scan(self):
        if (hasattr(self, 'scan_thread') and self.scan_thread.isRunning()) or self.cooldown_seconds > 0: return
        keywords_map = self.sns_manager.get_keywords()
        if not any(keywords_map.values()): QMessageBox.warning(self, "スキャン中止", "監視キーワードが1つも設定されていません。"); return
        self.scan_button.setEnabled(False); self.status_label.setText("自律的インテリジェンス分析を開始...")
        self.scan_thread = ScanWorker(self.sns_manager, keywords_map); self.scan_thread.finished.connect(self.on_scan_finished); self.scan_thread.start()
    
    def on_scan_finished(self):
        self.status_label.setText("分析サイクル完了。"); QMessageBox.information(self, "サイクル完了", "今回の分析サイクルが完了しました。"); self.load_detected_leaks(); self.start_cooldown(60)
    
    def start_cooldown(self, seconds): self.cooldown_seconds = seconds; self.scan_button.setEnabled(False); self.update_cooldown(); self.cooldown_timer.start(1000)
    
    def update_cooldown(self):
        if self.cooldown_seconds > 0: self.scan_button.setText(f"待機中 ({self.cooldown_seconds}秒)"); self.cooldown_seconds -= 1
        else: self.cooldown_timer.stop(); self.scan_button.setText("分析サイクル開始"); self.scan_button.setEnabled(True); self.status_label.setText("待機中")
    
    def on_row_double_clicked(self, index):
        if not index.isValid(): return
        leak_data = self.leaks_model.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        if not leak_data: return
        
        # URLをブラウザで開く
        if leak_data.get('url'):
            QDesktopServices.openUrl(QUrl(leak_data['url']))
        
        # 再分析のロジック
        if leak_data.get('status') == 'ANALYZED':
            reply = QMessageBox.question(self, '再分析の確認', f"ID: {leak_data['id']} を再分析しますか？", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes: self.start_single_ai_analysis(leak_data)

    def start_single_ai_analysis(self, leak_data):
        unified_id = leak_data['id']
        self.db_manager.update_leak_status(unified_id, 'PENDING')
        self.load_detected_leaks() # テーブルの表示を「分析中...」に更新
        self.report_area.setHtml(f"<h3>AIサマリー生成中...</h3><p>ID: {unified_id} を分析しています。</p>")
        worker = AiAnalysisWorker(leak_data, self.ai_model_name)
        self.ai_workers[unified_id] = worker
        worker.result_ready.connect(self.on_ai_analysis_finished)
        worker.finished.connect(lambda lid=unified_id: self.ai_workers.pop(lid, None))
        worker.start()
    
    def on_ai_analysis_finished(self, unified_id, analysis_result):
        self.db_manager.update_leak_with_ai_analysis(unified_id, analysis_result)
        current_selected_id = None
        current_index = self.leaks_table.currentIndex()
        if current_index.isValid():
            selected_item = self.leaks_model.item(current_index.row(), 0)
            if selected_item and selected_item.data(Qt.ItemDataRole.UserRole):
                current_selected_id = selected_item.data(Qt.ItemDataRole.UserRole).get('id')

        self.load_detected_leaks()
        
        if unified_id == current_selected_id:
            for row in range(self.leaks_model.rowCount()):
                item = self.leaks_model.item(row, 0)
                if item and item.data(Qt.ItemDataRole.UserRole) and item.data(Qt.ItemDataRole.UserRole).get('id') == unified_id:
                    self.display_ai_report(item.data(Qt.ItemDataRole.UserRole))
                    # 再選択してハイライトを維持
                    self.leaks_table.selectRow(row)
                    break

    def display_ai_report(self, leak_data):
        if not leak_data:
            self.report_area.clear()
            return
        status = leak_data.get('status')
        # ★★★ 修正箇所 ★★★
        # 'NEW'や'PENDING'の時のメッセージを調整
        if status == 'NEW': 
            self.report_area.setHtml(f"<h3>分析開始...</h3><p>ID: {leak_data['id']} の分析を開始します。</p>")
            return
        if status == 'PENDING': 
            self.report_area.setHtml(f"<h3>分析中...</h3><p>ID: {leak_data['id']} を分析中です。</p>")
            return
        
        report_content = leak_data.get('ai_report', {}); report_data = report_content.get('report_data', {})
        if 'error_report' in report_data:
            html = f"<h3><font color='#e74c3c'>分析エラー</font></h3><hr><p>{report_data['error_report'].replace('\n', '<br>')}</p>"
        else:
            reasons_html = ""
            if leak_data.get('relevance_reasons'):
                reasons = "<li>" + "</li><li>".join(leak_data['relevance_reasons']) + "</li>"
                reasons_html = f"<p><b>関連度が高い理由:</b><ul>{reasons}</ul></p>"
            html = f"""<h3>AIサマリー (ID: {leak_data['id']})</h3><hr>{reasons_html}
                <p><b>概要:</b><br>{report_data.get('repository_summary', 'N/A').replace('\n', '<br>')}</p>
                <p><b>脅威の分析:</b><br>{report_data.get('threat_summary', 'N/A').replace('\n', '<br>')}</p>
                <p><b><font color='#e67e22'>直接的な害:</font></b><br>{report_data.get('direct_harm', 'N/A').replace('\n', '<br>')}</p>
                <p><b><font color='#f1c40f'>将来的なリスク:</font></b><br>{report_data.get('future_harm', 'N/A').replace('\n', '<br>')}</p>"""
        self.report_area.setHtml(html)

    def shutdown(self):
        self.save_keywords_from_ui()
