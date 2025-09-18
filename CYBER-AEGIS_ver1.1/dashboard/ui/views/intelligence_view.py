import os
import json
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, 
                             QPushButton, QTableView, QHeaderView, QAbstractItemView, 
                             QTabWidget, QGroupBox, QMessageBox, QLineEdit)
from PyQt6.QtCore import QTimer, QThread, pyqtSignal, Qt
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor
from selenium import webdriver
from selenium.webdriver.chrome.service import Service

# あなたが作成した全てのコレクターと、新しい部品をインポート
from src.collectors.nicterweb_collector import NicterwebCollector 
from src.collectors.cisa_kev_collector import CisaKevCollector
from src.threat_intel.orion_investigator import OrionInvestigator
from src.core_ai.ollama_manager import OllamaManager

class AnalysisWorker(QThread):
    # ... (このクラスは変更ありません。既存のコードのまま)
    nicter_finished = pyqtSignal(dict)
    cisa_finished = pyqtSignal(dict)
    orion_finished = pyqtSignal(dict)
    ai_summary_finished = pyqtSignal(str)

    def __init__(self, analyzer, driver=None, orion_target=None, orion_password=None, summary_data=None):
        super().__init__()
        self.analyzer = analyzer
        self.driver = driver
        self.orion_target = orion_target
        self.orion_password = orion_password
        self.summary_data = summary_data

    def run(self):
        if isinstance(self.analyzer, NicterwebCollector):
            results = self.analyzer.fetch_threat_feed(self.driver)
            self.nicter_finished.emit(results)
        elif isinstance(self.analyzer, CisaKevCollector):
            results = self.analyzer.fetch_threat_feed()
            self.cisa_finished.emit(results)
        elif isinstance(self.analyzer, OrionInvestigator):
            results = {}
            if self.orion_target:
                target = self.orion_target.split(':')[0]
                is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
                is_domain = '.' in target and not is_ip

                if is_domain:
                    results['whois'] = self.analyzer.get_whois_info(target)
                elif is_ip:
                    results['dnsbl'] = self.analyzer.check_dnsbl(target)
                    if self.driver:
                        results['talos'] = self.analyzer.check_talos(self.driver, target)
                    else:
                        results['talos'] = {"error": "WebDriverが利用できませんでした。"}
                    results['whois'] = {"info": "ターゲットはIPアドレスのため、WHOIS調査はスキップしました。"}
                else:
                    results['whois'] = {"info": "ターゲットがドメイン形式ではないため、WHOIS調査をスキップしました。"}
                    results['dnsbl'] = {"info": "ターゲットがIPアドレス形式ではないため、DNSBL調査をスキップしました。"}
                
                url = self.orion_target
                if not url.startswith(('http://', 'https://')): url = 'http://' + url
                results['google_safeBrowse'] = self.analyzer.check_google_safeBrowse(url)

            elif self.orion_password:
                results['hibp_password'] = self.analyzer.check_pwned_password(self.orion_password)
            self.orion_finished.emit(results)
        elif isinstance(self.analyzer, OllamaManager) and self.summary_data:
            # ... (AI要約部分は変更ありません)
            final_report = "<h3>分析エラー</h3><p>AIによるレポート生成中に予期せぬエラーが発生しました。</p>"
            try:
                # --- ステージ1: 事実の構造化抽出 ---
                system_prompt_1 = "You are a data extraction specialist. Your task is to extract specific information from the provided JSON data and format it into a new, clean JSON object. Do not add any interpretation or text outside of the JSON structure."
                prompt_1 = f"""
                Extract the following key facts from the NICTER observation data below and provide the output ONLY in JSON format.
                - top_3_countries_by_host: The top 3 countries by host count.
                - top_3_countries_by_packet: The top 3 countries by packet count.
                - top_3_ports_by_host: The top 3 ports by host count.
                - total_unique_hosts: The total number of unique hosts observed.

                # Observation Data:
                {json.dumps(self.summary_data, ensure_ascii=False, indent=2)}

                # Output JSON format:
                {{
                  "top_3_countries_by_host": [{{ "country": "...", "count": ... }}, ...],
                  "top_3_countries_by_packet": [{{ "country": "...", "count": ... }}, ...],
                  "top_3_ports_by_host": [{{ "port_info": "...", "count": ... }}, ...],
                  "total_unique_hosts": ...
                }}
                """
                key_facts_json_str = self.analyzer.generate_response(prompt_1, system_prompt_1)
                
                if "```json" in key_facts_json_str: key_facts_json_str = key_facts_json_str.split("```json", 1)[-1]
                if "```" in key_facts_json_str: key_facts_json_str = key_facts_json_str.rsplit("```", 1)[0]
                key_facts = json.loads(key_facts_json_str.strip())
                print(f"[AI Stage 1] Structured Facts Extracted:\n{json.dumps(key_facts, ensure_ascii=False, indent=2)}")

                # --- ステージ2: 脅威の分析と考察 ---
                system_prompt_2 = "あなたは、日本のサイバーセキュリティ脅威インテリジェンスの専門家です。与えられた構造化データを基に、日本の一般PCユーザーにとっての潜在的な脅威を分析し、その考察を簡潔な文章で記述してください。"
                prompt_2 = f"""
                以下の構造化された事実リストを分析し、日本のユーザーに対する具体的な脅威とその背景にある可能性を考察してください。特に、なぜ特定のポートが狙われるのか、その意味を専門家として解説してください。

                # 事実リスト (JSON):
                {json.dumps(key_facts, ensure_ascii=False, indent=2)}
                """
                analysis = self.analyzer.generate_response(prompt_2, system_prompt_2)
                print(f"[AI Stage 2] Threat Analysis:\n{analysis}")

                # --- ステージ3: レポートの清書 ---
                system_prompt_3 = "あなたは、プロのレポート作成者です。与えられた専門的な分析内容を、指示されたHTMLテンプレートに沿って、非専門家にも分かりやすい、簡潔で洗練されたレポートにまとめてください。"
                prompt_3 = f"""
                以下の「脅威分析の要点」を読み、指定された「HTMLレポートテンプレート」の対応する箇所に、自然な日本語で埋め込んで、完全なHTMLレポートを生成してください。

                # 脅威分析の要点:
                {analysis}

                # HTMLレポートテンプレート:
                <div>
                    <h3>本日のサイバー脅威レポート</h3>
                    <p></p>
                    <h3>日本への具体的な脅威</h3>
                    <p></p>
                    <h3>推奨される対策</h3>
                    <ul>
                        <li></li>
                        <li>不審なメールや添付ファイルは絶対に開かないでください。</li>
                        <li>ファイアウォール設定を確認し、不要なポートが外部に公開されていないか確認してください。</li>
                    </ul>
                </div>
                """
                final_report = self.analyzer.generate_response(prompt_3, system_prompt_3)
                if "```html" in final_report: final_report = final_report.split("```html",1)[-1]
                if "```" in final_report: final_report = final_report.rsplit("```",1)[0]

            except Exception as e:
                print(f"[AI Summary] An error occurred during the 3-stage summary generation: {e}")
            self.ai_summary_finished.emit(final_report.strip())


class IntelligenceView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.nicter_collector = NicterwebCollector()
        self.cisa_collector = CisaKevCollector()
        self.orion_investigator = OrionInvestigator()
        self.ai_manager = OllamaManager()
        self.worker = None
        
        # ▼▼▼ 変更点 ▼▼▼
        # WebDriverの初期化と状態を診断メッセージで追跡します
        self.driver = self._init_selenium_driver()
        print(f"--- [診断] IntelligenceView初期化直後、self.driverの状態: {'正常に初期化済み' if self.driver else '失敗(None)'} ---")
        # ▲▲▲ 変更点 ▲▲▲
        
        self.init_ui()

        self.nicter_timer = QTimer(self); self.nicter_timer.timeout.connect(self.load_nicter_data); self.nicter_timer.start(30 * 60 * 1000)
        self.cisa_timer = QTimer(self); self.cisa_timer.timeout.connect(self.load_cisa_data); self.cisa_timer.start(12 * 60 * 60 * 1000)
        QTimer.singleShot(1000, self.load_nicter_data)
        QTimer.singleShot(2000, self.load_cisa_data)

    def _init_selenium_driver(self):
        # ▼▼▼ 変更点 ▼▼▼
        # 初期化プロセスの詳細をコンソールに出力します
        print("--- [診断] WebDriverの初期化処理を開始します... ---")
        # ▲▲▲ 変更点 ▲▲▲
        try:
            options = webdriver.ChromeOptions()
            download_dir = os.path.abspath(os.path.join('cache', 'nicter_downloads'))
            os.makedirs(download_dir, exist_ok=True)
            prefs = {"download.default_directory": download_dir, "download.prompt_for_download": False}
            options.add_experimental_option("prefs", prefs)
            options.add_argument('--headless'); options.add_argument('--disable-gpu'); options.add_argument('--window-size=1920,1080')
            options.add_experimental_option('excludeSwitches', ['enable-logging'])
            service = Service(executable_path='chromedriver.exe')
            driver = webdriver.Chrome(service=service, options=options)
            # ▼▼▼ 変更点 ▼▼▼
            print("--- [診断] WebDriverの初期化に成功しました。 ---")
            # ▲▲▲ 変更点 ▲▲▲
            return driver
        except Exception as e:
            # ▼▼▼ 変更点 ▼▼▼
            print(f"--- [診断] WebDriverの初期化中に致命的なエラーが発生しました: {e} ---")
            # ▲▲▲ 変更点 ▲▲▲
            QMessageBox.critical(self, "ブラウザ起動エラー", f"バックグラウンドブラウザの起動に失敗しました。\nchromedriver.exeがプロジェクトのルートにありますか？\n\nエラー: {e}")
            return None

    def init_ui(self):
        # ... (このメソッドは変更ありません)
        main_layout = QVBoxLayout(self)
        title_label = QLabel("統合脅威インテリジェンス・センター"); title_label.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 10px;")
        
        self.tabs = QTabWidget()
        
        # --- NICTER Tab ---
        nicter_widget = QWidget(); nicter_main_layout = QHBoxLayout(nicter_widget)
        nicter_left_widget = QWidget(); nicter_left_layout = QVBoxLayout(nicter_left_widget)
        summary_label = QLabel("AIによる脅威サマリー"); summary_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        self.summary_area = QTextEdit(); self.summary_area.setReadOnly(True); self.summary_area.setPlaceholderText("データを取得・分析中です...")
        nicter_left_layout.addWidget(summary_label); nicter_left_layout.addWidget(self.summary_area)
        nicter_right_container = QWidget(); nicter_right_layout = QVBoxLayout(nicter_right_container)
        nicter_right_container.setFixedWidth(450)
        ranking_label = QLabel("Top 5 ランキング"); ranking_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        country_host_label = QLabel("攻撃元 国別 (ホスト数)"); self.country_host_table, self.country_host_model = self.create_ranking_table()
        country_packet_label = QLabel("攻撃元 国別 (パケット数)"); country_packet_label.setStyleSheet("margin-top: 15px;"); self.country_packet_table, self.country_packet_model = self.create_ranking_table()
        port_host_label = QLabel("標的ポート別 (ホスト数)"); port_host_label.setStyleSheet("margin-top: 15px;"); self.port_host_table, self.port_host_model = self.create_ranking_table()
        self.refresh_nicter_button = QPushButton("NICTER情報を手動更新")
        nicter_right_layout.addWidget(ranking_label); nicter_right_layout.addWidget(country_host_label); nicter_right_layout.addWidget(self.country_host_table)
        nicter_right_layout.addWidget(country_packet_label); nicter_right_layout.addWidget(self.country_packet_table)
        nicter_right_layout.addWidget(port_host_label); nicter_right_layout.addWidget(self.port_host_table)
        nicter_right_layout.addStretch(); nicter_right_layout.addWidget(self.refresh_nicter_button)
        nicter_main_layout.addWidget(nicter_left_widget, 1); nicter_main_layout.addWidget(nicter_right_container, 0)
        
        # --- CISA KEV Tab ---
        cisa_widget = QWidget(); cisa_layout = QVBoxLayout(cisa_widget)
        self.cisa_table = QTableView(); self.cisa_table.setSortingEnabled(True)
        self.cisa_model = QStandardItemModel(); self.cisa_model.setHorizontalHeaderLabels(["脆弱性ID(CVE)", "製品", "脆弱性の名称", "追加日"])
        self.cisa_table.setModel(self.cisa_model)
        cisa_header = self.cisa_table.horizontalHeader(); cisa_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); cisa_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.refresh_cisa_button = QPushButton("CISA脆弱性カタログを更新")
        cisa_layout.addWidget(self.cisa_table); cisa_layout.addWidget(self.refresh_cisa_button)

        # --- Orion Tab ---
        orion_widget = QWidget(); orion_layout = QVBoxLayout(orion_widget)
        ip_domain_group = QGroupBox("IP / ドメイン / URL 調査"); ip_domain_layout = QHBoxLayout(ip_domain_group)
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("調査したいIP、ドメイン、URLを入力...")
        self.investigate_button = QPushButton("調査"); ip_domain_layout.addWidget(self.target_input); ip_domain_layout.addWidget(self.investigate_button)
        orion_layout.addWidget(ip_domain_group)

        password_group = QGroupBox("漏洩パスワード調査 (Pwned Passwords)"); pw_layout = QHBoxLayout(password_group)
        self.password_input = QLineEdit(); self.password_input.setPlaceholderText("漏洩を確認したいパスワードやAPIキーを入力...")
        self.check_password_button = QPushButton("漏洩チェック")
        pw_layout.addWidget(self.password_input); pw_layout.addWidget(self.check_password_button)
        orion_layout.addWidget(password_group)

        self.results_area = QTextEdit(); self.results_area.setReadOnly(True); self.results_area.setFontFamily("Consolas, Courier New")
        orion_layout.addWidget(self.results_area)
        
        self.tabs.addTab(nicter_widget, "グローバル攻撃トレンド (NICTER)")
        self.tabs.addTab(cisa_widget, "悪用が確認された脆弱性 (CISA KEV)")
        self.tabs.addTab(orion_widget, "オンデマンド脅威分析 (Orion)")
        
        main_layout.addWidget(title_label); main_layout.addWidget(self.tabs)

        self.refresh_nicter_button.clicked.connect(self.load_nicter_data)
        self.refresh_cisa_button.clicked.connect(self.load_cisa_data)
        self.investigate_button.clicked.connect(self.start_ip_domain_investigation)
        self.target_input.returnPressed.connect(self.start_ip_domain_investigation)
        self.check_password_button.clicked.connect(self.start_password_investigation)
        
    # ... (create_ranking_table, load_nicter_data, process_nicter_data, etc. は変更ありません)

    def start_ip_domain_investigation(self):
        if self.worker and self.worker.isRunning(): return
        target = self.target_input.text().strip()
        if not target: QMessageBox.warning(self, "入力エラー", "調査対象を入力してください。"); return
        
        # ▼▼▼ 変更点 ▼▼▼
        # 調査開始直前のWebDriverの状態をコンソールに出力します
        print(f"--- [診断] Orion調査開始直前、self.driverの状態: {'渡せる状態(正常)' if self.driver else '渡せない状態(None)'} ---")
        if not self.driver:
            print("--- [診断] self.driverがNoneのため、Talos調査は失敗します。アプリ起動時のログを確認してください。 ---")
        # ▲▲▲ 変更点 ▲▲▲

        self.disable_orion_buttons()
        self.results_area.setText(f"'{target}' の各種情報を調査しています...")
        self.worker = AnalysisWorker(self.orion_investigator, driver=self.driver, orion_target=target)
        self.worker.orion_finished.connect(self.display_orion_report)
        self.worker.start()

    # ... (start_password_investigation, display_orion_report, shutdown など、残りのメソッドは変更ありません)
    def create_ranking_table(self):
        table = QTableView(); table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        model = QStandardItemModel(); model.setHorizontalHeaderLabels(["項目", "観測数", "%"])
        table.setModel(model)
        header = table.horizontalHeader(); header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents); header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        return table, model

    def load_nicter_data(self):
        if self.worker and self.worker.isRunning(): return
        if not self.driver: QMessageBox.warning(self, "ブラウザ未起動", "バックグラウンドブラウザが起動していないため、NICTER情報を更新できません。"); return
        self.refresh_nicter_button.setText("更新中..."); self.refresh_nicter_button.setEnabled(False)
        self.summary_area.setPlaceholderText("NICTERから最新の脅威データを取得・分析しています...")
        self.worker = AnalysisWorker(self.nicter_collector, driver=self.driver)
        self.worker.nicter_finished.connect(self.process_nicter_data)
        self.worker.start()

    def process_nicter_data(self, result):
        self.refresh_nicter_button.setText("NICTER情報を手動更新"); self.refresh_nicter_button.setEnabled(True)
        if not result or result.get("status") != "success":
            self.summary_area.setHtml("<h3>分析エラー</h3><p>NICTERデータの取得に失敗しました。</p>")
            return

        data = result.get("data", [])
        countries_host = sorted([item for item in data if item['type'] == '国別ユニークホスト数'], key=lambda x: x.get('count', 0), reverse=True)
        countries_packet = sorted([item for item in data if item['type'] == '国別パケット数'], key=lambda x: x.get('count', 0), reverse=True)
        ports_host = sorted([item for item in data if item['type'] == 'TCPポート別ユニークホスト数'], key=lambda x: x.get('count', 0), reverse=True)
        
        self.update_ranking_table(self.country_host_model, countries_host[:5], sum(c.get('count', 0) for c in countries_host))
        self.update_ranking_table(self.country_packet_model, countries_packet[:5], sum(c.get('count', 0) for c in countries_packet))
        self.update_ranking_table(self.port_host_model, ports_host[:5], sum(p.get('count', 0) for p in ports_host))
        
        if not countries_host or not countries_packet or not ports_host:
                    self.summary_area.setHtml("<h3>分析データ不足</h3><p>AIサマリーを作成するための十分なデータがありませんでした。</p>")
                    return

        summary_data_for_ai = {
            "top_countries_host": [{"name": c['name'], "count": c.get('count', 0)} for c in countries_host[:3]],
            "top_countries_packet": [{"name": c['name'], "count": c.get('count', 0)} for c in countries_packet[:3]],
            "top_ports_host": [{"name": p['name'], "count": p.get('count', 0)} for p in ports_host[:3]],
            "total_host_count": sum(c.get('count', 0) for c in countries_host)
        }
        self.summary_area.setHtml("<h3>分析中...</h3><p>AIが最新の脅威状況を分析しています。</p>")
        self.worker = AnalysisWorker(self.ai_manager, summary_data=summary_data_for_ai)
        self.worker.ai_summary_finished.connect(self.summary_area.setHtml)
        self.worker.start()

    def update_ranking_table(self, model, top_data, total_count):
        model.removeRows(0, model.rowCount())
        if total_count == 0: return
        for item in top_data:
            name = item.get('name', 'N/A'); count = item.get('count', 0)
            percentage = (count / total_count) * 100 if total_count > 0 else 0
            row = [QStandardItem(str(name)), QStandardItem(str(count)), QStandardItem(f"{percentage:.1f}%")]
            model.appendRow(row)

    def load_cisa_data(self):
        if self.worker and self.worker.isRunning(): return
        self.refresh_cisa_button.setText("更新中..."); self.refresh_cisa_button.setEnabled(False)
        self.worker = AnalysisWorker(self.cisa_collector)
        self.worker.cisa_finished.connect(self.update_cisa_table)
        self.worker.start()

    def update_cisa_table(self, result):
        self.cisa_model.removeRows(0, self.cisa_model.rowCount())
        if result.get("status") == "success":
            for vuln in result.get("data", []):
                items = [QStandardItem(vuln.get("id")), QStandardItem(vuln.get("vendor")), QStandardItem(vuln.get("name")), QStandardItem(vuln.get("dateAdded"))]
                self.cisa_model.appendRow(items)
        self.cisa_table.sortByColumn(3, Qt.SortOrder.DescendingOrder)
        self.refresh_cisa_button.setText("CISA脆弱性カタログを更新"); self.refresh_cisa_button.setEnabled(True)
        print("[IntelligenceView] CISA KEV updated.")

    def start_password_investigation(self):
        if self.worker and self.worker.isRunning(): return
        password = self.password_input.text().strip()
        if not password: QMessageBox.warning(self, "入力エラー", "パスワードを入力してください。"); return
        self.disable_orion_buttons()
        self.results_area.setText(f"'{password}' の漏洩情報を問い合わせています...")
        self.worker = AnalysisWorker(self.orion_investigator, orion_password=password)
        self.worker.orion_finished.connect(self.display_orion_report)
        self.worker.start()

    def display_orion_report(self, results):
        self.enable_orion_buttons()
        report_text = ""

        if 'hibp_password' in results:
            pwned_count = results['hibp_password'].get('pwned_count', 0)
            if pwned_count > 0:
                report_text = f"--- 漏洩パスワード調査結果 ---\n\n警告: このパスワードは過去に {pwned_count:,} 回漏洩しています。\n直ちに使用を中止し、変更してください。"
            else:
                report_text = f"--- 漏洩パスワード調査結果 ---\n\n安全: このパスワードの漏洩は確認されませんでした。"
        else:
            target = self.target_input.text().strip()
            report_text = f"--- 調査結果：{target} ---\n\n"
            
            gsb = results.get('google_safeBrowse', {})
            report_text += "--- Google Safe Browse ---\n"
            if 'error' in gsb: report_text += f"  ステータス: 調査エラー\n  詳細: {gsb['error']}\n\n"
            else:
                gsb_status = gsb.get('判定', '不明')
                report_text += f"  ステータス: {gsb_status}\n"
                if gsb_status == '危険':
                    for match in gsb.get('詳細', []): report_text += f"  - 脅威タイプ: {match.get('threatType', 'N/A')}\n"
                else: report_text += f"  詳細: {gsb.get('詳細', 'N/A')}\n"
                report_text += "\n"

            if 'dnsbl' in results:
                dnsbl = results.get('dnsbl', {})
                report_text += "--- Spamhaus DNSBL ---\n"
                if 'error' in dnsbl: report_text += f"  ステータス: 調査エラー\n  詳細: {dnsbl['error']}\n\n"
                else:
                    dnsbl_status = dnsbl.get('status', '不明')
                    report_text += f"  総合ステータス: {dnsbl_status}\n"
                    if dnsbl_status == 'LISTED':
                        for zone, detail in dnsbl.get('details', {}).items():
                            if detail.get('listed'): report_text += f"  - {zone}: 掲載されています\n"
                    report_text += "\n"

            if 'talos' in results:
                talos = results.get('talos', {})
                report_text += "--- Cisco Talos Intelligence ---\n"
                if 'error' in talos:
                    report_text += f"  ステータス: 調査エラー\n  詳細: {talos['error']}\n\n"
                else:
                    report_text += f"  判定: {talos.get('判定', 'N/A')}\n"
                    report_text += f"  Webレピュテーション: {talos.get('Webレピュテーション', 'N/A')}\n"
                    report_text += f"  所有者: {talos.get('所有者', 'N/A')}\n\n"

            whois_res = results.get('whois', {})
            report_text += "--- WHOIS ---\n"
            if 'error' in whois_res: report_text += f"  ステータス: 調査エラー\n  詳細: {whois_res['error']}\n"
            elif 'info' in whois_res: report_text += f"  ステータス: {whois_res['info']}\n"
            else:
                for key, value in whois_res.items(): report_text += f"  {key}: {value}\n"
        
        self.results_area.setText(report_text)

    def disable_orion_buttons(self):
        self.investigate_button.setEnabled(False)
        self.check_password_button.setEnabled(False)

    def enable_orion_buttons(self):
        self.investigate_button.setEnabled(True)
        self.check_password_button.setEnabled(True)

    def shutdown(self):
        print("[IntelligenceView] Shutting down background resources...")
        if hasattr(self, 'nicter_timer') and self.nicter_timer.isActive(): self.nicter_timer.stop()
        if hasattr(self, 'cisa_timer') and self.cisa_timer.isActive(): self.cisa_timer.stop()
        if self.worker and self.worker.isRunning():
            self.worker.quit(); self.worker.wait(2000)
        if self.driver:
            try:
                self.driver.quit()
                print("[IntelligenceView] Background browser has been shut down.")
            except Exception as e:
                print(f"[IntelligenceView] Error shutting down browser: {e}")