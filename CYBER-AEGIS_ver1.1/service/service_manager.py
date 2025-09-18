# service/service_manager.py (修正版)
import time
import threading
import os
import sys
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager # 自動ダウンロードのためにインポート

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.config_manager import ConfigManager
from src.database.db_manager import DBManager
from src.collectors.nicterweb_collector import NicterwebCollector
from service.workers.log_monitor import LogMonitorWorker
from service.workers.event_log_collector import EventLogCollector

class ServiceManager:
    def __init__(self):
        self.config = ConfigManager()
        self.db_manager = DBManager()
        self.running = False
        self.threads = []
        self.nicter_download_dir = os.path.abspath(os.path.join('cache', 'nicter_downloads'))
        self.driver = self._init_webdriver()
        self.log_monitor_worker = None
        self.event_log_collector = None

    def _init_webdriver(self):
        try:
            print("[ServiceManager] Initializing Chrome WebDriver...")
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920x1080")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            
            prefs = {
                "download.default_directory": self.nicter_download_dir,
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "safebrowsing.enabled": True
            }
            options.add_experimental_option("prefs", prefs)
            
            # ▼▼▼【重要修正点】▼▼▼
            # chromedriver.exe を自動でダウンロード・管理するように変更
            service = ChromeService(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            print("[ServiceManager] Chrome WebDriver initialized successfully.")
            return driver
        except Exception as e:
            print(f"[ServiceManager] Error initializing WebDriver: {e}")
            return None

    def start(self):
        self.running = True
        
        # NicterコレクターはWebDriverが正常な場合のみ起動
        if self.driver:
            nicter_thread = threading.Thread(target=self.run_nicter_collector, daemon=True, name="NicterCollector")
            self.threads.append(nicter_thread)
        else:
            print("[ServiceManager] WebDriver initialization failed. Nicter Collector will not start.")

        log_monitor_enabled = self.config.get('log_monitoring', 'enabled', fallback='true').lower() == 'true'
        if log_monitor_enabled:
            print("[ServiceManager] Log Monitoring service is enabled.")
            log_file = self.config.get('log_monitoring', 'log_file', fallback='logs/security_events.log')
            sigma_rules_path = 'rules/sigma'
            
            self.log_monitor_worker = LogMonitorWorker(log_file, sigma_rules_path)
            log_thread = threading.Thread(target=self.log_monitor_worker.start, daemon=True, name="LogMonitor")
            self.threads.append(log_thread)

            # --- ▼▼▼【重要】SIGMA機能の最終テストを確実に行うため、以下の2行を一時的に無効化しています ▼▼▼ ---
            # --- テスト完了後、このコメントアウト(#)を外すことで、リアルタイム自動監視が有効になります ---
            self.event_log_collector = EventLogCollector()
            collector_thread = threading.Thread(target=self.event_log_collector.start, daemon=True, name="EventLogCollector")
            self.threads.append(collector_thread)
            # --- ▲▲▲ ここまで ▲▲▲ ---

        else:
            print("[ServiceManager] Log Monitoring service is disabled.")
        
        for thread in self.threads:
            thread.start()
            
        print("[ServiceManager] All services started.")

    def stop(self):
        print("[ServiceManager] Stopping all services...")
        self.running = False

        if self.log_monitor_worker:
            self.log_monitor_worker.running = False
        if self.event_log_collector:
            self.event_log_collector.running = False
        
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        if self.driver:
            self.driver.quit()
            print("[ServiceManager] Chrome WebDriver stopped.")
            
        print("[ServiceManager] All services stopped.")

    def run_nicter_collector(self):
        if not self.driver: return
        collector = NicterwebCollector(download_dir=self.nicter_download_dir)
        while self.running:
            print("\n" + "="*30)
            print("[Nicter Collector] Starting scheduled run...")
            collector.fetch_threat_feed(self.driver)
            print("[Nicter Collector] Run finished.")
            print("="*30 + "\n")
            
            interval = collector.cache_duration_seconds
            print(f"[Nicter Collector] Waiting for {interval} seconds until next run...")
            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)