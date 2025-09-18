# CYBER-AEGIS/src/data_integrators/file_monitor.py
import os
import time
import queue
from PyQt6.QtCore import QThread, pyqtSignal
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
from src.utils.config_manager import ConfigManager
from src.utils.app_logger import Logger
from src.threat_intel.yara_scanner import YaraScanner

class ScanWorker(QThread):
    scan_complete = pyqtSignal(dict)

    def __init__(self, yara_scanner):
        super().__init__()
        self.yara_scanner = yara_scanner
        self.queue = queue.Queue()
        self.logger = Logger()
        self._is_running = True

    def run(self):
        while self._is_running:
            try:
                event_data = self.queue.get(timeout=1)
                time.sleep(3)
                path = event_data['path']
                self.logger.info(f"ScanWorker is now scanning: {path}")
                yara_matches = []
                if self.yara_scanner:
                    matches = self.yara_scanner.scan_file(path)
                    if matches:
                        for match in matches:
                            yara_matches.append({
                                'rule': match.rule, 'meta': match.meta, 'tags': match.tags
                            })
                event_data['yara_matches'] = yara_matches
                self.scan_complete.emit(event_data)
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in ScanWorker: {e}")

    def add_to_scan_queue(self, event_data):
        self.queue.put(event_data)

    def stop(self):
        self._is_running = False

class FileChangeEventHandler(FileSystemEventHandler):
    def __init__(self, scan_worker, exclusions, monitored_paths):
        super().__init__()
        self.scan_worker = scan_worker
        self.exclusions = exclusions
        self.monitored_paths = [os.path.normpath(p) for p in monitored_paths]
        self.ignore_patterns = ['appdata', 'application data', '__pycache__', '$recycle.bin', '.tmp']
        self.ignore_filenames = ['aegis.db', 'aegis.db-journal', 'cyber_aegis.log']

    def process_event(self, event_type, path):
        if not path or os.path.isdir(path):
            return

        # --- ここからが最後の修正点です ---
        # OSのパス区切り文字（\または/）に依存しないように正規化
        normalized_path = os.path.normpath(path).lower()
        # 'quarantine' フォルダ内のイベントを完全に無視する
        if os.sep + 'quarantine' + os.sep in normalized_path:
            return
        # --- ここまで ---

        if os.path.basename(path) in self.ignore_filenames:
            return

        path_lower = path.lower()
        if any(pattern in path_lower for pattern in self.ignore_patterns): return
        if any(ex_dir.lower() in path_lower for ex_dir in self.exclusions.get('directories', [])): return
        if any(path_lower.endswith(ex_ext.lower()) for ex_ext in self.exclusions.get('extensions', [])): return

        self.scan_worker.add_to_scan_queue({"event_type": event_type, "path": path})

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("作成", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("変更", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event("移動/名前変更", event.dest_path)

class MonitorThread(QThread):
    file_event_detected = pyqtSignal(dict)
    
    def __init__(self, paths_to_watch):
        super().__init__()
        self.paths_to_watch = paths_to_watch
        self.observer = PollingObserver()
        self.config_manager = ConfigManager()
        self.logger = Logger()
        self._is_running = True
        self.yara_scanner = None
        self.scan_worker = None

    def initialize_yara_scanner(self):
        try:
            rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'rules', 'yara'))
            if not os.path.exists(rules_path):
                self.logger.warning(f"YARA rules directory not found. Disabling YARA scan.")
                return False
            self.yara_scanner = YaraScanner(rules_path=rules_path)
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize YaraScanner: {e}")
            return False

    def run(self):
        if self.initialize_yara_scanner():
            self.scan_worker = ScanWorker(self.yara_scanner)
            self.scan_worker.scan_complete.connect(self.file_event_detected)
            self.scan_worker.start()

        exclusions = {
            'directories': self.config_manager.get_list('FileMonitorExclusions', 'directories'),
            'extensions': self.config_manager.get_list('FileMonitorExclusions', 'extensions'),
        }
        
        event_handler = FileChangeEventHandler(self.scan_worker, exclusions, self.paths_to_watch)
        
        for path in self.paths_to_watch:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=True)
        
        if not self.observer.emitters:
            self.logger.warning("No valid directories to monitor were found.")
            return

        self.observer.start()
        while self._is_running:
            time.sleep(1)
        
        self.observer.stop()
        self.observer.join()
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()

    def stop(self):
        self._is_running = False