import time
import os
import json
import sys
import logging
import datetime
import traceback

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.database.db_manager import get_session
from src.database.models import SigmaMatch
from src.threat_intel.sigma_analyzer import SigmaAnalyzer

logger = logging.getLogger(__name__)

# --- ▼▼▼【最終修正点】▼▼▼ ---
# json.dumpsが日付オブジェクトを文字列に変換できるようにするためのヘルパー関数
def json_serial_converter(o):
    """日付や時刻オブジェクトをISO形式の文字列に変換します。"""
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    # それ以外の変換できない型があった場合にエラーを出す
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")
# --- ▲▲▲ 修正はここまで ▲▲▲ ---

class LogMonitorWorker:
    def __init__(self, log_file_path, sigma_rule_path):
        if not os.path.dirname(log_file_path):
            log_file_path = os.path.join('logs', log_file_path)

        self.log_file_path = os.path.join(project_root, log_file_path)
        self.sigma_rule_path = os.path.join(project_root, sigma_rule_path)
        
        self.session = get_session()
        self.analyzer = SigmaAnalyzer(rule_dirs=[self.sigma_rule_path])
        self.running = False
        print(f"Log Monitor Worker initialized for: {self.log_file_path}")
        print(f"Loaded {len(self.analyzer.rules)} SIGMA rules.")

    def start(self):
        self.running = True
        print("Log Monitor Worker started. Now polling for file changes...")
        
        last_position = 0
        if os.path.exists(self.log_file_path):
             with open(self.log_file_path, 'r', encoding='utf-8') as f:
                f.seek(0, 2)
                last_position = f.tell()

        while self.running:
            try:
                if not os.path.exists(self.log_file_path):
                    print(f"Log file not found at {self.log_file_path}. Waiting for it to be created.")
                    time.sleep(2)
                    continue

                with open(self.log_file_path, 'r', encoding='utf-8') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    if new_lines:
                         last_position = f.tell()
                
                if new_lines:
                    for line in new_lines:
                        self.process_line(line)
                
                time.sleep(1) 
            except Exception as e:
                print(f"Error in LogMonitorWorker loop: {e}")
                logger.error(f"Error in LogMonitorWorker loop: {e}", exc_info=True)
                time.sleep(5)
    
    def process_line(self, line):
        line = line.strip()
        if not line:
            return

        try:
            log_entry = json.loads(line)
        except json.JSONDecodeError:
            print(f"Skipping non-JSON line: {line[:100]}")
            return
        
        matches = self.analyzer.analyze_log_entry(log_entry)
        if matches:
            print(f"[{datetime.datetime.now()}] MATCH FOUND: {len(matches)} matches in log entry.")
            
            # --- ▼▼▼【最終修正点】▼▼▼ ---
            # json.dumps に default=json_serial_converter を追加
            with open("debug_matches.log", "a", encoding="utf-8") as f:
                f.write(f"[{datetime.datetime.now()}] MATCH FOUND: {json.dumps(matches, ensure_ascii=False, default=json_serial_converter)}\n")

            for match in matches:
                try:
                    new_match = SigmaMatch(
                        rule_title=match.get('title', 'N/A'),
                        rule_level=match.get('level', 'N/A'),
                        log_source=json.dumps(match.get('logsource', {}), ensure_ascii=False, default=json_serial_converter),
                        detection_details=json.dumps(match.get('detection', {}), ensure_ascii=False, default=json_serial_converter),
                        log_entry=json.dumps(log_entry, ensure_ascii=False, default=json_serial_converter)
                    )
                    # --- ▲▲▲ 修正はここまで ▲▲▲ ---
                    self.session.add(new_match)
                    print(f"  - Prepared for DB: \"{new_match.rule_title}\"")
                except Exception as e:
                    print(f"ERROR: Failed to create SigmaMatch object for DB: {e}")
                    logger.error(f"ERROR: Failed to create SigmaMatch object for DB: {e}", exc_info=True)
            
            try:
                self.session.commit()
                print("SUCCESS: All matches committed to the database.")
                logger.info("SUCCESS: All matches committed to the database.")
            except Exception as e:
                print(f"ERROR: Failed to commit matches to the database: {e}")
                logger.error(f"ERROR: Failed to commit matches to the database: {e}", exc_info=True)
                
                with open("debug_db_errors.log", "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.datetime.now()}] COMMIT FAILED: {str(e)}\n")
                    f.write(traceback.format_exc() + "\n")
                
                self.session.rollback()

    def stop(self):
        if self.session:
            self.session.close()
        print("Log Monitor Worker stopped.")