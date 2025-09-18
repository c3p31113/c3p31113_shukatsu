# CYBER-AEGIS/src/collectors/nicterweb_collector.py (修正版)
import os
import time
import csv
import json
import zipfile
import datetime
from io import BytesIO, StringIO
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class NicterwebCollector:
    TOP_PAGE_URL = "https://www.nicter.jp/top10"
    
    FILE_TYPES = {
        "country_host": "国別ユニークホスト数",
        "tcp_host": "TCPポート別ユニークホスト数",
        "udp_host": "UDPポート別ユニークホスト数",
        "country_packet": "国別パケット数",
        "tcp_packet": "TCPポート別パケット数",
        "udp_packet": "UDPポート別パケット数"
    }
    
    def __init__(self, download_dir=None):
        if download_dir:
            self.download_dir = download_dir
        else:
            self.download_dir = os.path.abspath(os.path.join('cache', 'nicter_downloads'))
        
        os.makedirs(self.download_dir, exist_ok=True)
        self.cache_path = os.path.join('cache', 'nicterweb_cache.json')
        self.cache_duration_seconds = 10800 # 3時間
        print(f"[{self.__class__.__name__}] Initialized. Download dir: {self.download_dir}")

    def is_cache_valid(self):
        if not os.path.exists(self.cache_path): 
            return False
        try:
            cache_mod_time = os.path.getmtime(self.cache_path)
            if (time.time() - cache_mod_time) < self.cache_duration_seconds:
                if os.path.getsize(self.cache_path) > 0:
                    with open(self.cache_path, 'r', encoding='utf-8') as f:
                        json.load(f)
                    return True
        except (IOError, json.JSONDecodeError):
            return False
        return False

    def read_from_cache(self):
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            print(f"[{self.__class__.__name__}] Error reading cache file. It might be corrupted.")
            return {"status": "error", "data": []}

    def _write_to_cache(self, data):
        try:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                # ▼▼▼【重要修正点】▼▼▼
                # ensure_ascii=False を追加して日本語の文字化けを防ぎ、破損したJSONが生成されるのを防ぎます
                json.dump(data, f, ensure_ascii=False, indent=4)
            print(f"[{self.__class__.__name__}] Successfully wrote data to cache.")
        except IOError as e:
            print(f"[{self.__class__.__name__}] Failed to write to cache: {e}")

    def _wait_for_download(self, timeout=60):
        print(f"[{self.__class__.__name__}] > Step 4.1: Waiting for download to complete in '{self.download_dir}'...")
        for i in range(timeout):
            for filename in os.listdir(self.download_dir):
                if filename.endswith('.zip') and not filename.endswith('.crdownload'):
                    print(f"[{self.__class__.__name__}] > Step 4.2: Downloaded file found: {filename}")
                    return os.path.join(self.download_dir, filename)
            if (i + 1) % 10 == 0:
                print(f"[{self.__class__.__name__}] > Still waiting... ({i+1}s)")
            time.sleep(1)
        
        print(f"[{self.__class__.__name__}] > FAILURE: Download did not complete within {timeout} seconds.")
        print(f"[{self.__class__.__name__}] > Current files in dir: {os.listdir(self.download_dir)}")
        return None

    def _clear_download_dir(self):
        print(f"[{self.__class__.__name__}] > Step 1: Clearing download directory: {self.download_dir}")
        for filename in os.listdir(self.download_dir):
            try:
                os.remove(os.path.join(self.download_dir, filename))
            except OSError:
                pass
        print(f"[{self.__class__.__name__}] > Directory cleared.")

    def _parse_zip_file(self, zip_content, target_date):
        print(f"[{self.__class__.__name__}] > Step 6: Parsing ZIP content for date {target_date.strftime('%Y-%m-%d')}")
        threat_entities = []
        date_str_zip_folder = target_date.strftime("%Y_%m_%d")
        
        try:
            with zipfile.ZipFile(BytesIO(zip_content)) as zf:
                all_files_in_zip = zf.namelist()
                print(f"[{self.__class__.__name__}] > Files in ZIP: {all_files_in_zip}")
                
                for file_key, threat_type_name in self.FILE_TYPES.items():
                    target_csv_path = f"{date_str_zip_folder}/{file_key}.csv"
                    if target_csv_path in all_files_in_zip:
                        csv_text = StringIO(zf.read(target_csv_path).decode('utf-8', errors='ignore'))
                        reader = csv.reader(csv_text)
                        next(reader, None)
                        
                        for row in reader:
                            try:
                                if "country" in file_key:
                                    if len(row) < 4: continue
                                    item_name, count_str = row[1], row[3]
                                else: 
                                    if len(row) < 3: continue
                                    item_name, count_str = row[1], row[2]

                                threat_entities.append({
                                    "id": f"NICTER-{target_date.strftime('%Y-%m-%d')}-{file_key}-{item_name}",
                                    "type": threat_type_name,
                                    "name": item_name.strip(),
                                    "count": int(count_str),
                                    "risk_level": "INFO",
                                    "platform": "NICTER ダークネット観測",
                                    "last_seen": target_date.strftime("%Y-%m-%d"),
                                    "source": "NICTERWEB"
                                })
                            except (ValueError, IndexError):
                                continue
                
                print(f"[{self.__class__.__name__}] > Successfully parsed {len(threat_entities)} entities from ZIP.")
                return {"status": "success", "data": threat_entities}

        except Exception as e:
            print(f"[{self.__class__.__name__}] > FAILURE: Failed to parse ZIP content: {e}")
            return {"status": "error", "data": []}

    def fetch_threat_feed(self, driver: webdriver.Chrome):
        if self.is_cache_valid():
            print(f"[{self.__class__.__name__}] Reading from valid cache...")
            return self.read_from_cache()

        print(f"[{self.__class__.__name__}] Cache invalid or not found. Fetching via browser automation...")
        
        try:
            self._clear_download_dir()
            print(f"[{self.__class__.__name__}] > Step 2: Navigating to {self.TOP_PAGE_URL}")
            driver.get(self.TOP_PAGE_URL)
            
            wait = WebDriverWait(driver, 20)
            download_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "div#day_btn a")))
            latest_date_str = download_button.text.strip()
            print(f"[{self.__class__.__name__}] > Step 3: Found latest date '{latest_date_str}'. Clicking download...")
            download_button.click()
            
            downloaded_zip_path = self._wait_for_download()
            if not downloaded_zip_path:
                return {"status": "error", "data": []}

            print(f"[{self.__class__.__name__}] > Step 5: Reading downloaded file: {os.path.basename(downloaded_zip_path)}")
            with open(downloaded_zip_path, 'rb') as f:
                zip_content = f.read()
            
            date_obj = datetime.datetime.strptime(latest_date_str, '%Y/%m/%d').date()
            result = self._parse_zip_file(zip_content, date_obj)
            
            if result.get("status") == "success":
                self._write_to_cache(result)
                
            return result

        except Exception as e:
            print(f"[{self.__class__.__name__}] > FATAL: An error occurred during browser automation: {e}")
            return {"status": "error", "data": []}
        finally:
            print(f"[{self.__class__.__name__}] > Step 7: Final cleanup of download directory.")
            self._clear_download_dir()