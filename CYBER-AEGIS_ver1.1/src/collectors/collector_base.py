# CYBER-AEGIS/src/collectors/collector_base.py

import os
import json
import requests # requestsをインポート
import time

class CollectorBase:
    CACHE_DIR = "cache"
    CACHE_DURATION_SECONDS = 86400  # 24時間

    def __init__(self, source_url, cache_filename):
        self.source_url = source_url
        self.cache_path = os.path.join(self.CACHE_DIR, cache_filename)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
        }
        
        # ★★★ 修正点1: 効率的な接続のためのセッションオブジェクトを作成 ★★★
        self.session = requests.Session()
        self.session.headers.update(headers)
        
        os.makedirs(self.CACHE_DIR, exist_ok=True)

    def _is_cache_valid(self):
        if not os.path.exists(self.cache_path):
            return False
        cache_mod_time = os.path.getmtime(self.cache_path)
        return (time.time() - cache_mod_time) < self.CACHE_DURATION_SECONDS

    def _read_from_cache(self, status=""):
        print(f"[{self.__class__.__name__}] Reading from {status} cache: {self.cache_path}")
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError, UnicodeDecodeError) as e:
            print(f"[{self.__class__.__name__}] Failed to read or parse cache file: {e}. Deleting corrupt cache.")
            try:
                os.remove(self.cache_path)
            except OSError as del_e:
                print(f"[{self.__class__.__name__}] Error deleting corrupt cache file: {del_e}")
            return None

    def _fetch_and_cache(self):
        print(f"[{self.__class__.__name__}] Fetching from network: {self.source_url}")
        try:
            # ★★★ 修正点2: requests.get -> self.session.get に変更 ★★★
            response = self.session.get(self.source_url, timeout=180, stream=True)
            response.raise_for_status()
            
            # response.json()で直接デコードを試みる
            data = response.json()

            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            
            print(f"[{self.__class__.__name__}] Successfully cached data to {self.cache_path}")
            return data

        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"[{self.__class__.__name__}] Error during fetch from network: {e}")
            return None

    def get_feed(self):
        if self._is_cache_valid():
            data = self._read_from_cache(status="valid")
            if data:
                return data

        fresh_data = self._fetch_and_cache()
        if fresh_data is not None:
            return fresh_data
        
        print(f"[{self.__class__.__name__}] Network fetch failed.")
        if os.path.exists(self.cache_path):
            return self._read_from_cache(status="stale (fallback)")
            
        print(f"[{self.__class__.__name__}] Network failed and no cache available.")
        return None
            
    def fetch_threat_feed(self):
        raise NotImplementedError("This method should be implemented by subclasses.")