# CYBER-AEGIS/src/collectors/spamhaus_collector.py

import os
from .collector_base import CollectorBase

class SpamhausCollector(CollectorBase):
    def __init__(self):
        super().__init__(
            source_url="https://www.spamhaus.org/drop/drop.txt",
            cache_filename="spamhaus_drop.txt"
        )
    
    def _parse_feed(self, raw_data_text):
        """プレーンテキストのDROPリストを解析し、標準の辞書形式に変換する"""
        threat_entities = []
        if not raw_data_text:
            return threat_entities
            
        lines = raw_data_text.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            
            ip_cidr = line.split(';')[0].strip()
            
            entity = {
                "id": f"SPAMHAUS-{ip_cidr}",
                "type": "Malicious IP",
                "name": f"Spamhaus DROP List Entry",
                "risk_level": "HIGH",
                "platform": "Spamhaus",
                "last_seen": "N/A",
                "source": "Spamhaus"
            }
            threat_entities.append(entity)
            
        return threat_entities

    def fetch_threat_feed(self):
        """
        Spamhausコレクターのメイン処理。
        テキストファイルを取得するため、get_feed()は使わず専用ロジックを実装。
        """
        # 1. 有効なキャッシュがあれば、それを読んで返す
        if self._is_cache_valid():
            print(f"[{self.__class__.__name__}] Reading from valid cache: {self.cache_path}")
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    return {"status": "success", "data": self._parse_feed(f.read())}
            except Exception as e:
                print(f"[{self.__class__.__name__}] Failed to read valid cache, re-fetching... ({e})")
        
        # 2. キャッシュが無効か読めなければ、ネットワークから取得
        print(f"[{self.__class__.__name__}] Fetching from network: {self.source_url}")
        try:
            # ★★★ ここで self.session が使えるようになっている ★★★
            response = self.session.get(self.source_url, timeout=30)
            response.raise_for_status()
            data = response.text
            
            # 取得したデータをキャッシュに保存
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                f.write(data)
            
            return {"status": "success", "data": self._parse_feed(data)}
        except Exception as e:
            print(f"[{self.__class__.__name__}] Error during fetch from network: {e}")
            
            # 3. ネットワーク取得に失敗した場合、古いキャッシュでもあればそれを最後の手段として使う
            if os.path.exists(self.cache_path):
                 print(f"[{self.__class__.__name__}] Using stale cache as fallback.")
                 try:
                    with open(self.cache_path, 'r', encoding='utf-8') as f:
                        return {"status": "success", "data": self._parse_feed(f.read())}
                 except Exception as fallback_e:
                     print(f"[{self.__class__.__name__}] Fallback cache read failed: {fallback_e}")

            # すべて失敗した場合
            return {"status": "error", "data": []}