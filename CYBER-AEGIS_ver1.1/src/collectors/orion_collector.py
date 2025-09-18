# CYBER-AEGIS/src/collectors/orion_collector.py

import datetime
from .collector_base import CollectorBase

class OrionCollector(CollectorBase):
    def __init__(self):
        super().__init__(
            source_url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            cache_filename="orion_feodotracker.json"
        )

    def fetch_threat_feed(self):
        raw_data = self.get_feed()
        
        # ★★★ 修正点: 厳格すぎたチェックを削除 ★★★
        # データがリストでない場合や空の場合でも、ループ処理で安全に対応
        if not raw_data:
            print(f"[{self.__class__.__name__}] Fetched data is empty or invalid.")
            # 空の成功レスポンスを返す
            return {"status": "success", "data": []}

        threat_entities = []
        for entry in raw_data:
            if not isinstance(entry, dict):
                continue
            
            ip_address = entry.get('ip_address')
            if not ip_address:
                continue

            # 日付情報のフォーマット
            last_seen_formatted = "N/A"
            # 'last_online'キーが存在すればそれを使用し、なければ'first_seen_utc'を使用
            date_str = entry.get('last_online') or entry.get('first_seen_utc')
            if date_str:
                try:
                    # abuse.chの複数の日付フォーマットに対応
                    if ' ' in date_str: # 'YYYY-MM-DD HH:MM:SS' 形式
                        last_seen_dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    else: # ISO形式 ('YYYY-MM-DDTHH:MM:SSZ')
                        last_seen_dt = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    last_seen_formatted = last_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    last_seen_formatted = "Invalid Date"

            entity = {
                "id": f"ABUSE.CH-{ip_address}",
                "type": "C2 Server",
                "name": f"{entry.get('malware', 'Unknown')} Botnet",
                "risk_level": "CRITICAL",
                "platform": f"AS{entry.get('as_number')} ({entry.get('as_name')})",
                "last_seen": last_seen_formatted,
                "source": "abuse.ch" # ソース情報を追加
            }
            threat_entities.append(entity)
            
        return {"status": "success", "data": threat_entities}