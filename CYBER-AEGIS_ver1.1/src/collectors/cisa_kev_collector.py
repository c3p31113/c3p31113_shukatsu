# CYBER-AEGIS/src/collectors/cisa_kev_collector.py

import datetime
from .collector_base import CollectorBase

class CisaKevCollector(CollectorBase):
    def __init__(self):
        # ★★★ 修正点: source_urlを正しいCISAのJSONエンドポイントに変更 ★★★
        super().__init__(
            source_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            cache_filename="cisa_kev.json"
        )

    def fetch_threat_feed(self):
        # CollectorBaseのget_feed()を呼び出し、キャッシュ/ネットワークから自動でデータを取得
        raw_data = self.get_feed()

        if not raw_data or not isinstance(raw_data, dict) or 'vulnerabilities' not in raw_data:
            # データが不正な場合は空の成功レスポンスを返す
            return {"status": "success", "data": []}

        threat_entities = []
        for vuln in raw_data.get('vulnerabilities', []):
            if not isinstance(vuln, dict):
                continue
            
            vuln_id = vuln.get('cveID')
            if not vuln_id:
                continue
            
            entity = {
                "id": vuln_id,
                "type": "脆弱性",
                "name": f"{vuln.get('vulnerabilityName', 'N/A')}",
                "risk_level": "HIGH",
                "platform": "CISA KEV",
                "last_seen": vuln.get('dateAdded'),
                "source": "CISA KEV"
            }
            threat_entities.append(entity)
            
        return {"status": "success", "data": threat_entities}