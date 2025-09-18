# CYBER-AEGIS/src/collectors/mitre_attack_collector.py

import datetime
from .collector_base import CollectorBase

class MitreAttackCollector(CollectorBase):
    def __init__(self):
        # MITRE ATT&CKのSTIX形式のデータを取得する公式JSONソース
        super().__init__(
            source_url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            cache_filename="mitre_enterprise_attack.json"
        )

    def fetch_threat_feed(self):
        raw_data = self.get_feed()

        if not raw_data or raw_data.get("type") != "bundle" or 'objects' not in raw_data:
            print(f"[{self.__class__.__name__}] Fetched data is empty or invalid.")
            return {"status": "success", "data": []}

        threat_entities = []
        # MITRE ATT&CKのデータを解析
        for obj in raw_data.get('objects', []):
            # 'attack-pattern' タイプ（=攻撃の技術や手法）で、かつ無効化されていないものだけを抽出
            if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False):
                
                # MITRE ATT&CKのID (例: T1548) を取得
                external_id = "N/A"
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        external_id = ref.get('external_id')
                        break
                
                # 最終更新日時を整形
                last_seen_formatted = "N/A"
                if 'modified' in obj:
                    try:
                        last_seen_dt = datetime.datetime.fromisoformat(obj['modified'].replace('Z', '+00:00'))
                        last_seen_formatted = last_seen_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        last_seen_formatted = "Invalid Date"

                entity = {
                    "id": external_id,
                    "type": "攻撃技術 (Tactic/Technique)",
                    "name": obj.get('name', 'N/A'),
                    "risk_level": "INFO",  # ATT&CKデータは情報であり直接的な脅威ではないため"INFO"レベルとする
                    "platform": ", ".join(obj.get('x_mitre_platforms', ['N/A'])),
                    "last_seen": last_seen_formatted,
                    "source": "MITRE ATT&CK"
                }
                threat_entities.append(entity)
            
        return {"status": "success", "data": threat_entities}