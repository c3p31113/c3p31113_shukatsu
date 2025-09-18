# src/threat_intel/mitre_mapper.py

import json
import re
from src.collectors.mitre_attack_collector import MitreAttackCollector

class MitreMapper:
    def __init__(self):
        self.collector = MitreAttackCollector()
        self.attack_data = self._load_attack_data()
        # ▼▼▼【本格実装】兵法書から、全ての既知の脅威アクターとマルウェアの名前リストを作成 ▼▼▼
        self.known_threat_names = self._extract_known_threat_names()

    def _load_attack_data(self):
        """
        MitreAttackCollectorを通じて、MITRE ATT&CKのデータを取得またはキャッシュから読み込む。
        """
        print(f"[{self.__class__.__name__}] Loading MITRE ATT&CK data...")
        data = self.collector.get_feed()
        if not data or 'objects' not in data:
            print(f"[{self.__class__.__name__}] Failed to load MITRE ATT&CK data.")
            return []
        print(f"[{self.__class__.__name__}] MITRE ATT&CK data loaded successfully.")
        return data['objects']

    def _extract_known_threat_names(self):
        """
        ロードしたATT&CKデータから、全ての攻撃者グループとマルウェアの名前を抽出する。
        """
        if not self.attack_data:
            return []
        
        threats = set()
        for obj in self.attack_data:
            if obj.get('type') in ['intrusion-set', 'malware']:
                # 正規名と、エイリアス（別名）の両方をリストに追加
                if 'name' in obj:
                    threats.add(obj['name'].lower())
                if 'aliases' in obj:
                    for alias in obj['aliases']:
                        threats.add(alias.lower())
        return list(threats)

    def extract_threat_actors(self, investigation_results):
        """
        【本格実装】調査結果のJSONデータ全体を再帰的に探索し、
        兵法書に記載のある、既知の脅威アクターやマルウェアの名前を動的に抽出する。
        """
        actors = set()
        
        # 調査結果のJSONデータを全て小文字の文字列に変換
        json_str = json.dumps(investigation_results).lower()

        # 兵法書にある全ての脅威名で、調査結果をチェック
        for threat in self.known_threat_names:
            # \b は単語の境界を示す正規表現。これにより "worm" が "Sandworm Team" の一部として誤検出されるのを防ぐ
            if re.search(r'\b' + re.escape(threat) + r'\b', json_str):
                # 見つかった名前を整形してセットに追加 (例: cobalt strike -> Cobalt Strike)
                actors.add(threat.title())
        
        return list(actors)

    def map_actors_to_techniques(self, actors):
        """
        脅威アクター名（またはマルウェア名）を、関連するMITRE ATT&CKの技術（Technique）にマッピングする。
        """
        if not self.attack_data:
            return {"error": "MITRE ATT&CK data not available."}

        mapping = {}
        
        # 検索しやすいように、名前をキーにした辞書を作成
        intrusion_sets = {obj['name'].lower(): obj for obj in self.attack_data if obj.get('type') == 'intrusion-set'}
        malwares = {obj['name'].lower(): obj for obj in self.attack_data if obj.get('type') == 'malware'}
        
        relationships = [obj for obj in self.attack_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses']
        techniques = {obj['id']: obj for obj in self.attack_data if obj.get('type') == 'attack-pattern'}

        for actor_name in actors:
            actor_key = actor_name.lower()
            # 脅威名が intrusion-set または malware として登録されているかチェック
            actor_obj = intrusion_sets.get(actor_key) or malwares.get(actor_key)

            if not actor_obj:
                # エイリアス（別名）でも検索
                for is_obj in intrusion_sets.values():
                    if actor_key in [a.lower() for a in is_obj.get('aliases', [])]:
                        actor_obj = is_obj
                        break
                if not actor_obj:
                    for m_obj in malwares.values():
                        if actor_key in [a.lower() for a in m_obj.get('aliases', [])]:
                            actor_obj = m_obj
                            break
            
            if not actor_obj:
                continue

            actor_id = actor_obj.get('id')
            used_technique_ids = set()

            for rel in relationships:
                if rel.get('source_ref') == actor_id:
                    target_id = rel.get('target_ref')
                    if target_id and target_id.startswith('attack-pattern--'):
                        used_technique_ids.add(target_id)

            actor_techniques = []
            for tech_id in used_technique_ids:
                technique = techniques.get(tech_id)
                if technique:
                    external_id = "N/A"
                    for ref in technique.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            external_id = ref.get('external_id')
                            break
                    
                    actor_techniques.append({
                        "id": external_id,
                        "name": technique.get('name'),
                        "tactic_id": tech_id
                    })
            
            if actor_techniques:
                tactic_map = {}
                for tech in actor_techniques:
                    # 'kill_chain_phases' から戦術を取得
                    phases = techniques.get(tech['tactic_id'], {}).get('kill_chain_phases', [])
                    for phase in phases:
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            tactic = phase.get('phase_name', 'unknown-tactic').replace('-', ' ').title()
                            if tactic not in tactic_map:
                                tactic_map[tactic] = []
                            tactic_map[tactic].append(f"{tech['name']} ({tech['id']})")
                
                mapping[actor_name] = tactic_map

        return mapping if mapping else {"info": "検出された脅威と一致するMITRE ATT&CKの戦術・技術は見つかりませんでした。"}