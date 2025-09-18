import os
import json

class NicterAnalyzer:
    def __init__(self, cache_dir='cache'):
        self.cache_path = os.path.join(cache_dir, 'nicterweb_cache.json')
        self.nicter_data = self._load_nicter_data()

    def _load_nicter_data(self):
        """
        キャッシュされたNICTERの脅威フィードを読み込む。
        （注：あなたのcollector_base.pyが24時間ごとに自動更新してくれます）
        """
        if not os.path.exists(self.cache_path):
            # collector_baseが動く前にanalyzerが呼ばれることは稀だが、念のため
            return []
        
        try:
            with open(self.cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                threat_list = data.get('data', [])
                print(f"  > [NICTER] Successfully loaded {len(threat_list)} threat entities from cache.")
                return threat_list
        except (json.JSONDecodeError, IOError) as e:
            print(f"  > [NICTER] Error reading cache file: {e}")
            return []

    def get_top_attack_trends(self, top_n=5):
        """
        【最終進化】ロードしたNICTERデータから、最新の攻撃傾向を分析し、
        上位N件の攻撃元国と、狙われているサービスをレポートする。
        """
        if not self.nicter_data:
            return {"error": "NICTERデータがロードされていません。"}

        top_countries = []
        top_services = []

        # データを種類別に分類
        for threat in self.nicter_data:
            if threat.get('type') == '国別ユニークホスト数':
                top_countries.append({
                    "国": threat.get('name'),
                    "観測ホスト数": threat.get('count')
                })
            elif threat.get('type') == 'TCPポート別ユニークホスト数':
                top_services.append({
                    "サービス(ポート)": threat.get('name'),
                    "観測ホスト数": threat.get('count')
                })
        
        # 観測ホスト数で降順にソート
        top_countries = sorted(top_countries, key=lambda x: x['観測ホスト数'], reverse=True)
        top_services = sorted(top_services, key=lambda x: x['観測ホスト数'], reverse=True)

        return {
            "判定": "情報あり",
            "詳細": "NICTERのダークネット観測網における最新の攻撃傾向トップ5です。",
            "攻撃元国トップ5": top_countries[:top_n],
            "標的サービス トップ5": top_services[:top_n]
        }