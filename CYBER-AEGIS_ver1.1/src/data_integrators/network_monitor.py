# CYBER-AEGIS/src/data_integrators/network_monitor.py

import psutil
import datetime
from src.defense_matrix.real_defense import RealDefense
from src.threat_intel.threat_scoring_engine import ThreatScoringEngine # 新しくインポート

class NetworkMonitor:
    def __init__(self):
        self.real_defense = RealDefense()
        self.scoring_engine = ThreatScoringEngine() # スコアリングエンジンをインスタンス化

    def get_active_connections(self):
        connections = []
        self.real_defense._load_blocklist()

        try:
            conns = [c for c in psutil.net_connections(kind='tcp') if c.status == psutil.CONN_ESTABLISHED]
            
            for conn in conns:
                proc_name = "N/A"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "Access Denied"

                if conn.raddr:
                    ip_address = conn.raddr.ip
                    destination = f"{ip_address}:{conn.raddr.port}"
                    
                    connection_data = {
                        "name": proc_name,
                        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "destination": destination,
                    }
                    
                    if self.real_defense.is_blocked(ip_address):
                        connection_data["status"] = "ブロック済み"
                        connection_data["threat_level"] = "CRITICAL"
                    else:
                        connection_data["status"] = "監視中"
                        # --- ランダム判定をスコアリングに変更 ---
                        connection_data["threat_level"] = self.scoring_engine.score_network_event(connection_data)

                    connections.append(connection_data)
                    
        except Exception as e:
            print(f"ネットワーク接続の取得中にエラーが発生しました: {e}")
            
        return connections