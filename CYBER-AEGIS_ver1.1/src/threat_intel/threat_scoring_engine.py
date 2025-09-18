# CYBER-AEGIS/src/threat_intel/threat_scoring_engine.py

import os

class ThreatScoringEngine:
    """
    イベントのデータに基づいて脅威レベルを判定するルールベースのエンジン。
    """
    def __init__(self):
        # --- ファイルイベントに関するルール ---
        # 拡張子ごとの脅威スコア (高いほど危険)
        self.file_extension_scores = {
            '.exe': 90, '.dll': 80, '.bat': 90, '.ps1': 85, '.vbs': 85, '.jar': 70,
            '.docm': 75, '.xlsm': 75, '.pptm': 75, # マクロ付きOfficeファイル
            '.zip': 40, '.rar': 40,
            '.txt': 5, '.log': 1,
        }
        # イベントタイプごとのスコア加算
        self.file_event_scores = {
            '作成': 20,
            '変更': 5,
            '削除': 10,
            '移動/名前変更': 15,
        }

        # --- ネットワークイベントに関するルール ---
        # 危険な可能性のあるポート番号
        self.risky_ports = {
            21: 40, # FTP
            22: 30, # SSH
            23: 50, # Telnet
            135: 60, # RPC
            445: 70, # SMB
            3389: 80, # RDP
            5900: 75, # VNC
        }
        # 監視すべきプロセス名（部分一致）
        self.suspicious_processes = {
            'powershell': 70,
            'cmd.exe': 60,
            'svchost.exe': 20, # 悪用されることもあるが、通常は正常
        }

    def _score_to_level(self, score):
        """スコアを脅威レベルに変換する"""
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"

    def score_file_event(self, event_data):
        """ファイルイベントの脅威スコアを計算する"""
        score = 0
        file_path = event_data.get('path', '').lower()
        event_type = event_data.get('event_type')
        
        # 1. 拡張子でスコアリング
        _, ext = os.path.splitext(file_path)
        score += self.file_extension_scores.get(ext, 10) # 不明な拡張子は10点

        # 2. イベントタイプでスコアを加算
        score += self.file_event_scores.get(event_type, 0)
        
        return self._score_to_level(score)

    def score_network_event(self, event_data):
        """ネットワークイベントの脅威スコアを計算する"""
        score = 10 # ベーススコア
        process_name = event_data.get('name', '').lower()
        destination = event_data.get('destination', '')
        
        # 1. ポート番号でスコアリング
        try:
            port = int(destination.split(':')[-1])
            score += self.risky_ports.get(port, 0)
        except (ValueError, IndexError):
            pass

        # 2. プロセス名でスコアリング
        for proc, proc_score in self.suspicious_processes.items():
            if proc in process_name:
                score += proc_score
        
        return self._score_to_level(score)