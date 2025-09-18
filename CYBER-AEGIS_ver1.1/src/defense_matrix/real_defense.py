# CYBER-AEGIS/src/defense_matrix/real_defense.py

import os
import shutil # ファイルの移動に適したライブラリをインポート

class RealDefense:
    def __init__(self, blocklist_file='blocklist.txt', quarantine_dir='quarantine'):
        self.blocklist_file = blocklist_file
        self.quarantine_dir = quarantine_dir
        self.blocked_ips = self._load_blocklist()
        
        # --- 隔離ディレクトリがなければ作成 ---
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def _load_blocklist(self):
        if not os.path.exists(self.blocklist_file):
            return set()
        with open(self.blocklist_file, 'r') as f:
            return {line.strip() for line in f if line.strip()}

    def add_to_blocklist(self, ip_address):
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            with open(self.blocklist_file, 'a') as f:
                f.write(f"{ip_address}\n")
            return True
        return False

    def is_blocked(self, ip_address):
        return ip_address in self.blocked_ips

    def quarantine_file(self, file_path):
        """指定されたファイルを隔離ディレクトリに移動する"""
        if not os.path.exists(file_path):
            return False, f"ファイルが見つかりません: {file_path}"
        
        # ファイル名のみを取得
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(self.quarantine_dir, file_name)
        
        try:
            shutil.move(file_path, dest_path)
            return True, f"ファイルを隔離しました: {dest_path}"
        except Exception as e:
            return False, f"ファイルの隔離に失敗しました: {e}"