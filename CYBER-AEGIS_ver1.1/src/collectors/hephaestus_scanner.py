# CYBER-AEGIS/src/collectors/hephaestus_scanner.py

import socket
import threading

class HephaestusScanner:
    """
    Project Hephaestusのコアとなる脆弱性スキャナ。
    現バージョンでは、基本的なポートスキャン機能を実装する。
    """
    def __init__(self):
        # スキャン対象とする一般的なポートとその用途
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt"
        }

    def scan_open_ports(self, target='127.0.0.1', progress_callback=None):
        """
        指定されたターゲットの一般的なポートが開いているかスキャンする。
        
        :param target: スキャン対象のIPアドレス
        :param progress_callback: 進捗を報告するためのコールバック関数 (例: progress_bar.setValue)
        :return: 開いているポートのリスト
        """
        open_ports = []
        ports_to_scan = list(self.common_ports.keys())
        total_ports = len(ports_to_scan)
        
        for i, port in enumerate(ports_to_scan):
            # ソケットを作成し、タイムアウトを短く設定して接続を試みる
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)  # タイムアウトを短く設定し、高速にスキャンする
                    if s.connect_ex((target, port)) == 0:
                        service = self.common_ports.get(port, "不明")
                        open_ports.append({'port': port, 'service': service})
            except socket.error:
                # ソケット関連のエラーは無視して次に進む
                pass
            
            # 進捗をコールバック関数を通じてUIに通知する
            if progress_callback:
                progress = int(((i + 1) / total_ports) * 100)
                progress_callback(progress)
                
        return open_ports