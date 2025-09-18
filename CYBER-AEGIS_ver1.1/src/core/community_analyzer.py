import re

class CommunityAnalyzer:
    def __init__(self):
        # スコアリングのためのキーワードと、その危険度ウェイトを定義
        self.threat_keywords = {
            # 高リスク（マルウェア、ハッキングツールなど）
            'malware': 10, 'rat': 10, 'botnet': 10, 'exploit': 8, 'vulnerability': 8,
            'zeroday': 12, '0day': 12, 'ransomware': 10, 'payload': 7, 'c2': 9,
            # 中リスク（一般的なサイバーセキュリティ用語）
            'pentest': 3, 'red team': 3, 'hacking': 4, 'dox': 5, 'leak': 5,
            # 低リスク（注意すべきだが、文脈による）
            'vpn': 1, 'proxy': 1, 'tor': 2, 'anonymous': 2
        }

    def analyze_server_messages(self, messages):
        """サーバーのメッセージ群を受け取り、危険度スコアを算出する"""
        total_score = 0
        hit_keywords = []

        if not messages:
            return 0, []

        # 全メッセージを1つのテキストに結合して分析効率を上げる
        full_text = " ".join([msg.get('message_text', '').lower() for msg in messages])

        for keyword, weight in self.threat_keywords.items():
            # テキスト内にキーワードが出現した回数をカウント
            count = len(re.findall(r'\b' + re.escape(keyword) + r'\b', full_text))
            if count > 0:
                total_score += count * weight
                hit_keywords.append(f"{keyword} (x{count})")
        
        # メッセージ数でスコアを正規化し、極端な値になるのを防ぐ
        # (メッセージが少ないサーバーでスコアが跳ね上がるのを抑制)
        normalized_score = (total_score / len(messages)) * 20
        
        # 最終スコアを0-100の範囲に収める
        final_score = min(int(normalized_score), 100)

        return final_score, list(set(hit_keywords))