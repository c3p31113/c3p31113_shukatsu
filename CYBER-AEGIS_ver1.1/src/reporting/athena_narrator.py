# CYBER-AEGIS/src/reporting/athena_narrator.py

from typing import Tuple
from src.core_ai.ollama_manager import OllamaManager

class Narrator:
    """
    脅威インテリジェンスデータを基に、AI(Ollama)を用いて
    詳細な分析レポートを生成する役割を担うクラス。
    """
    def __init__(self):
        # ★★★ 修正点1: モデルを実績のある'llama3:8b'に固定 ★★★
        self.ollama = OllamaManager(model='llama3:8b')

    def summarize_threat_intel(self, threat_data: dict) -> str:
        """
        単一の脅威データを受け取り、AIに分析を依頼し、
        レポートの中身となるHTMLのdivブロックを返す。
        """
        if not isinstance(threat_data, dict):
            return "<div><p style='color: #e74c3c;'>エラー: 分析対象のデータ形式が不正です。</p></div>"

        system_message, user_prompt = self._create_prompts_for_blacklist(threat_data)
        
        # タイムアウトを60秒に設定してAIから応答を取得
        ai_response = self.ollama.generate_response(user_prompt, system_message, timeout=60)

        # AIの応答がエラーメッセージだった場合、整形して表示
        if ai_response.startswith("[エラー:") or ai_response.startswith("[警告:"):
            return f"<div><p style='color: #e74c3c; font-weight: bold;'>{ai_response}</p></div>"

        # AIが生成したレポート部分だけを返す
        return ai_response

    # ★★★ 修正点2: プロンプト生成ロジックをdashboard_view.py方式に完全準拠 ★★★
    def _create_prompts_for_blacklist(self, threat_data: dict) -> Tuple[str, str]:
        """AIへのシステムメッセージとユーザープロンプトを生成する"""
        
        system_message = (
            "あなたはプロのサイバー脅威インテリジェンス・アナリストです。"
            "あなたの唯一の役割は、与えられた脅威データを分析し、HTMLの`<div>`ブロック形式でレポートを生成することです。"
            "会話は一切不要です。指定された形式の日本語HTMLレポートのみを生成してください。"
        )

        # 手本1: CISAの脆弱性情報 (CRITICAL)
        example1_input = "ID: CVE-2023-38831, 種別: 脆弱性, 名称: WinRAR - ZIP Files - Remote Code Execution, リスクレベル: CRITICAL, ソース: CISA KEV"
        example1_output = """<div>
<h3>脅威の概要</h3><p>ファイル圧縮・解凍ツール「WinRAR」に存在する、リモートでコードが実行される極めて危険な脆弱性(CVE-2023-38831)です。攻撃者が作成した特殊なZIPファイルを開くだけで、PCがマルウェアに感染する可能性があります。</p>
<h3>潜在的なリスク</h3><p>CRITICALレベルの脅威です。ランサムウェアによるファイル暗号化、個人情報や機密情報の窃取、更なるサイバー攻撃の踏み台にされるなど、深刻な被害に直結する危険性があります。</p>
<h3>推奨される対応</h3><ul><li>直ちにWinRARをバージョン6.23以降にアップデートしてください。</li><li>身に覚えのない送信元からのZIPやRARファイルは絶対に開かないでください。</li><li>PCのフルスキャンを実行し、不審なファイルがないか確認してください。</li></ul>
</div>"""

        # 手本2: SpamhausのIPアドレス (HIGH)
        example2_input = "ID: SPAMHAUS-190.115.24.0/22, 種別: Malicious IP, 名称: Spamhaus DROP List Entry, リスクレベル: HIGH, ソース: Spamhaus"
        example2_output = """<div>
<h3>脅威の概要</h3><p>このIPアドレス帯(190.115.24.0/22)は、サイバー犯罪に悪用されていると報告されているため、Spamhausのブロックリストに登録されています。主にボットネットのC2サーバーやマルウェア配布元として利用されています。</p>
<h3>潜在的なリスク</h3><p>HIGHレベルの脅威です。このIPアドレスとの通信は、マルウェア感染、フィッシング詐欺、サービス妨害(DoS)攻撃など、様々なサイバー攻撃に巻き込まれるリスクを意味します。</p>
<h3>推奨される対応</h3><ul><li>ファイアウォールでこのIPアドレス帯からの通信をすべてブロックしてください。</li><li>このIPアドレスへのアクセスログがないか確認し、もしあれば感染の有無を調査してください。</li><li>ネットワーク監視を強化し、同様の不審な通信がないか監視してください。</li></ul>
</div>"""
        
        # 実際のタスク入力を作成
        task_input_parts = []
        key_map = {'id': 'ID', 'type': '種別', 'name': '名称', 'risk_level': 'リスクレベル', 'platform': 'プラットフォーム', 'last_seen': '最終確認日時', 'source': 'ソース'}
        for key, display_name in key_map.items():
            if key in threat_data:
                task_input_parts.append(f"{display_name}: {threat_data[key]}")
        task_input_str = ", ".join(task_input_parts)

        # 最終的なプロンプトを組み立て
        prompt = f"""<INSTRUCTION>
以下の<TASK_INPUT>のデータを分析し、脅威レベルに応じてHTMLレポート(`<div>`ブロック)を生成してください。
提示された<EXAMPLE>の形式とトーンに厳密に従ってください。
</INSTRUCTION>

<EXAMPLE No.1: CRITICALな脅威>
TASK_INPUT: {example1_input}
OUTPUT:
{example1_output}
</EXAMPLE>

<EXAMPLE No.2: HIGHな脅威>
TASK_INPUT: {example2_input}
OUTPUT:
{example2_output}
</EXAMPLE>

<TASK_INPUT>
{task_input_str}
</TASK_INPUT>
"""
        return system_message, prompt