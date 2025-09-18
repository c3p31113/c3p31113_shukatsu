# CYBER-AEGIS/src/core_ai/ollama_manager.py

import logging
import requests
import json
import re

class OllamaManager:
    def __init__(self, model='gemma:2b', host='127.0.0.1', port='11434', timeout=20000):
        self.model = model
        self.host = host
        self.port = port
        self.chat_url = f"http://{self.host}:{self.port}/api/chat"
        self.generate_url = f"http://{self.host}:{self.port}/api/generate"
        self.timeout = timeout
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)

    # --- ▼▼▼【ここから追加】▼▼▼ ---
    def _clean_json_response(self, response_text):
        """
        AIが生成した応答からMarkdownのコードブロックや余分なテキストを削除し、
        純粋なJSON文字列を抽出する。
        """
        # ```json ... ``` や ``` ... ``` 形式を検索
        match = re.search(r'```(json)?\s*({.*})\s*```', response_text, re.DOTALL)
        if match:
            # マッチしたJSON部分を返す
            return match.group(2)
        
        # 上記にマッチしない場合、最初と最後の波括弧で囲まれた部分を探す
        # これにより、AIが前後に余計な解説を付けてもJSON本体を救出しやすくなる
        start = response_text.find('{')
        end = response_text.rfind('}')
        if start != -1 and end != -1 and end > start:
            return response_text[start:end+1]

        # それでも見つからない場合は、元のテキストをそのまま返す（エラーは後続処理に任せる）
        return response_text
    # --- ▲▲▲【追加ここまで】▲▲▲ ---

    def generate(self, model_name, prompt):
        """
        /api/generateエンドポイントを直接呼び出すメソッド。
        """
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False
        }
        logging.info(f"--- AIへのリクエスト開始 (モデル: {model_name}, エンドポイント: /api/generate) ---")
        logging.info(f"[送信プロンプト]:\n{prompt[:500]}...")

        try:
            response = requests.post(self.generate_url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            response_data = response.json()
            raw_response = response_data.get('response', '').strip()

            logging.info("--- AIからの応答受信完了 ---")
            logging.info(f"[受信した生の応答]: {raw_response[:500]}...")

            # --- ▼▼▼【ここを修正】▼▼▼ ---
            # クリーニング処理を呼び出す
            final_response = self._clean_json_response(raw_response)
            # --- ▲▲▲【修正ここまで】▲▲▲ ---

            if not final_response:
                logging.warning("AIの応答内容が空か、JSON部分を抽出できませんでした。")
                return "{}"

            return final_response

        except requests.exceptions.Timeout:
            logging.error(f"AIとの接続がタイムアウトしました ({self.timeout}秒)。")
            return f'{{"error": "AIとの接続がタイムアウトしました"}}'
        except requests.exceptions.RequestException as e:
            logging.error(f"Ollama APIへのリクエスト中にエラーが発生しました: {e}")
            return f'{{"error": "Ollama APIへの接続に失敗しました。"}}'

    def generate_response(self, prompt, system_message="You are a helpful assistant."):
        """
        /api/chatエンドポイントを呼び出すメソッド。
        """
        # (このメソッドは変更ありません)
        payload = { "model": self.model, "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": prompt}], "stream": True }
        
        logging.info(f"--- AIへのリクエスト開始 (モデル: {self.model}, エンドポイント: /api/chat) ---")
        # (...以降、変更なし)
        logging.info(f"[送信SYSTEMプロンプト]: {system_message}")
        logging.info(f"[送信USERプロンプト]:\n{prompt}")
        
        full_response_content = []
        
        try:
            with requests.post(self.chat_url, json=payload, stream=True, timeout=self.timeout) as response:
                response.raise_for_status()
                
                for line in response.iter_lines():
                    if line:
                        try:
                            chunk = json.loads(line.decode('utf-8'))
                            content = chunk.get('message', {}).get('content')
                            if content:
                                full_response_content.append(content)
                            if chunk.get('done'):
                                break
                        except json.JSONDecodeError:
                            logging.warning(f"JSONのデコードに失敗した行をスキップ: {line}")
                            continue
            
            final_response = "".join(full_response_content)
            logging.info("--- AIからの応答受信完了 ---")
            logging.info(f"[組み立てられた最終応答]: {final_response}")

            if not final_response.strip():
                logging.warning("AIは応答を返しましたが、内容が空でした。")
                return ""

            return final_response

        except requests.exceptions.Timeout:
            logging.error(f"AIとの接続がタイムアウトしました ({self.timeout}秒)。")
            return f"[エラー: AIとの接続がタイムアウトしました]"
        except requests.exceptions.RequestException as e:
            logging.error(f"Ollama APIへのリクエスト中にエラーが発生しました: {e}")
            return f"[エラー: Ollama APIへの接続に失敗しました。]"