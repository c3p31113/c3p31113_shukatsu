# src/core_ai/white_team_ai.py
import os, json, re, random
from .ollama_manager import OllamaManager
from .threat_engine import ThreatEngine
from .red_team_ai import RedTeamAI
from .blue_team_ai import BlueTeamAI
from .environment_profiler import EnvironmentProfiler
from .simulation_arena import SimulationArena
from .scenario_generator_ai import ScenarioGeneratorAI
from .threat_intelligence_analyst_ai import ThreatIntelligenceAnalystAI
from src.database.db_manager import DBManager

class WhiteTeamAI:
    def __init__(self, fast_mode=False):
        self.ollama = OllamaManager()
        self.model = "gemma3:latest"
        self.threat_engine = ThreatEngine()
        self.fast_mode = fast_mode
        self.red_team = RedTeamAI(fast_mode=self.fast_mode)
        self.blue_team = BlueTeamAI(fast_mode=self.fast_mode)
        self.db_manager = DBManager()
        self.scenario_generator = ScenarioGeneratorAI()
        self.threat_analyst = ThreatIntelligenceAnalystAI()

    def _sanitize_and_load_json(self, raw_text):
        try:
            start = raw_text.find('{'); end = raw_text.rfind('}')
            if start == -1 or end == -1 or end < start: raise ValueError("Invalid JSON structure")
            json_str = raw_text[start:end+1]
            json_str = re.sub(r',\s*([\}\]])', r'\1', json_str)
            return json.loads(json_str)
        except Exception as e:
            print(f"Error: AI JSON response parsing failed. Error: {e}")
            return None

    def run_full_simulation(self, sim_id):
        profiler = EnvironmentProfiler()
        user_pc_profile = profiler.generate_profile()
        
        print("  [White Team] Tasking Threat Intelligence Analyst AI to build dynamic profile...")
        dynamic_security_profile = self.threat_analyst.research_and_build_profile(
            user_pc_profile.get("security_software", [])
        )
        
        arena = SimulationArena(user_pc_profile, "M&A_plan.xlsx", security_profile=dynamic_security_profile)
        
        digital_twin_state = json.loads(arena.get_current_state_for_ai())
        
        full_action_history = []
        print("\n--- [START] Trinity AI Dynamic Scenario Combat (Level 2) ---")

        attack_arsenal = [
            {"id": "T1059.001", "name": "PowerShell", "desc": "攻撃者はPowerShellを利用して、防御を回避しつつ悪意のある操作を実行する。"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "desc": "攻撃者は、外部から内部の侵害済み環境へツールやファイルを送り込む。"},
            {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "desc": "攻撃者は、レジストリにプログラムを登録し、OS起動時に自動実行させることで永続性を確保する。"},
            {"id": "T1005", "name": "Data from Local System", "desc": "攻撃者は、ローカルシステム上の特定のファイルや種類のデータを収集する。"}
        ]
        
        selected_scenario = random.choice(attack_arsenal)
        full_action_history.append(f"[SCENARIO SELECTED]: {selected_scenario['id']} ({selected_scenario['name']})")

        generic_red_team_prompt = self.scenario_generator.generate_red_team_prompt(
            selected_scenario['id'],
            selected_scenario['name'],
            selected_scenario['desc'],
            digital_twin_state
        )
        full_action_history.append(f"[DIRECTOR AI PROMPT]:\n{generic_red_team_prompt}")

        print("🔴 Red Team AI: Devising tactics based on Director AI's scenario...")
        
        # ★★★ 核心的な修正点：Red Teamへのプロンプトを強化 ★★★
        red_team_tactic_prompt = f"""
        あなたはWindows環境をターゲットとするRed Teamの実行担当AIです。以下の作戦シナリオに基づき、ターゲットシステムで実行すべき具体的な**Windowsコマンド**を考案し、JSON形式で出力してください。

        【作戦シナリオ】
        {generic_red_team_prompt}

        【思考の証跡】
        あなたの思考プロセスを簡潔に記述してください。

        【絶対厳守ルール】
        - あなたが最終的に出力するJSONの`tactic`キーの値は、必ず「{selected_scenario['id']}」でなければならない。
        - 生成するコマンドは、**必ずWindowsの`powershell.exe`または`cmd.exe`で実行可能**なものでなければならない。Linuxのコマンド（sh, lsなど）を生成してはならない。

        【出力フォーマット】
        ```json
        {{
          "tactic": "{selected_scenario['id']}",
          "parameters": {{
            "command_to_execute": "（考案した具体的なWindowsコマンド）"
          }}
        }}
        ```
        """
        red_team_tactic = self.red_team._think(red_team_tactic_prompt)
        full_action_history.append(f"[RED TEAM TACTIC]: {json.dumps(red_team_tactic, indent=2, ensure_ascii=False)}")
        
        if not red_team_tactic or red_team_tactic.get("error"):
            final_report_summary = "Exercise failed: Red Team was unable to devise a valid tactic."
        else:
            # 実行前に、Red Teamが正しいtactic IDを使ったか最終チェック
            if red_team_tactic.get("tactic") != selected_scenario['id']:
                 final_report_summary = f"Exercise failed: Red Team disobeyed orders. Expected {selected_scenario['id']} but got {red_team_tactic.get('tactic')}."
                 print(f"  [White Team] CRITICAL: Red Team disobeyed orders. Aborting mission.")
            else:
                arena.execute_red_team_tactic(red_team_tactic)
                blue_action = self.blue_team.generate_defense_action(arena.get_all_logs())
                if blue_action and blue_action.get("action") and blue_action.get("action") != "no_action":
                    print("--- Blue Team Intervenes! ---")
                    full_action_history.append(f"[BLUE TEAM ACTION]: {json.dumps(blue_action, ensure_ascii=False)}")
                    arena.execute_blue_team_action(blue_action)
                final_report_summary = "Exercise complete: Red Team executed an attack, and Blue Team responded."
        
        print("\n--- [END] Trinity AI Dynamic Scenario Combat (Level 2) ---")
        
        # ... (以降のレポート生成、保存処理は変更なし) ...
        final_logs = arena.get_all_logs()
        action_history_str = "\n".join(full_action_history)
        initial_context = self.threat_engine.get_latest_threat_brief()
        report = self._generate_report(initial_context, final_logs, action_history_str, final_report_summary)
        code = self._generate_code(action_history_str + final_logs)
        red_logs, blue_logs = self.split_logs_for_display(action_history_str, final_logs)
        saved_sim_id = self.db_manager.save_trinity_simulation(initial_context, red_logs, blue_logs, report)
        if code and saved_sim_id and "# コード生成に失敗しました。" not in code:
            self.save_generated_module(saved_sim_id, code)
            self.db_manager.add_system_learning(saved_sim_id, "New Analyzer Module", code)
        return {"red_team_output": red_logs, "blue_team_output": blue_logs, "white_team_report": report, "generated_code": code, "simulation_id": saved_sim_id }

    def split_logs_for_display(self, action_history, arena_logs): return action_history, arena_logs
    def save_generated_module(self, sim_id, code_content):
        save_dir = "src/analyzers/generated"; os.makedirs(save_dir, exist_ok=True)
        file_path = os.path.join(save_dir, f"dynamic_analyzer_sim_{sim_id}.py")
        with open(file_path, "w", encoding="utf-8") as f: f.write(code_content)
        print(f"✅ Self-evolution module saved to: {file_path}")

    def _generate_report(self, initial_context, final_logs, action_history, final_summary):
        print("⚪ White Team AI [Step 1/2]: Generating Final Report...")
        prompt = f"""
        あなたはCYBER-AEGISの最高監査AI、White Teamです。演習の全記録を分析し、人間が理解できる詳細な最終レポートを作成してください。
        【演習の最終結果】\n{final_summary}
        【全行動履歴と最終ログ】\n{action_history}\n{final_logs}
        【厳守ルール】
        - 以下の「レポートフォーマット例」に厳密に従い、Markdown形式で記述すること。
        - 演習全体の流れ、重要な発見、そして未来への教訓を明確に記述すること。
        - **レポートのテキストのみを出力し、JSONやコードを含めないこと。**
        【レポートフォーマット例】
        # CYBER-AEGIS 演習最終レポート
        ## 1. 演習サマリー
        （ここに演習全体の概要を記述。）
        ## 2. タイムライン分析
        * **[時刻]**: （例：Red Teamが偵察を開始。）
        * **[時刻]**: （例：Blue Teamがファイルの作成を検知。）
        ## 3. 結論と教訓
        今回の演習から、以下の3つの重要な教訓が得られた。
        1. **教訓1**: （例：EDRによるリアルタイム検知の有効性など）
        2. **教訓2**: （例：攻撃者の初期潜入経路としてDownloadsフォルダが多用される危険性など）
        3. **教訓3**: （例：AIによる自律的な攻防が、新たな脅威をあぶりだす可能性など）
        """
        return self.ollama.generate(self.model, prompt)

    def _generate_code(self, full_context):
        print("⚪ White Team AI [Step 2/2]: Generating Self-Evolution Module...")
        prompt = f"""
        あなたはCYBER-AEGISの自己進化を担当するAIエンジニアです。以下の演習ログ全体を分析し、観測された攻撃パターンを検知するためのシンプルなPythonアナライザーを作成してください。
        【演習ログ全文】\n{full_context}
        【厳守ルール】
        - **以下のテンプレートに厳密に従い、Pythonコードのみを出力すること。**
        - 解説や言い訳、JSONなど、コード以外のテキストは一切含めないこと。
        【コードテンプレート】
        ```python
        import re
        class GeneratedAnalyzer:
            def analyze(self, logs: str) -> bool:
                # ログから観測された攻撃の痕跡を検知するロジックを記述
                if re.search(r'powershell.exe', logs, re.IGNORECASE):
                    return True
                if re.search(r'reg add', logs, re.IGNORECASE): # レジストリ操作の検知例
                    return True
                return False
        ```
        """
        raw_code = self.ollama.generate(self.model, prompt)
        match = re.search(r'```(?:python)?\s*([\s\S]+)\s*```', raw_code)
        if match: return match.group(1).strip()
        return raw_code.strip()
