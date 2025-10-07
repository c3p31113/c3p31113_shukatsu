import sqlite3
import json
import os
import threading
from src.utils.config_manager import ConfigManager
from datetime import datetime, timezone, timedelta

# SQLAlchemy関連のライブラリをインポート
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
# models.pyで定義するBaseクラスとSigmaMatchクラスをインポート
from .models import Base, SigmaMatch

class DBManager:
    # クラス全体で単一のインスタンスを共有するための変数 (シングルトンパターン)
    _instance = None
    _engine = None
    _Session = None
    _lock = None

    def __new__(cls):
        # インスタンスがまだ作成されていない場合にのみ初期化処理を行う
        if cls._instance is None:
            cls._instance = super(DBManager, cls).__new__(cls)
            
            config = ConfigManager()
            db_path = config.get('DATABASE', 'path', fallback='aegis.db')
            
            db_uri = f'sqlite:///{os.path.abspath(db_path)}'
            cls._engine = create_engine(db_uri, connect_args={'check_same_thread': False})
            
            cls._Session = sessionmaker(bind=cls._engine)

            cls._instance.conn = sqlite3.connect(
                db_path, 
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                check_same_thread=False
            )
            cls._instance.conn.row_factory = sqlite3.Row
            
            cls._lock = threading.Lock()

            cls._instance.setup_tables()
            
        return cls._instance

    def setup_tables(self):
        with self._lock:
            cursor = self.conn.cursor()
            Base.metadata.create_all(self._engine)

            # --- 全てのテーブル定義 ---
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, process_name TEXT,
                    event_time TEXT NOT NULL, destination TEXT, threat_level TEXT, status TEXT, description TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, event_type TEXT,
                    file_path TEXT NOT NULL, event_time TEXT NOT NULL, threat_level TEXT, description TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS github_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source TEXT, keyword TEXT,
                    repository TEXT, file_path TEXT, url TEXT UNIQUE, matches TEXT,
                    risk_level TEXT, confidence REAL, ai_report TEXT, status TEXT DEFAULT 'NEW'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS x_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source TEXT, keyword TEXT,
                    author TEXT, tweet_text TEXT, url TEXT UNIQUE, tweet_created_at TEXT,
                    risk_level TEXT, confidence REAL, ai_report TEXT, status TEXT DEFAULT 'NEW'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discord_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source TEXT, keyword TEXT,
                    server TEXT, channel TEXT, author TEXT, message_text TEXT, url TEXT UNIQUE,
                    risk_level TEXT, confidence REAL, ai_report TEXT, status TEXT DEFAULT 'NEW'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS community_threat_scores (
                    server_id TEXT PRIMARY KEY, server_name TEXT, invite_code TEXT,
                    danger_score INTEGER, last_analyzed_at TEXT, hit_keywords TEXT,
                    status TEXT DEFAULT 'UNKNOWN'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pastebin_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source TEXT, keyword TEXT,
                    title TEXT, url TEXT UNIQUE, content_preview TEXT,
                    risk_level TEXT, confidence REAL, ai_report TEXT, status TEXT DEFAULT 'NEW'
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL,
                    is_user INTEGER NOT NULL, -- 1 for user, 0 for AI
                    text TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trinity_ai_simulations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    simulation_time TEXT NOT NULL,
                    context_data TEXT,
                    red_team_output TEXT,
                    blue_team_output TEXT,
                    white_team_report TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_learnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    learning_time TEXT NOT NULL,
                    source_simulation_id INTEGER,
                    learning_type TEXT,
                    learning_content TEXT,
                    FOREIGN KEY (source_simulation_id) REFERENCES trinity_ai_simulations(id)
                )
            ''')
            
            self.conn.commit()
            cursor.close()

    def create_conversation(self, title):
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            query = "INSERT INTO conversations (title, created_at) VALUES (?, ?)"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (title, timestamp))
                self.conn.commit()
                last_id = cursor.lastrowid
                return last_id
            except sqlite3.Error as e:
                print(f"Error creating conversation: {e}")
                return None
            finally:
                cursor.close()

    def get_all_conversations(self):
        query = "SELECT id, title FROM conversations ORDER BY created_at DESC"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return [{"id": r[0], "title": r[1]} for r in rows]

    def add_message_to_conversation(self, conv_id, message_data):
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            is_user_int = 1 if message_data['is_user'] else 0
            query = "INSERT INTO messages (conversation_id, is_user, text, timestamp) VALUES (?, ?, ?, ?)"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (conv_id, is_user_int, message_data['text'], timestamp))
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"Error adding message: {e}")
            finally:
                cursor.close()

    def get_messages_for_conversation(self, conv_id):
        query = "SELECT text, is_user FROM messages WHERE conversation_id = ? ORDER BY timestamp ASC"
        cursor = self.conn.cursor()
        cursor.execute(query, (conv_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [{"text": r[0], "is_user": bool(r[1])} for r in rows]

    def update_conversation_title(self, conv_id, new_title):
        with self._lock:
            query = "UPDATE conversations SET title = ? WHERE id = ?"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (new_title, conv_id))
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"Error updating title: {e}")
            finally:
                cursor.close()
            
    def delete_conversation(self, conv_id):
        with self._lock:
            query = "DELETE FROM conversations WHERE id = ?"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (conv_id,))
                self.conn.commit()
                return True
            except sqlite3.Error as e:
                print(f"Error deleting conversation: {e}")
                return False
            finally:
                cursor.close()

    def add_network_incident(self, incident_data):
        with self._lock:
            query = '''INSERT INTO network_incidents (event_id, process_name, event_time, destination, threat_level, status, description) VALUES (?, ?, ?, ?, ?, ?, ?)'''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (incident_data.get('id'), incident_data.get('name'), incident_data.get('time'), incident_data.get('destination'), incident_data.get('threat_level'), incident_data.get('status'), incident_data.get('description')))
                self.conn.commit()
            finally:
                cursor.close()

    def add_file_event(self, event_data):
        with self._lock:
            query = '''INSERT INTO file_events (event_id, event_type, file_path, event_time, threat_level, description) VALUES (?, ?, ?, ?, ?, ?)'''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (event_data.get('id'), event_data.get('event_type'), event_data.get('path'), event_data.get('time'), event_data.get('threat_level'), event_data.get('description')))
                self.conn.commit()
            finally:
                cursor.close()
        
    def add_github_leak(self, leak_data):
        with self._lock:
            query = '''INSERT OR IGNORE INTO github_leaks (timestamp, source, keyword, repository, file_path, url, matches) VALUES (?, ?, ?, ?, ?, ?, ?)'''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (leak_data.get('timestamp'), leak_data.get('source'), leak_data.get('keyword'), leak_data.get('repository'), leak_data.get('file_path'), leak_data.get('url'), json.dumps(leak_data.get('matches', []))))
                self.conn.commit()
                return cursor.lastrowid > 0
            finally:
                cursor.close()

    def add_x_leak(self, leak_data):
        with self._lock:
            query = '''INSERT OR IGNORE INTO x_leaks (timestamp, source, keyword, author, tweet_text, url, tweet_created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (leak_data.get('timestamp'), leak_data.get('source'), leak_data.get('keyword'), leak_data.get('author'), leak_data.get('tweet_text'), leak_data.get('url'), leak_data.get('tweet_created_at')))
                self.conn.commit()
                return cursor.lastrowid > 0
            finally:
                cursor.close()

    def add_discord_leak(self, leak_data):
        with self._lock:
            query = '''INSERT OR IGNORE INTO discord_leaks (timestamp, source, keyword, server, channel, author, message_text, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (leak_data.get('timestamp'), leak_data.get('source'), leak_data.get('keyword'), leak_data.get('server'), leak_data.get('channel'), leak_data.get('author'), leak_data.get('message_text'), leak_data.get('url')))
                self.conn.commit()
                return cursor.lastrowid > 0
            finally:
                cursor.close()
        
    def add_pastebin_leak(self, leak_data):
        with self._lock:
            query = '''
                INSERT OR IGNORE INTO pastebin_leaks (timestamp, source, keyword, title, url, content_preview)
                VALUES (?, ?, ?, ?, ?, ?)
            '''
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (
                    leak_data.get('timestamp'), leak_data.get('source'), leak_data.get('keyword'),
                    leak_data.get('title'), leak_data.get('url'), leak_data.get('content_preview')
                ))
                self.conn.commit()
                return cursor.lastrowid > 0
            finally:
                cursor.close()
    
    def update_leak_with_ai_analysis(self, unified_id, analysis_result):
        with self._lock:
            source, leak_id = self._get_source_and_id(unified_id)
            if not source: return
            table_name = f"{source}_leaks"
            query = f"UPDATE {table_name} SET risk_level = ?, confidence = ?, ai_report = ?, status = 'ANALYZED' WHERE id = ?"
            report_str = json.dumps(analysis_result.get('report_data', {}), ensure_ascii=False)
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (analysis_result.get('risk_level'), analysis_result.get('confidence'), report_str, leak_id))
                self.conn.commit()
            finally:
                cursor.close()

    def update_leak_status(self, unified_id, status):
        with self._lock:
            source, leak_id = self._get_source_and_id(unified_id)
            if not source: return
            table_name = f"{source}_leaks"
            query = f"UPDATE {table_name} SET status = ? WHERE id = ?"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (status, leak_id))
                self.conn.commit()
            finally:
                cursor.close()

    def update_community_score(self, server_id, server_name, invite_code, score, keywords, status):
        with self._lock:
            query = '''
                INSERT INTO community_threat_scores (server_id, server_name, invite_code, danger_score, last_analyzed_at, hit_keywords, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    server_name = excluded.server_name, danger_score = excluded.danger_score,
                    last_analyzed_at = excluded.last_analyzed_at, hit_keywords = excluded.hit_keywords,
                    status = excluded.status
            '''
            timestamp = datetime.now(timezone.utc).isoformat()
            keywords_str = json.dumps(keywords, ensure_ascii=False)
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (server_id, server_name, invite_code, score, timestamp, keywords_str, status))
                self.conn.commit()
            finally:
                cursor.close()

    def get_high_threat_communities(self, limit=20):
        query = "SELECT server_name, invite_code, danger_score, last_analyzed_at, hit_keywords FROM community_threat_scores ORDER BY danger_score DESC LIMIT ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return [{'name': r[0], 'invite': r[1], 'score': r[2], 'analyzed_at': r[3], 'keywords': json.loads(r[4]) if r[4] else []} for r in rows]
    
    def get_prioritized_server_batch(self, all_invite_codes, batch_size=5):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT invite_code, danger_score, last_analyzed_at, status FROM community_threat_scores")
            db_servers = {row[0]: {'score': row[1], 'last_scan': datetime.fromisoformat(row[2]), 'status': row[3]} for row in cursor.fetchall()}
            cursor.close()
            
            unscanned_servers = []
            priority_servers = []
            
            one_day_ago = datetime.now(timezone.utc) - timedelta(days=1)
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)

            for code in all_invite_codes:
                if code in db_servers:
                    server = db_servers[code]
                    priority = 4
                    if server['status'] == 'FAILED' and server['last_scan'] > one_hour_ago:
                        priority = 5
                    elif server['score'] >= 70:
                        priority = 1
                    elif server['last_scan'] < one_day_ago:
                        priority = 2
                    priority_servers.append({'code': code, 'priority': priority, 'last_scan': server['last_scan']})
                else:
                    unscanned_servers.append(code)

            priority_servers.sort(key=lambda x: (x['priority'], x['last_scan']))
            
            batch = unscanned_servers[:batch_size]
            
            if len(batch) < batch_size:
                needed = batch_size - len(batch)
                batch.extend([s['code'] for s in priority_servers[:needed]])
            
            print(f"[DBManager] Prioritized batch of {len(batch)} servers selected. ({len(unscanned_servers)} new, {len(priority_servers)} known)")
            return batch
        except Exception as e:
            print(f"[DBManager] Error prioritizing server batch: {e}")
            return all_invite_codes[:batch_size]

    def get_all_network_incidents(self, limit=500):
        query = "SELECT event_id, process_name, event_time, destination, threat_level, status, description FROM network_incidents ORDER BY id DESC LIMIT ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return [{'id': r[0], 'name': r[1], 'time': r[2], 'destination': r[3], 'threat_level': r[4], 'status': r[5], 'description': r[6]} for r in rows]

    def get_all_file_events(self, limit=500):
        query = "SELECT event_id, event_type, file_path, event_time, threat_level, description FROM file_events ORDER BY id DESC LIMIT ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return [{'id': r[0], 'event_type': r[1], 'path': r[2], 'time': r[3], 'threat_level': r[4], 'description': r[5]} for r in rows]

    def get_all_github_leaks(self):
        query = "SELECT id, timestamp, source, keyword, repository, file_path, url, matches, risk_level, confidence, ai_report, status FROM github_leaks ORDER BY id DESC"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return self._format_leak_rows(rows, 'github')

    def get_all_x_leaks(self):
        query = "SELECT id, timestamp, source, keyword, author, tweet_text, url, tweet_created_at, risk_level, confidence, ai_report, status FROM x_leaks ORDER BY id DESC"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return self._format_leak_rows(rows, 'x')

    def get_all_discord_leaks(self):
        query = "SELECT id, timestamp, source, keyword, server, channel, author, message_text, url, risk_level, confidence, ai_report, status FROM discord_leaks ORDER BY id DESC"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return self._format_leak_rows(rows, 'discord')
        
    def get_all_pastebin_leaks(self):
        query = "SELECT id, timestamp, source, keyword, title, url, content_preview, risk_level, confidence, ai_report, status FROM pastebin_leaks ORDER BY id DESC"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return self._format_leak_rows(rows, 'pastebin')

    def get_pending_leaks(self):
        query = "SELECT id, timestamp, source, keyword, repository, file_path, url, matches, risk_level, confidence, ai_report, status FROM github_leaks WHERE status = 'PENDING'"
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return self._format_leak_rows(rows, 'github')

    def get_threat_level_distribution(self):
        query = "SELECT threat_level, COUNT(*) FROM (SELECT threat_level FROM network_incidents UNION ALL SELECT threat_level FROM file_events) WHERE threat_level IS NOT NULL GROUP BY threat_level;"
        cursor = self.conn.cursor()
        cursor.execute(query)
        result = dict(cursor.fetchall())
        cursor.close()
        return result
    
    def get_total_event_counts(self):
        cursor = self.conn.cursor()
        net_count = cursor.execute("SELECT COUNT(*) FROM network_incidents").fetchone()[0]
        file_count = cursor.execute("SELECT COUNT(*) FROM file_events").fetchone()[0]
        cursor.close()
        return {"network": net_count, "file": file_count}

    def _get_source_and_id(self, unified_id):
        parts = unified_id.split('-', 1)
        if len(parts) == 2:
            source_map = {'gh': 'github', 'x': 'x', 'dsc': 'discord', 'pst': 'pastebin'}
            db_source = source_map.get(parts[0])
            if db_source:
                return db_source, int(parts[1])
        return None, None

    def _format_leak_rows(self, rows, source):
        leaks = []
        for r in rows:
            try:
                # sqlite3.Rowオブジェクトをミュータブルな辞書に変換
                leak_item = dict(r)
                db_id = leak_item['id']

                # 整数の 'id' をフォーマットされた文字列の 'id' で上書きする
                if source == 'github':
                    leak_item['id'] = f"gh-{db_id}"
                    leak_item['matches'] = json.loads(leak_item.get('matches') or '[]')
                elif source == 'x':
                    leak_item['id'] = f"x-{db_id}"
                elif source == 'discord':
                    leak_item['id'] = f"dsc-{db_id}"
                elif source == 'pastebin':
                    leak_item['id'] = f"pst-{db_id}"
                
                ai_report_raw = leak_item.get('ai_report')
                if ai_report_raw:
                    try:
                        report_data = json.loads(ai_report_raw)
                        leak_item['ai_report'] = {"report_data": report_data}
                    except (json.JSONDecodeError, TypeError):
                        leak_item['ai_report'] = {"report_data": {'error_report': f"DBから不正な形式のレポートを読込: {ai_report_raw}"}}
                else:
                    leak_item['ai_report'] = {"report_data": {}}
                
                leaks.append(leak_item)
            except (IndexError, KeyError) as e:
                print(f"[DBManager] Warning: Row with incorrect columns/keys for source '{source}'. Error: {e}. Skipping.")
                continue
        return leaks

    def get_event_by_id(self, event_id):
        tables_to_search = ['file_events', 'network_incidents']
        cursor = self.conn.cursor()
        try:
            for table in tables_to_search:
                try:
                    query = f"SELECT * FROM {table} WHERE event_id = ?"
                    cursor.execute(query, (event_id,))
                    row = cursor.fetchone()
                    if row:
                        return dict(row)
                except sqlite3.Error as e:
                    print(f"データベースエラー ({table}検索中): {e}")
                    continue
            return None
        finally:
            cursor.close()


    def save_trinity_simulation(self, context, red_output, blue_output, white_report):
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            query = """
                INSERT INTO trinity_ai_simulations 
                (simulation_time, context_data, red_team_output, blue_team_output, white_team_report) 
                VALUES (?, ?, ?, ?, ?)
            """
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (timestamp, context, red_output, blue_output, white_report))
                self.conn.commit()
                return cursor.lastrowid
            except sqlite3.Error as e:
                print(f"Error saving trinity simulation: {e}")
                return None
            finally:
                cursor.close()

    def get_all_trinity_simulations(self):
        query = "SELECT id, simulation_time, red_team_output, blue_team_output, white_team_report FROM trinity_ai_simulations ORDER BY simulation_time DESC"
        cursor = self.conn.cursor()
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"Error fetching trinity simulations: {e}")
            return []
        finally:
            cursor.close()

    def get_trinity_simulation_by_id(self, sim_id):
        """指定されたIDのシミュレーション結果を1件取得する"""
        query = "SELECT * FROM trinity_ai_simulations WHERE id = ?"
        cursor = self.conn.cursor()
        try:
            cursor.execute(query, (sim_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            print(f"Error fetching trinity simulation by ID {sim_id}: {e}")
            return None
        finally:
            cursor.close()

    def add_system_learning(self, sim_id, learning_type, content):
        with self._lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            query = "INSERT INTO system_learnings (learning_time, source_simulation_id, learning_type, learning_content) VALUES (?, ?, ?, ?)"
            cursor = self.conn.cursor()
            try:
                cursor.execute(query, (timestamp, sim_id, learning_type, content))
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"Error adding system learning: {e}")
            finally:
                cursor.close()

    def get_system_learning_by_sim_id(self, sim_id):
        query = "SELECT learning_content FROM system_learnings WHERE source_simulation_id = ? AND learning_type = 'New Analyzer Module' LIMIT 1"
        cursor = self.conn.cursor()
        try:
            cursor.execute(query, (sim_id,))
            row = cursor.fetchone()
            return row[0] if row else None
        except sqlite3.Error as e:
            print(f"Error fetching learning for sim_id {sim_id}: {e}")
            return None
        finally:
            cursor.close()
            
    def delete_trinity_simulation(self, sim_id):
        with self._lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("DELETE FROM system_learnings WHERE source_simulation_id = ?", (sim_id,))
                cursor.execute("DELETE FROM trinity_ai_simulations WHERE id = ?", (sim_id,))
                self.conn.commit()
                return True
            except sqlite3.Error as e:
                print(f"Error deleting trinity simulation for ID {sim_id}: {e}")
                return False
            finally:
                cursor.close()

    def __del__(self):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

def get_session():
    if DBManager._Session is None:
        DBManager()
    return DBManager._Session()

def init_db_schema():
    DBManager()
