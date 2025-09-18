import re
from src.collectors.github_collector import GithubCollector
from src.collectors.x_collector import XCollector
from src.collectors.discord_collector import run_discord_collector_sync
from src.collectors.pastebin_collector import run_pastebin_collector_sync
from src.database.db_manager import DBManager
from src.utils.config_manager import ConfigManager
from src.core.relevance_analyzer import RelevanceAnalyzer
from src.core.community_analyzer import CommunityAnalyzer
from datetime import datetime, timezone

class SNSManager:
    def __init__(self):
        self.config = ConfigManager()
        self.db = DBManager()
        self.github_collector = GithubCollector()
        self.community_analyzer = CommunityAnalyzer()
        try:
            self.x_collector = XCollector()
            self.x_enabled = True
        except ValueError as e:
            print(f"[SNSManager] X Collectorの初期化に失敗しました: {e}")
            self.x_collector = None
            self.x_enabled = False

    def scan_all_sources(self, keywords_map):
        all_collected_text = []
        if 'github' in keywords_map and keywords_map.get('github'):
            gh_leaks = self.github_collector.fetch_leaks(keywords_map['github'])
            for leak in gh_leaks:
                self.db.add_github_leak(leak)
                all_collected_text.append(leak.get('repository', ''))
                all_collected_text.extend(leak.get('matches', []))
        if self.x_enabled and 'x' in keywords_map and keywords_map.get('x'):
            x_leaks = self.x_collector.fetch_leaks(keywords_map['x'])
            for leak in x_leaks:
                self.db.add_x_leak(leak)
                all_collected_text.append(leak.get('tweet_text', ''))
        
        if all_collected_text:
            self._discover_and_add_discord_invites(all_collected_text)

        if 'pastebin' in keywords_map and keywords_map['pastebin']:
            print(f"[SNSManager] Scanning Pastebin...")
            pastebin_leaks = run_pastebin_collector_sync()
            for leak in pastebin_leaks:
                self.db.add_pastebin_leak(leak)
            print(f"[SNSManager] Found {len(pastebin_leaks)} potential leaks on Pastebin.")

        all_discord_invites = self.config.get_list('SNS_MONITOR', 'discord_server_invites')
        if not all_discord_invites:
            print("[SNSManager] No Discord servers in the knowledge base to scan.")
            return

        batch_to_scan = self.db.get_prioritized_server_batch(all_discord_invites, batch_size=5)
        
        print(f"[SNSManager] Starting prioritized Discord analysis for a batch of {len(batch_to_scan)} servers...")
        all_server_data = run_discord_collector_sync(batch_to_scan)
        
        for server_data in all_server_data:
            server_info = server_data['server_info']
            messages = server_data['messages']
            
            if server_data.get('status') == 'FAILED':
                server_id = server_info.get('id', server_info['invite_code'])
                self.db.update_community_score(
                    server_id=server_id, 
                    server_name=server_info.get('name', 'N/A'),
                    invite_code=server_info['invite_code'], 
                    score=0, keywords=[], status='FAILED'
                )
                print(f"[SNSManager]  - Server '{server_info['invite_code']}' failed to scan. It will be deprioritized.")
                continue

            score, hit_keywords = self.community_analyzer.analyze_server_messages(messages)
            self.db.update_community_score(
                server_id=server_info['id'], server_name=server_info['name'],
                invite_code=server_info['invite_code'], score=score, keywords=hit_keywords,
                status='SUCCESS'
            )
            print(f"[SNSManager]  - Server '{server_info['name']}' analyzed. Danger Score: {score}")

            if 'discord' in keywords_map and keywords_map.get('discord'):
                personal_keywords = keywords_map['discord']
                for message in messages:
                    for keyword in personal_keywords:
                        if keyword.lower() in message['message_text'].lower():
                            self.db.add_discord_leak({
                                "timestamp": datetime.now(timezone.utc).isoformat(), "source": "Discord", "keyword": keyword,
                                "server": server_info['name'], "channel": message['channel_name'], "author": message['author'], 
                                "message_text": message['message_text'],
                                "url": f"https://discord.com/channels/{server_info.get('id', 'N/A')}/{message.get('channel_id', 'N/A')}/{message.get('message_id', 'N/A')}"
                            })
                            break
        
        print(f"[SNSManager] Scan batch complete. Full knowledge base contains {len(all_discord_invites)} servers.")

    def _discover_and_add_discord_invites(self, text_list):
        invite_pattern = r'discord\.gg/([a-zA-Z0-9_-]+)'
        found_codes = set(re.findall(invite_pattern, " ".join(text_list)))
        if found_codes:
            current_list = self.config.get_list('SNS_MONITOR', 'discord_server_invites')
            new_codes = [code for code in found_codes if code not in current_list]
            if new_codes:
                print(f"[SNSManager] Discovered {len(new_codes)} new Discord invite codes.")
                self.config.add_to_list('SNS_MONITOR', 'discord_server_invites', new_codes)

    def get_all_leaks_unified(self, sort_by_relevance=True):
        gh_leaks = self.db.get_all_github_leaks()
        x_leaks = self.db.get_all_x_leaks() if self.x_enabled else []
        discord_leaks = self.db.get_all_discord_leaks()
        pastebin_leaks = self.db.get_all_pastebin_leaks()
        all_leaks = gh_leaks + x_leaks + discord_leaks + pastebin_leaks
        if sort_by_relevance and all_leaks:
            network_events = self.db.get_all_network_incidents(limit=200)
            file_events = self.db.get_all_file_events(limit=500)
            analyzer = RelevanceAnalyzer(network_events, file_events)
            sorted_leaks = analyzer.analyze_and_sort(all_leaks)
            return sorted_leaks
        else:
            all_leaks.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return all_leaks

    def get_keywords(self):
        gh_keys_str = self.config.get('SNS_MONITOR', 'github_keywords', fallback='')
        x_keys_str = self.config.get('SNS_MONITOR', 'x_keywords', fallback='')
        discord_keys_str = self.config.get('SNS_MONITOR', 'discord_keywords', fallback='')
        pastebin_keys_str = self.config.get('SNS_MONITOR', 'pastebin_keywords', fallback='')
        return {
            'github': [k.strip() for k in gh_keys_str.split(',') if k.strip()],
            'x': [k.strip() for k in x_keys_str.split(',') if k.strip()],
            'discord': [k.strip() for k in discord_keys_str.split(',') if k.strip()],
            'pastebin': [k.strip() for k in pastebin_keys_str.split(',') if k.strip()]
        }

    def save_keywords(self, keywords_map):
        if 'github' in keywords_map: self.config.set('SNS_MONITOR', 'github_keywords', ",".join(keywords_map['github']))
        if 'x' in keywords_map: self.config.set('SNS_MONITOR', 'x_keywords', ",".join(keywords_map['x']))
        if 'discord' in keywords_map: self.config.set('SNS_MONITOR', 'discord_keywords', ",".join(keywords_map['discord']))
        if 'pastebin' in keywords_map: self.config.set('SNS_MONITOR', 'pastebin_keywords', ",".join(keywords_map['pastebin']))
        self.config.save()