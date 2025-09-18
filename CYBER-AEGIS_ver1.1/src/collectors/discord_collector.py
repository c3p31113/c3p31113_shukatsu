import requests
from datetime import datetime, timezone
from src.utils.config_manager import ConfigManager
import time
import random

class DiscordCollector:
    def __init__(self):
        self.config = ConfigManager()
        self.base_delay_seconds = 20

    def fetch_leaks(self, server_invites_batch):
        all_server_data = []
        
        print(f"[DiscordCollector] Received a batch of {len(server_invites_batch)} servers to scan.")

        for invite_code in server_invites_batch:
            human_like_delay = self.base_delay_seconds + random.uniform(0, 10)
            print(f"[DiscordCollector] Waiting for {human_like_delay:.2f} seconds before scraping '{invite_code}'...")
            time.sleep(human_like_delay)

            server_info = self._get_server_data_from_invite(invite_code)
            
            if not server_info or 'error' in server_info:
                all_server_data.append({
                    'server_info': {'invite_code': invite_code},
                    'messages': [],
                    'status': 'FAILED'
                })
                continue

            server_id, server_name = server_info.get('id'), server_info.get('name')
            messages_from_this_server = []
            channels = self._get_server_public_channels(server_id)
            
            for channel in channels:
                channel_id, channel_name = channel.get('id'), channel.get('name')
                
                messages = self._get_channel_messages(channel_id)
                for message in messages:
                    author = message.get('author', {})
                    messages_from_this_server.append({
                        "message_id": message.get('id'),
                        "channel_id": channel_id,
                        "message_text": message.get('content', ''),
                        "author": f"{author.get('username', 'N/A')}#{author.get('discriminator', '0000')}",
                        "channel_name": channel_name,
                        "timestamp": message.get('timestamp')
                    })
                time.sleep(random.uniform(1, 3)) 
            
            all_server_data.append({
                'server_info': {'id': server_id, 'name': server_name, 'invite_code': invite_code},
                'messages': messages_from_this_server,
                'status': 'SUCCESS'
            })
            
        return all_server_data

    def _get_server_data_from_invite(self, invite_code):
        try:
            url = f"https://discord.com/api/v9/invites/{invite_code}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            return response.json().get('guild')
        except requests.RequestException as e:
            print(f"[DiscordCollector] Error fetching server info for '{invite_code}': {e}")
            return {'error': str(e), 'status_code': e.response.status_code if hasattr(e, 'response') and e.response else None}

    def _get_server_public_channels(self, server_id):
        try:
            url = f"https://discord.com/api/v9/guilds/{server_id}/channels"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            return [ch for ch in response.json() if ch['type'] == 0 and not ch.get('permission_overwrites')]
        except requests.RequestException:
            return []

    def _get_channel_messages(self, channel_id, limit=50):
        try:
            url = f"https://discord.com/api/v9/channels/{channel_id}/messages?limit={limit}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return []

def run_discord_collector_sync(server_invites_batch):
    if not server_invites_batch:
        return []
    collector = DiscordCollector()
    return collector.fetch_leaks(server_invites_batch)