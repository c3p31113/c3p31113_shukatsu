import re
import socket
import ssl
from datetime import datetime, timedelta

class RelevanceAnalyzer:
    def __init__(self, network_events, file_events):
        self.network_events = network_events
        self.file_events = file_events
        self.local_keywords = self._extract_local_keywords()
        self.local_ips = {event.get('destination') for event in network_events if event.get('destination')}
        self.safe_ip_cache = {}

    def _verify_ssl_certificate(self, ip_str):
        if ip_str in self.safe_ip_cache: return self.safe_ip_cache[ip_str]
        known_good_subjects = ['*.google.com', '*.1e100.net', '*.googleusercontent.com', '*.microsoft.com', '*.windowsupdate.com', '*.apple.com', '*.icloud.com', '*.amazonaws.com', '*.github.com', '*.github.io', '*.cloudflare.com', '*.x.com', '*.twitter.com', '*.discord.gg']
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip_str, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip_str) as ssock:
                    cert = ssock.getpeercert()
            valid_from = datetime.strptime(cert.get('notBefore'), '%b %d %H:%M:%S %Y %Z')
            valid_to = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
            if not (valid_from < datetime.utcnow() < valid_to):
                self.safe_ip_cache[ip_str] = False; return False
            subject = dict(x[0] for x in cert.get('subject', []))
            common_name = subject.get('commonName', '')
            if any(re.match(pattern.replace('.', r'\.').replace('*', '.*'), common_name) for pattern in known_good_subjects):
                print(f"[RelevanceAnalyzer] SSL証明書を検証し、安全なIPを確認: {ip_str} ({common_name})")
                self.safe_ip_cache[ip_str] = True; return True
            self.safe_ip_cache[ip_str] = False; return False
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError):
            self.safe_ip_cache[ip_str] = False; return False

    def _extract_local_keywords(self):
        keywords = set()
        for event in self.network_events:
            if event.get('name'): keywords.add(event['name'].split('.')[0].lower())
        for event in self.file_events:
            if event.get('path'):
                parts = re.split(r'[\\/]', event['path'])
                for part in parts:
                    if len(part) > 4: keywords.add(part.lower())
        return keywords

    def analyze_and_sort(self, leaks):
        scored_leaks = []
        for leak in leaks:
            score, reasons = self._calculate_score(leak)
            leak['relevance_score'] = score
            leak['relevance_reasons'] = reasons
            scored_leaks.append(leak)
        scored_leaks.sort(key=lambda x: x['relevance_score'], reverse=True)
        return scored_leaks

    def _calculate_score(self, leak):
        score, reasons = 0, []
        content_parts = []
        if leak.get('id', '').startswith('gh-'):
            content_parts.extend([leak.get('repository', ''), leak.get('file_path', '')])
            content_parts.extend(leak.get('matches', []))
        elif leak.get('id', '').startswith('x-'):
            content_parts.append(leak.get('tweet_text', ''))
        elif leak.get('id', '').startswith('dsc-'):
            content_parts.append(leak.get('message_text', ''))
        content_str = ' '.join(content_parts).lower()

        for local_key in self.local_keywords:
            if local_key in content_str:
                score += 30; reasons.append(f"PC内の活動記録「{local_key}」と一致")
        found_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content_str)
        if found_ips:
            for ip in set(found_ips):
                if not self._verify_ssl_certificate(ip) and ip in self.local_ips:
                    score += 50; reasons.append(f"要注意IP「{ip}」への接続記録と一致")
        try:
            leak_time_str = leak.get('timestamp') or leak.get('message_date')
            leak_time = datetime.fromisoformat(leak_time_str.replace('Z', '+00:00'))
            if datetime.now(leak_time.tzinfo) - leak_time < timedelta(days=7):
                score += 15; reasons.append("1週間以内に発生")
        except (ValueError, TypeError): pass
        risk = leak.get('risk_level')
        if risk == "CRITICAL": score *= 1.5
        elif risk == "HIGH": score *= 1.2
        return min(int(score), 100), list(set(reasons))