# src/core_ai/threat_engine.py
import feedparser
import datetime
import requests

class ThreatEngine:
    def get_latest_threat_brief(self):
        """
        RSSフィードと基本的なシステムプロファイルから、
        AIが状況認識するための初期コンテキストを生成する。
        """
        rss_url = "http://feeds.feedburner.com/TheHackersNews"
        try:
            response = requests.get(rss_url, timeout=10)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            threat_headlines = [f"- {entry.title}" for entry in feed.entries[:5] if hasattr(entry, 'title')]
            dynamic_threat_info = "\n        ".join(threat_headlines) if threat_headlines else "- (最新の脅威ニュースは取得できませんでした)"
        except Exception as e:
            print(f"Error fetching RSS feed: {e}")
            dynamic_threat_info = "- (最新の脅威ニュースの取得に失敗しました)"

        today = datetime.date.today()
        briefing = f"""
        ### CYBER-AEGIS Threat Intelligence Briefing - {today}

        **1. 最新のサイバーセキュリティヘッドライン:**
        {dynamic_threat_info}
        
        **2. ターゲットシステムのプロファイル（ユーザー環境）:**
        - OS: Windows 11 Enterprise (完全パッチ適用済み)
        - 主要ソフトウェア: Microsoft Office 365, Adobe Acrobat Reader, カスタムERPクライアント
        - ユーザープロファイル: 経理部門に所属し、機密性の高い財務データを扱う
        - ネットワーク: EDR（Endpoint Detection and Response）による監視下にある
        - 目標: ユーザーのDocumentsフォルダから 'M&A_plan.xlsx' という名前のファイルを窃取する
        """
        return briefing.strip()