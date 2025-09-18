# src/tools/google_search.py
import requests
from bs4 import BeautifulSoup
import time

# ユーザーエージェントを設定して、ボットと判定されるのを避ける
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

class PerQueryResult:
    """単一の検索結果を格納するクラス"""
    def __init__(self, index, source_title, url, snippet, publication_time=None):
        self.index = index
        self.source_title = source_title
        self.url = url
        self.snippet = snippet
        self.publication_time = publication_time

class SearchResults:
    """単一クエリに対する検索結果全体を格納するクラス"""
    def __init__(self, query, results):
        self.query = query
        self.results = results

def search(queries: list[str]) -> list[SearchResults]:
    """
    Google検索を実行し、結果をパースして返す。
    """
    all_results = []
    for query in queries:
        try:
            print(f"  [Tool] Executing Google Search for: '{query}'")
            # Google検索のURLを組み立てる
            search_url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
            
            # Webページを取得
            response = requests.get(search_url, headers=HEADERS, timeout=15)
            response.raise_for_status() # エラーがあれば例外を発生

            # BeautifulSoupでHTMLをパース
            soup = BeautifulSoup(response.text, 'html.parser')

            # 検索結果の各ブロックを抽出
            search_containers = soup.find_all('div', class_='g')
            
            per_query_results = []
            for i, container in enumerate(search_containers[:5]): # 上位5件に限定
                title_element = container.find('h3')
                link_element = container.find('a')
                snippet_element = container.find('div', style="display:block")

                if title_element and link_element and snippet_element:
                    title = title_element.get_text()
                    url = link_element['href']
                    snippet = snippet_element.get_text()
                    
                    result = PerQueryResult(
                        index=str(i + 1),
                        source_title=title,
                        url=url,
                        snippet=snippet
                    )
                    per_query_results.append(result)
            
            all_results.append(SearchResults(query=query, results=per_query_results))
            time.sleep(1) # 連続リクエストを避けるための短い待機

        except requests.exceptions.RequestException as e:
            print(f"  [Tool Error] Failed to search for '{query}': {e}")
            all_results.append(SearchResults(query=query, results=[]))
        except Exception as e:
            print(f"  [Tool Error] An unexpected error occurred during search for '{query}': {e}")
            all_results.append(SearchResults(query=query, results=[]))
            
    return all_results