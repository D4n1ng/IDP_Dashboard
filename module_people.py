import time
import random
import requests
from googlesearch import search
from ddgs import DDGS
import pandas as pd

class PeopleScanner:
    def __init__(self, company_name, google_api_key=None, google_cx=None):
        self.company = company_name
        self.google_api_key = google_api_key
        self.google_cx = google_cx # Custom Search Engine ID
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15"
        ]

    def scan_all_sources(self, limit=10):
        all_results = []
        
        # 1. DuckDuckGo 
        ddg_res = self.search_via_duckduckgo(limit)
        all_results.extend(ddg_res)

        # 2. Google Custom Search 
        if self.google_api_key and self.google_cx and len(all_results) < limit:
            api_res = self.search_via_api(limit - len(all_results))
            all_results.extend(api_res)

        # 3. Google Dorking 
        if len(all_results) < 10: # Nur wenn wir fast gar nichts haben
             google_res = self.search_via_google_dork(5)
             all_results.extend(google_res)

        if not all_results:
            return pd.DataFrame()
            
        return pd.DataFrame(all_results).drop_duplicates(subset=['URL'])

    def search_via_api(self, limit):
        print("Suche via Google API...")
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            'q': f'site:linkedin.com/in/ "{self.company}"',
            'key': self.google_api_key,
            'cx': self.google_cx,
            'num': limit
        }
        r = requests.get(url, params=params)
        results = []
        if r.status_code == 200:
            for item in r.json().get('items', []):
                results.append({"Name": item['title'], "URL": item['link'], "Quelle": "Google API"})
        return results

    def search_via_duckduckgo(self, limit):
        print("Suche via DuckDuckGo ...")
        results = []
        try:
            with DDGS() as ddgs:
                ddgs_gen = ddgs.text(f'site:linkedin.com/in/ "{self.company}"', max_results=limit)
                for r in ddgs_gen:
                    results.append({
                        "Name": r['title'].split("-")[0].strip(),
                        "URL": r['href'],
                        "Quelle": "DuckDuckGo"
                    })
        except Exception as e:
            print(f"DDG Fehler: {e}")
        return results

    def search_via_google_dork(self, limit):
        print("Suche via Google Dorking ...")
        results = []
        headers = {'User-Agent': random.choice(self.user_agents)}
        try:
            # Hier nutzen wir das sleep_interval massiv hoch
            for url in search(f'site:linkedin.com/in/ "{self.company}"', 
                             num_results=limit, sleep_interval=15):
                results.append({"Name": "Unbekannt", "URL": url, "Quelle": "Google Dork"})
        except:
            print("Google Dorking fehlgeschlagen (Block).")
        return results