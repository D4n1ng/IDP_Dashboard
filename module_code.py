import requests
import pandas as pd
import re
import base64

class CodeScanner:
    def __init__(self, target_company, github_token=None):
        self.target_company = target_company
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        if github_token:
            self.session.headers.update({'Authorization': f'token {github_token}'})

    def scan_repositories(self):
        """Kombiniert Orgs-Suche und allgemeine Code-Suche mit Rate-Limit Check."""
        try:
            # 1. Versuch: Offizielle Organisation
            url = f"{self.base_url}/orgs/{self.target_company}/repos"
            res = self.session.get(url, timeout=5)
            
            if res.status_code in [403, 429]:
                print("⚠️ GitHub Rate Limit (403/429) bei Orgs-Scan.")
                return None  # Signal für App: Nutze Cache!

            repos_found = []
            if res.status_code == 200:
                repos = res.json()
                for r in repos:
                    repos_found.append({
                        "repo_name": r['name'],
                        "url": r['html_url'],
                        "description": r.get('description', ''),
                        "last_update": r.get('updated_at', ''),
                        "risk_score": 10 
                    })
                return pd.DataFrame(repos_found)

            # 2. Versuch: Wenn keine Org gefunden wurde -> Code Mentions Suche
            print(f"Organisation '{self.target_company}' nicht gefunden. Starte Code-Suche...")
            search_url = f"{self.base_url}/search/repositories?q={self.target_company}"
            res = self.session.get(search_url, timeout=5)
            
            if res.status_code in [403, 429]:
                return None

            leaks = []
            if res.status_code == 200:
                items = res.json().get('items', [])
                for item in items[:15]: # Top 15 Funde
                    leaks.append({
                        "repo_name": item['full_name'],
                        "url": item['html_url'],
                        "description": item.get('description', ''),
                        "last_update": item.get('updated_at', ''),
                        "risk_score": 30 # Höheres Risiko bei Funden außerhalb der Org
                    })
            
            return pd.DataFrame(leaks)

        except Exception as e:
            print(f"Verbindungsfehler GitHub: {e}")
            return None

    def get_contributors(self, repo_path):
        """Holt die Liste der Mitwirkenden eines Repositories."""
        try:
            url = f"{self.base_url}/repos/{repo_path}/contributors"
            res = self.session.get(url, timeout=5)
            if res.status_code == 200:
                return res.json()
            return []
        except:
            return []

    def verify_user_identity(self, username):
        """Prüft Profile auf Firmenzugehörigkeit und extrahiert Metadaten."""
        try:
            url = f"{self.base_url}/users/{username}"
            res = self.session.get(url, timeout=5)
            if res.status_code != 200:
                return None
            
            data = res.json()
            bio = data.get('bio', '') or ""
            company_field = data.get('company', '') or ""
            
            # Validierung: Arbeitet die Person wirklich dort?
            is_employee = False
            if self.target_company.lower() in bio.lower() or self.target_company.lower() in company_field.lower():
                is_employee = True
            
            return {
                "Username": username,
                "Real_Name": data.get('name'),
                "Company_Field": company_field,
                "Is_Verified_Employee": is_employee,
                "Bio": bio,
                "Links": {
                    "Twitter": data.get("twitter_username"),
                    "Website/Blog": data.get("blog"),
                    "GitHub_URL": data.get("html_url")
                }
            }
        except:
            return None

    def deep_scan_profile_text(self, username):
        """Analysiert das README-Profil eines Users nach weiteren Social Links und Keywords."""
        found_data = {"social_links": [], "detected_keywords": []}
        try:
            # README-Inhalt abrufen 
            readme_url = f"{self.base_url}/repos/{username}/{username}/contents/README.md"
            res = self.session.get(readme_url, timeout=5)
            
            if res.status_code == 200:
                content_encoded = res.json().get('content', '')
                content_text = base64.b64decode(content_encoded).decode('utf-8', errors='ignore')

                # Regex für Social Media Links
                social_pattern = r"(linkedin\.com\/in\/[a-zA-Z0-9_-]+|twitter\.com\/[a-zA-Z0-9_]+|instagram\.com\/[a-zA-Z0-9_]+|facebook\.com\/[a-zA-Z0-9.]+)"
                matches = re.findall(social_pattern, content_text)
                for match in matches:
                    found_data["social_links"].append(f"https://{match}")

                # Suche nach Firma im Text
                if self.target_company.lower() in content_text.lower():
                    found_data["detected_keywords"].append(f"Target '{self.target_company}' mentioned in README")
        except:
            pass
        return found_data