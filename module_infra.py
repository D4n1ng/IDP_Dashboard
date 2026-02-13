import dns.resolver
import requests
from ddgs import DDGS

class InfraScanner:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"https://{domain}"

    def analyze_web_headers(self):
        tech_found = []
        try:
            # Gängiger User-Agent, um nicht sofort blockiert zu werden
            response = requests.get(self.url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            headers = response.headers
            
            # Server-Software 
            if "Server" in headers:
                tech_found.append({"Software": f"Server: {headers['Server']}", "Risk": "Info"})
            
            # Frameworks 
            if "X-Powered-By" in headers:
                tech_found.append({"Software": headers['X-Powered-By'], "Risk": "Medium"})
            
            # Sicherheits-Features
            if "Strict-Transport-Security" in headers:
                tech_found.append({"Software": "HSTS Security", "Risk": "Low"})

            # Body-Analyse 
            body = response.text.lower()
            if "wp-content" in body:
                tech_found.append({"Software": "WordPress CMS", "Risk": "Medium"})
            if "react" in body or "react-dom" in body:
                tech_found.append({"Software": "React Frontend", "Risk": "Low"})

        except Exception as e:
            print(f"Web-Header Scan fehlgeschlagen: {e}")
        
        return tech_found

    def analyze_dns_txt(self):
        print(f"Analysiere DNS Records für {self.domain}...")
        found_software = []
        
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                
                if "google-site-verification" in txt_record:
                    found_software.append({"Software": "Google Workspace", "Risk": "Low"})
                if "outlook" in txt_record or "protection.outlook.com" in txt_record:
                    found_software.append({"Software": "Microsoft Office 365", "Risk": "Low"})
                if "atlassian" in txt_record:
                    found_software.append({"Software": "Atlassian Cloud", "Risk": "Medium"})
                if "v=spf1" in txt_record:
                    found_software.append({"Software": "SPF Mail Security", "Risk": "Low"})

        except Exception as e:
            print(f"DNS Fehler: {e}")
            
        return found_software

    def check_subdomains(self):
        common_subs = ["vpn", "jira", "wiki", "hr", "personio", "mail", "dev", "git", "test"]
        found_portals = []
        
        for sub in common_subs:
            hostname = f"{sub}.{self.domain}"
            try:
                dns.resolver.resolve(hostname, 'A')
                found_portals.append({"Portal": hostname, "Risk": "High (Login Portal exposed)"})
            except:
                pass 
        
        return found_portals

class CompanyEnricher:
    def get_details(self, domain):
        company_name = domain.split('.')[0].title()
        description = "Keine Beschreibung gefunden."
        
        try:
            with DDGS() as ddgs:
                # Suche nach dem Firmenprofil für eine Kurzbeschreibung
                query = f"{company_name} company profile information"
                results = list(ddgs.text(query, max_results=1))
                if results:
                    description = results[0]['body'][:250] + "..."
        except:
            pass

        return {
            "name": company_name,
            "description": description,
            "employees": "Schätzung via OSINT",
            "linkedin": f"https://www.linkedin.com/company/{company_name.lower()}"
        }

# Test-Block
if __name__ == "__main__":
    scanner = InfraScanner("trusteq.de")
    print("DNS:", scanner.analyze_dns_txt())
    print("Subdomains:", scanner.check_subdomains())