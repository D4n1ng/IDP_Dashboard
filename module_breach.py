import requests
import time

class BreachChecker:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            'hibp-api-key': api_key,
            'user-agent': 'IDP-Student-Project'
        }

    def check_email(self, email):
        if not self.api_key:
            return {"status": "skipped", "reason": "No API Key"}

        print(f"Prüfe Leak-Status für {email}...")
        url = f"{self.base_url}/breachedaccount/{email}?truncateResponse=false"
        
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            leaks = response.json()
            return {"status": "leaked", "count": len(leaks), "details": [l['Name'] for l in leaks]}
        elif response.status_code == 404:
            return {"status": "safe", "count": 0}
        elif response.status_code == 429:
            print("Rate Limit erreicht. Warte...")
            time.sleep(2)
            return self.check_email(email)
        else:
            return {"status": "error", "code": response.status_code}

# Testlauf
if __name__ == "__main__":
    # Key hier einfügen, falls vorhanden
    checker = BreachChecker(api_key="DEIN_KEY_HIER") 
    # Test mit einer oft geleakten E-Mail 
    print(checker.check_email("test@example.com"))