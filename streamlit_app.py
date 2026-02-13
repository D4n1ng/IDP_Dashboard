import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import os
from datetime import datetime

# Import der Module
from module_people import PeopleScanner
from module_infra import InfraScanner, CompanyEnricher
from module_breach import BreachChecker
from module_code import CodeScanner

st.set_page_config(page_title="TRUSTEQ SE-Platform", page_icon="🛡️", layout="wide")

class CacheManager:
    """Verwaltet das Speichern und Laden von Scan-Ergebnissen als JSON"""
    def __init__(self, filename="scan_cache.json"):
        self.filename = filename

    def save(self, key, data):
        full_cache = self._load_file()
        
        # DataFrames müssen serialisiert werden
        serializable_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'people': data['people'].to_dict(orient='records'),
            'infra': data['infra'],
            'code': data['code'].to_dict(orient='records'),
            'subdomains': data['subdomains'],
            'enrichment': data['enrichment']
        }
        
        full_cache[key] = serializable_data
        with open(self.filename, 'w') as f:
            json.dump(full_cache, f, indent=4)

    def load(self, key):
        full_cache = self._load_file()
        if key in full_cache:
            entry = full_cache[key]
            # DataFrames wiederherstellen
            return {
                'people': pd.DataFrame(entry['people']),
                'infra': entry['infra'],
                'code': pd.DataFrame(entry['code']),
                'subdomains': entry['subdomains'],
                'enrichment': entry['enrichment'],
                'timestamp': entry['timestamp'],
                'from_cache': True # Wichtig für die UI Warnung
            }
        return None

    def _load_file(self):
        if not os.path.exists(self.filename):
            return {}
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except:
            return {}

class OSINTCollector:
    def __init__(self, target_company, target_domain, github_token=None, hibp_key=None):
        self.google_api_key = "AIzaSyBaqFC2-xoswTLl2Sg8hKPy9EfTWSe42-s"
        self.google_cx = "959b9b79cf1dc4d87"
        self.target_company = target_company
        self.target_domain = target_domain
        self.infra_scanner = InfraScanner(target_domain)
        self.enricher = CompanyEnricher()
        self.code_scanner = CodeScanner(target_company, github_token=github_token)
        self.cache_manager = CacheManager()
        self.cache_key = f"{target_company}_{target_domain}"

    def run_full_scan(self):
        # 1. INFRASTRUKTUR & WEB SCAN
        st.write("🌐 Analysiere DNS Records und Web-Header...")
        dns_data = self.infra_scanner.analyze_dns_txt()
        web_data = self.infra_scanner.analyze_web_headers()
        subdomains = self.infra_scanner.check_subdomains()
        enrichment = self.enricher.get_details(self.target_domain)
        infra_combined = dns_data + web_data

        # 2. MITARBEITER-SUCHE VIA GOOGLE/LINKEDIN
        st.write("🕵️ Suche Mitarbeiter via OSINT ...")
        p_scanner = PeopleScanner(self.target_company, self.google_api_key, self.google_cx)
        df_people_osint = p_scanner.scan_all_sources(limit=8)
        # Harmonize OSINT column names to match GitHub logic
        if not df_people_osint.empty:
            df_people_osint = df_people_osint.rename(columns={'URL': 'Profile_URL'})

        # 3. GITHUB SCAN
        st.write("🔍 Scanne GitHub Repositories...")
        df_code = self.code_scanner.scan_repositories()
        
        verified_employees = []
        is_cached = False

        if df_code is None: 
            cached_data = self.cache_manager.load(self.cache_key)
            if cached_data:
                return cached_data['people'], infra_combined, cached_data['code'], subdomains, enrichment, True
            else:
                return df_people_osint, infra_combined, pd.DataFrame(), subdomains, enrichment, "LIMIT_NO_CACHE"

        # GITHUB ORG SCAN 
        st.write("🔗 Verifiziere GitHub-Mitwirkende...")
        if not df_code.empty:
            for _, repo in df_code.head(3).iterrows():
                repo_path = repo['url'].replace("https://github.com/", "")
                contributors = self.code_scanner.get_contributors(repo_path)
                if contributors:
                    for contrib in contributors[:5]:
                        username = contrib['login']
                        identity = self.code_scanner.verify_user_identity(username)
                        if identity:
                            deep_info = self.code_scanner.deep_scan_profile_text(username)
                            all_links = list(set(list(identity.get('Links', {}).values()) + deep_info.get('social_links', [])))
                            verified_employees.append({
                                "Username": username,
                                "Name": identity.get('Real_Name') or username,
                                "Status": "✅ Verified (Org Member)",
                                "Offizielle_Firma": identity.get('Company_Field'),
                                "Gefundene_Links": [l for l in all_links if l],
                                "URL": identity.get('Links', {}).get('GitHub_URL'),
                                "Source": "GitHub Org"
                            })

        # PIVOT SCAN 
        if not df_people_osint.empty:
            st.write("Starte Pivot-Scan: Suche OSINT-Fundfunde auf GitHub...")
            for _, person in df_people_osint.iterrows():
                search_name = person['Name']
                if search_name and search_name != "Unbekannt":
                    pivot_identity = self.code_scanner.verify_user_identity(search_name)
                    if pivot_identity and pivot_identity.get('Is_Verified_Employee'):
                        deep_info = self.code_scanner.deep_scan_profile_text(pivot_identity['Links']['GitHub_URL'].split('/')[-1])
                        all_links = list(set(list(pivot_identity.get('Links', {}).values()) + deep_info.get('social_links', [])))
                        verified_employees.append({
                            "Username": pivot_identity['Links']['GitHub_URL'].split('/')[-1],
                            "Name": pivot_identity.get('Real_Name'),
                            "Status": "High Risk (Shadow IT)",
                            "Offizielle_Firma": pivot_identity.get('Company_Field'),
                            "Gefundene_Links": [l for l in all_links if l],
                            "URL": pivot_identity['Links']['GitHub_URL'],
                            "Source": "Pivot Search"
                        })

        # Merge Results
        df_github_total = pd.DataFrame(verified_employees)
        df_p_final = pd.concat([df_github_total, df_people_osint], ignore_index=True)
        
        if not df_p_final.empty:
            df_p_final = df_p_final.drop_duplicates(subset=['Name'])
            # Fill missing values for the UI
            df_p_final['Username'] = df_p_final['Username'].fillna("N/A")
            df_p_final['Gefundene_Links'] = df_p_final['Gefundene_Links'].apply(lambda d: d if isinstance(d, list) else [])

        self.cache_manager.save(self.cache_key, {
            'people': df_p_final, 'infra': infra_combined, 'code': df_code,
            'subdomains': subdomains, 'enrichment': enrichment
        })

        return df_p_final, infra_combined, df_code, subdomains, enrichment, is_cached
    
def main():
    st.sidebar.title("🛡️ TRUSTEQ OSINT")
    target_company = st.sidebar.text_input("Firmenname", value="google")
    target_domain = st.sidebar.text_input("Domain", value="google.com")
    
    with st.sidebar.expander("API Keys"):
        github_token = st.text_input("GitHub Token", type="password")

    st.sidebar.markdown("---")
    page = st.sidebar.radio("Navigation", ["Dashboard Übersicht", "Gefundene Mitarbeiter", "Code Leaks"])

    collector = OSINTCollector(target_company, target_domain, github_token)

    if st.sidebar.button("Live Scan Starten"):
        with st.spinner(f"Scanne {target_company}..."):
            df_p, infra, df_c, subs, enrich, is_cached = collector.run_full_scan()
            
            # Fehlerbehandlung
            if is_cached == "ERROR_LIMIT":
                st.error("❌ GitHub API Rate Limit erreicht und kein lokaler Cache vorhanden.")
                st.stop()
            
            st.session_state['scan_results'] = {
                'people': df_p, 'infra': infra, 'code': df_c, 
                'subdomains': subs, 'enrichment': enrich,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'is_cached': is_cached
            }
            if is_cached:
                st.sidebar.warning(" API Limit! Zeige Cache-Daten.")
            else:
                st.sidebar.success("✅ Live-Scan erfolgreich & gespeichert.")

    results = st.session_state.get('scan_results', None)
    
    if page == "Dashboard Übersicht":
        render_dashboard(results, collector)
    elif page == "Gefundene Mitarbeiter":
        render_people_page(results)
    elif page == "Code Leaks":
        render_code_page(results)

def render_dashboard(results, collector):
    if not results:
        st.info("Bitte Scan starten.")
        return

    if results.get('is_cached'):
        st.warning(f" **ACHTUNG:** API Rate Limit aktiv. Zeige Daten vom letzten erfolgreichen Scan ({results.get('timestamp')}).")

    # Header
    st.title(f"🛡️ Surface Overview: {collector.target_company}")
    st.markdown(f"**Domain:** {collector.target_domain} | **Letzter Scan:** {results.get('timestamp')}")
    st.divider()

    # Risiko Score
    avg_risk = 30
    if not results['code'].empty: avg_risk += 40
    if results['subdomains']: avg_risk += 20
    
    # KPI
    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=avg_risk, title={'text': "Risk Score"},
            gauge={'axis': {'range': [0, 100]}, 'bar': {'color': "darkblue"},
                   'steps': [{'range': [0, 40], 'color': "green"}, {'range': [70, 100], 'color': "red"}]}))
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.metric("Mitarbeiter", len(results['people']))
        st.metric("Repos", len(results['code']))
    with c3:
        st.subheader("Tech Stack")
        for item in results['infra']:
            st.caption(f"{item['Software']}")

    st.divider()
    if results['subdomains']:
        st.subheader(" Kritische Subdomains")
        for sub in results['subdomains']:
            st.error(f"{sub['Portal']}")

def render_people_page(results):
    st.subheader("👥 Discovered Identities")
    if results and not results['people'].empty:
        for _, person in results['people'].iterrows():
            with st.expander(f"{person['Name']} (@{person['Username']}) - {person.get('Source', 'OSINT')}"):
                st.write(f"**Status:** {person['Status']}")
                st.write(f"**Company:** {person.get('Offizielle_Firma', 'Unknown')}")
                
                # Render all social links found
                links = person.get('Gefundene_Links', [])
                if links:
                    st.write("**Social Profiles & Mentions:**")
                    for link in links:
                        st.write(f"🔗 [{link}]({link})")
                
                # Main profile link
                profile_url = person.get('URL') or person.get('Profile_URL')
                if profile_url:
                    st.markdown(f"--- \n [View Primary Profile]({profile_url})")
    else:
        st.info("No employee data available.")

def render_code_page(results):
    st.subheader("💻 Critical Code Repositories")
    if results and not results['code'].empty:
        if results.get('is_cached'):
            st.warning("⚠️ Anzeige basiert auf Cache-Daten.")
        
        for _, repo in results['code'].iterrows():
            risk_score = repo.get('risk_score', 0)
            color = "red" if risk_score > 70 else "orange" if risk_score > 30 else "green"
            
            with st.container():
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"### 📂 {repo['repo_name']}")
                    st.caption(f"URL: {repo['url']}")
                with col2:
                    st.metric("Risk Score", f"{risk_score}/100")
                
                st.progress(risk_score / 100)
                st.markdown(f"[Inspect Repository]({repo['url']})")
                st.divider()
    else:
        st.info("Keine Repositories gefunden.")

if __name__ == "__main__":
    main()
