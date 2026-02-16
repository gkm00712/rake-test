import streamlit as st
import requests
import base64
import re
import urllib3
import pandas as pd
from datetime import datetime
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 0. CONFIG: BYPASS SSL (Like the Java Code) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. ENCRYPTION LOGIC (Java "EvpKDF" Replica)
# ==========================================
def evp_kdf(password, salt, key_size, iv_size):
    """ Replicates the OpenSSL Key Derivation used in the Java code. """
    derived_key_iv = b""
    prev_block = b""
    while len(derived_key_iv) < key_size + iv_size:
        md5 = MD5.new()
        if prev_block:
            md5.update(prev_block)
        md5.update(password)
        md5.update(salt)
        prev_block = md5.digest()
        derived_key_iv += prev_block
    return derived_key_iv[:key_size], derived_key_iv[key_size:key_size + iv_size]

def encrypt_password(plain_password, salt_hex):
    """ Encrypts password exactly how the Java App does. """
    try:
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = bytes.fromhex(salt_hex)
        key, iv = evp_kdf(password_bytes, salt_bytes, 16, 16)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pad_len = 16 - (len(password_bytes) % 16)
        padded_password = password_bytes + bytes([pad_len] * pad_len)
        
        encrypted_bytes = cipher.encrypt(padded_password)
        final_payload = b"Salted__" + salt_bytes + encrypted_bytes
        return base64.b64encode(final_payload).decode('utf-8')
    except Exception:
        return None

# ==========================================
# 2. THE REPLICA CLIENT
# ==========================================
class FOISReplica:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://www.fois.indianrail.gov.in/ecbs"
        
        # Retry logic to handle connection drops
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        
        # Headers mimicking the Android WebView
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{self.base_url}/JSP/LoginNew.jsp"
        })

    def login_flow(self, username, password):
        """
        Replicates the 'FOIShome' and 'FOISlogin' AsyncTasks.
        """
        # --- STEP 1: GET Login Page & Extract 'logintimeform' ---
        # Java Code: "name=\"logintimeform\" type=\"hidden\" value=\""
        try:
            resp_home = self.session.get(f"{self.base_url}/JSP/LoginNew.jsp", timeout=15, verify=False)
            
            # Extract the hidden token using Regex (mimicking Java's indexOf/substring)
            match = re.search(r'name="logintimeform" type="hidden" value="([^"]+)"', resp_home.text)
            if not match:
                return False, "Could not find 'logintimeform' token. Site changed?"
            
            logintimeform = match.group(1)
            # st.write(f"DEBUG: Found logintimeform: {logintimeform}") 
            
        except Exception as e:
            return False, f"Step 1 Failed: {e}"

        # --- STEP 2: GET Salt (PassSecure) ---
        try:
            resp_salt = self.session.post(f"{self.base_url}/PassSecure", timeout=15, verify=False)
            salt_hex = resp_salt.text.strip()
        except Exception as e:
            return False, f"Step 2 Failed: {e}"

        # --- STEP 3: Encrypt ---
        encrypted_pass = encrypt_password(password, salt_hex)
        if not encrypted_pass:
            return False, "Encryption Failed"

        # --- STEP 4: POST Login ---
        # Mimicking the exact parameters sent by the Java app
        payload = {
            "operation": "login",
            "logintimeform": logintimeform,  # Extracted from Step 1
            "txtInputPage": "",
            "txtUserID": username.upper(),
            "passwd": encrypted_pass,        # Encrypted PW
            "txtLangFlag": "E",
            "txtSHYFlag": "",
            "txtUserId": username,
            "txtPassword": encrypted_pass,   # Sent twice in Java code
            "answer": "heebd"                # HARDCODED CAPTCHA from Java code
        }

        try:
            resp_login = self.session.post(f"{self.base_url}/RouterServlet", data=payload, timeout=20, verify=False)
            
            # Success Check
            if "Logout" in resp_login.text or "Welcome" in resp_login.text or "Home" in resp_login.text:
                return True, "Login Successful"
            elif "Invalid" in resp_login.text:
                return False, "Invalid User/Pass or 'heebd' captcha rejected."
            else:
                return True, "Session Established (Implicit)"
        except Exception as e:
            return False, f"Login Request Error: {e}"

    def fetch_insight(self, station, consignee):
        """ Replicates 'FOISinsight' AsyncTask """
        # Java uses hardcoded date '21-12-2020'. We use current date to ensure it works.
        today_str = datetime.now().strftime("%d-%m-%Y")
        
        params = {
            "operation": "query",
            "suboperation": "insight",
            "txtSttnFrom": "",
            "txtSttnTo": station,
            "txtCommodity": "",
            "txtConsignor": "",
            "txtConsignee": consignee,
            "locnflag": "S",
            "user": consignee,
            "usrflag": "C",
            "txtSysDate": today_str 
        }
        try:
            resp = self.session.get(f"{self.base_url}/RouterServlet", params=params, timeout=30, verify=False)
            return self._parse_table(resp.text)
        except Exception:
            return pd.DataFrame()

    def fetch_indents(self, station, consignee, consignors_str):
        """ Replicates 'FOISindents' AsyncTask """
        today_str = datetime.now().strftime("%d-%m-%Y")
        params = {
            "operation": "query",
            "suboperation": "rakeostgdtls",
            "txtSttnFrom": "",
            "txtSttnTo": station,
            "txtStckType": "",
            "txtConsignor": "",
            "txtConsignee": consignee,
            "locnflag": "S",
            "user": consignee,
            "usrflag": "C",
            "txtSysDate": today_str
        }
        
        summary = {}
        try:
            resp = self.session.get(f"{self.base_url}/RouterServlet", params=params, timeout=30, verify=False)
            html = resp.text
            
            # Replicating the "countOfOccurrences" logic
            # Java: countOfOccurrences(uRLdataresult.message, ">" + str + "<")
            consignor_list = [c.strip() for c in consignors_str.split(',')]
            
            total_indents = html.count('<td id="Sno')
            summary['Total Indents'] = total_indents
            
            for c in consignor_list:
                # Counting strict occurrences like ">CCL<"
                pattern = f">{c}<"
                count = html.count(pattern)
                summary[c] = count
                
            return summary
        except Exception:
            return {}

    def _parse_table(self, html):
        """ Helper to parse HTML table to DataFrame """
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table', {'id': 'example'})
        if not table: table = soup.find('table')
        if not table: return pd.DataFrame()

        headers = [th.get_text(strip=True) for th in table.find_all('th')]
        rows = []
        for tr in table.find_all('tr'):
            cols = [td.get_text(strip=True) for td in tr.find_all('td')]
            if cols: rows.append(cols)
            
        if rows:
            max_cols = max(len(r) for r in rows)
            if not headers: headers = [f"Col_{i}" for i in range(max_cols)]
            elif len(headers) < max_cols: headers += [f"Col_{i}" for i in range(len(headers), max_cols)]
            return pd.DataFrame(rows, columns=headers[:max_cols])
        return pd.DataFrame()

# ==========================================
# 3. STREAMLIT UI (Replicates 'MainActivity')
# ==========================================
st.set_page_config(page_title="Coal Rakes Replica", layout="wide")
st.title("🚂 FOIS Android Replica")

# Sidebar Inputs
with st.sidebar:
    st.header("Login Details")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    st.header("Settings (Prefs)")
    consignee = st.text_input("Consignee", value="TATA")
    station = st.text_input("Station", value="NDLS")
    consignors = st.text_input("Consignors (comma sep)", value="CCL,NCL,MCL")
    
    run_btn = st.button("Run Sync", type="primary")

if run_btn:
    if not username or not password:
        st.error("Missing Credentials")
    else:
        client = FOISReplica()
        
        with st.status("Running Android Logic...", expanded=True) as status:
            # 1. LOGIN FLOW
            st.write("🔹 Fetching Token & Salt...")
            success, msg = client.login_flow(username, password)
            
            if success:
                st.write(f"✅ {msg}")
                
                # 2. FETCH INDENTS (Replicates 'FOISindents')
                st.write("🔹 Counting Indents...")
                indent_data = client.fetch_indents(station, consignee, consignors)
                
                # Display Indents Summary (Like the TextView in Java)
                if indent_data:
                    cols = st.columns(len(indent_data))
                    for i, (k, v) in enumerate(indent_data.items()):
                        cols[i].metric(k, v)
                
                # 3. FETCH INSIGHT (Replicates 'FOISinsight')
                st.write("🔹 Downloading Rake Data...")
                df = client.fetch_insight(station, consignee)
                
                status.update(label="Sync Complete", state="complete", expanded=False)
                
                if not df.empty:
                    st.dataframe(df, use_container_width=True)
                else:
                    st.warning("No Rake Data Found.")
            else:
                status.update(label="Login Failed", state="error")
                st.error(msg)
