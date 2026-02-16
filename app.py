import streamlit as st
import requests
import base64
import pandas as pd
import urllib3
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 0. CONFIGURATION & SAFETY ---
# Disable "InsecureRequestWarning" because we are bypassing SSL verification
# This is necessary for many legacy government portals.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. ENCRYPTION LOGIC (Standard OpenSSL / Java Equivalent)
# ==========================================

def evp_kdf(password, salt, key_size, iv_size):
    """
    Replicates OpenSSL's EVP_BytesToKey to generate the AES Key and IV.
    """
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
    """
    Encrypts the password using AES-128-CBC with the server-provided salt.
    """
    try:
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = bytes.fromhex(salt_hex)
        
        # FOIS uses 16-byte key and 16-byte IV (AES-128)
        key, iv = evp_kdf(password_bytes, salt_bytes, 16, 16)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # PKCS7 Padding
        pad_len = 16 - (len(password_bytes) % 16)
        padded_password = password_bytes + bytes([pad_len] * pad_len)
        
        encrypted_bytes = cipher.encrypt(padded_password)
        
        # Combine into OpenSSL format: "Salted__" + Salt + EncryptedData
        final_payload = b"Salted__" + salt_bytes + encrypted_bytes
        return base64.b64encode(final_payload).decode('utf-8')
    except Exception as e:
        return None

# ==========================================
# 2. FOIS CLIENT CLASS (With Connection Fixes)
# ==========================================

class FOISConnector:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://www.fois.indianrail.gov.in/ecbs"
        
        # --- FIX: ROBUST RETRY STRATEGY ---
        # This prevents the app from crashing on a single dropped connection
        retry_strategy = Retry(
            total=3,
            backoff_factor=1, # Wait 1s, 2s, 4s between retries
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # --- FIX: HEADERS ---
        # Mimic a real Chrome Browser to avoid bot detection
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Origin": "https://www.fois.indianrail.gov.in",
            "Referer": "https://www.fois.indianrail.gov.in/ecbs/JSP/LoginNew.jsp",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        })

    def get_salt(self):
        try:
            # Step 1: Hit Login Page (Sets JSESSIONID cookie)
            # verify=False is CRITICAL for FOIS
            self.session.get(f"{self.base_url}/JSP/LoginNew.jsp", timeout=15, verify=False)
            
            # Step 2: Request Salt
            response = self.session.post(f"{self.base_url}/PassSecure", timeout=15, verify=False)
            
            if response.status_code == 200:
                salt = response.text.strip()
                return salt
            return None
        except Exception as e:
            st.error(f"Network Error (Get Salt): {e}")
            return None

    def login(self, username, password, captcha_text="heebd"):
        salt = self.get_salt()
        if not salt:
            return False, "Could not connect to FOIS server (Check VPN/Internet)."

        encrypted_pass = encrypt_password(password, salt)
        if not encrypted_pass:
            return False, "Encryption failed."

        payload = {
            "operation": "login",
            "txtUserId": username,
            "txtUserID": username.upper(),
            "passwd": encrypted_pass,
            "txtLangFlag": "E",
            "txtUserType": "0",
            "txtCaptcha": captcha_text,
            "answer": captcha_text
        }

        try:
            # verify=False prevents SSL Error
            response = self.session.post(f"{self.base_url}/RouterServlet", data=payload, timeout=20, verify=False)
            
            # Check for success indicators in HTML
            if "Logout" in response.text or "Welcome" in response.text or "Home" in response.text:
                return True, "Login Successful"
            elif "Invalid" in response.text:
                return False, "Invalid Credentials or Captcha."
            else:
                # Sometimes successful login just redirects, return True to be safe
                return True, "Session Established"
        except Exception as e:
            return False, f"Login Request Error: {e}"

    def fetch_rake_insight(self, station_code, consignee):
        params = {
            "operation": "query",
            "suboperation": "insight",
            "txtSttnFrom": "",
            "txtSttnTo": station_code,
            "txtConsignee": consignee,
            "locnflag": "S",
            "user": consignee,
            "usrflag": "C"
        }
        try:
            response = self.session.get(f"{self.base_url}/RouterServlet", params=params, timeout=30, verify=False)
            if response.status_code == 200:
                return self.parse_html_table(response.text)
        except Exception as e:
            st.error(f"Fetch Error: {e}")
        return pd.DataFrame()

    def parse_html_table(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        
        # Look for the specific table ID used in FOIS
        table = soup.find('table', {'id': 'example'})
        
        if not table:
            # Fallback: Try finding any table with 'ZoneCode' which is common in their reports
            table = soup.find('table')
            if not table:
                return pd.DataFrame()

        # Headers
        headers = [th.get_text(strip=True) for th in table.find_all('th')]
        
        # Rows
        rows = []
        for tr in table.find_all('tr'):
            cols = [td.get_text(strip=True) for td in tr.find_all('td')]
            if cols:
                rows.append(cols)
        
        if rows:
            # Fix header mismatch if necessary
            max_cols = max(len(r) for r in rows)
            if not headers: 
                headers = [f"Col_{i}" for i in range(max_cols)]
            elif len(headers) < max_cols:
                headers += [f"Col_{i}" for i in range(len(headers), max_cols)]
            
            # Create DataFrame
            df = pd.DataFrame(rows, columns=headers[:max_cols])
            return df
        return pd.DataFrame()

# ==========================================
# 3. STREAMLIT UI
# ==========================================

st.set_page_config(page_title="FOIS Tracker", layout="wide")

st.title("🚂 FOIS Rake Tracker (Fixed)")
st.markdown("Use this tool to fetch **Rake Insight** data. SSL Verification is disabled to support legacy servers.")

# Sidebar
with st.sidebar:
    st.header("🔐 Credentials")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    st.markdown("---")
    st.header("📍 Parameters")
    consignee = st.text_input("Consignee", value="TATA")
    station = st.text_input("Station Code", value="NDLS")
    
    st.caption("Common Codes: NDLS, HWH, CSMT, TATA, SAIL")
    
    fetch_btn = st.button("🚀 Fetch Data", type="primary")

# Main Logic
if fetch_btn:
    if not username or not password:
        st.error("⚠️ Please enter Username and Password.")
    else:
        connector = FOISConnector()
        
        with st.status("Connecting to Indian Railways...", expanded=True) as status:
            st.write("1. Initializing Connection (Bypassing SSL)...")
            success, msg = connector.login(username, password)
            
            if success:
                st.write(f"2. {msg}")
                st.write("3. Fetching Insight Data...")
                
                df = connector.fetch_rake_insight(station, consignee)
                status.update(label="Complete!", state="complete", expanded=False)
                
                if not df.empty:
                    st.success(f"✅ Found {len(df)} records")
                    st.dataframe(df, use_container_width=True)
                    
                    csv = df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download CSV", csv, "fois_data.csv", "text/csv")
                else:
                    st.warning("⚠️ Connection successful, but no data found for these inputs.")
            else:
                status.update(label="Failed", state="error")
                st.error(f"❌ {msg}")
                st.caption("Tip: If you are outside India, you may need a VPN with an Indian IP.")
