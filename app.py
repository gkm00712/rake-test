import streamlit as st
import requests
import base64
import pandas as pd
import urllib3
import time
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 0. CONFIGURATION ---
# Disable SSL Warnings (Mimics the Java code's TrustManager override)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. ENCRYPTION LOGIC (Exact Java Replica)
# ==========================================

def evp_kdf(password, salt, key_size, iv_size):
    """
    Replicates OpenSSL's EVP_BytesToKey (Java: EvpKDF function)
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
    Encrypts password using AES-128-CBC with the salt.
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
        
        # Final Format: "Salted__" + Salt + EncryptedData
        final_payload = b"Salted__" + salt_bytes + encrypted_bytes
        return base64.b64encode(final_payload).decode('utf-8')
    except Exception as e:
        return None

# ==========================================
# 2. FOIS CLIENT (The "Java App" in Python)
# ==========================================

class FOISConnector:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://www.fois.indianrail.gov.in/ecbs"
        
        # --- NETWORK RETRY LOGIC (To fix "Connection Refused") ---
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # --- HEADERS (Mimicking the Java App) ---
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://www.fois.indianrail.gov.in",
            "Referer": "https://www.fois.indianrail.gov.in/ecbs/JSP/LoginNew.jsp"
        })

    def get_salt(self):
        """ Mimics accessing PassSecure to get the Hex Salt """
        try:
            # 1. Hit Login Page to set Cookies (JSESSIONID)
            self.session.get(f"{self.base_url}/JSP/LoginNew.jsp", timeout=15, verify=False)
            
            # 2. Post to PassSecure
            response = self.session.post(f"{self.base_url}/PassSecure", timeout=15, verify=False)
            
            if response.status_code == 200:
                return response.text.strip()
            return None
        except Exception as e:
            st.error(f"Network Error (Get Salt): {e}")
            return None

    def login(self, username, password):
        """ 
        Mimics the 'FOISlogin' class. 
        Uses hardcoded captcha 'heebd' just like the Java code. 
        """
        salt = self.get_salt()
        if not salt:
            return False, "Could not connect to FOIS server. (Are you inside India?)"

        encrypted_pass = encrypt_password(password, salt)
        if not encrypted_pass:
            return False, "Encryption failed."

        # Exact parameters from the Java 'doInBackground' method
        payload = {
            "operation": "login",
            "txtUserId": username,
            "txtUserID": username.upper(),
            "passwd": encrypted_pass,
            "txtLangFlag": "E",
            "txtSHYFlag": "", 
            "txtUserType": "0",
            # The Java code hardcodes this:
            "answer": "heebd" 
        }

        try:
            # POST to RouterServlet
            response = self.session.post(f"{self.base_url}/RouterServlet", data=payload, timeout=20, verify=False)
            
            # Check for success
            # If successful, FOIS usually returns a page with "Logout" or the user's name
            if "Logout" in response.text or "Welcome" in response.text or "Home" in response.text:
                return True, "Login Successful"
            elif "Invalid" in response.text:
                return False, "Invalid Credentials."
            else:
                # Assuming success if no explicit error, as FOIS redirects are messy
                return True, "Session Established"
        except Exception as e:
            return False, f"Login Request Error: {e}"

    def fetch_rake_insight(self, station_code, consignee):
        """ Mimics the 'FOISinsight' class """
        # Parameters from Java 'FOISinsight' class
        params = {
            "operation": "query",
            "suboperation": "insight",
            "txtSttnFrom": "",
            "txtSttnTo": station_code,
            "txtCommodity": "",
            "txtConsignor": "",
            "txtConsignee": consignee,
            "locnflag": "S",
            "user": consignee,
            "usrflag": "C",
            "txtSysDate": "" # Left empty, server usually defaults to today
        }
        try:
            response = self.session.get(f"{self.base_url}/RouterServlet", params=params, timeout=30, verify=False)
            if response.status_code == 200:
                return self.parse_html_table(response.text)
        except Exception as e:
            st.error(f"Fetch Error: {e}")
        return pd.DataFrame()

    def parse_html_table(self, html):
        """ Parses the HTML response into a Pandas DataFrame """
        soup = BeautifulSoup(html, 'html.parser')
        
        # Java code searches for <table id="example">
        table = soup.find('table', {'id': 'example'})
        
        # Fallback if ID is missing
        if not table:
            table = soup.find('table') 
            if not table: return pd.DataFrame()

        # Headers
        headers = [th.get_text(strip=True) for th in table.find_all('th')]
        
        # Rows
        rows = []
        for tr in table.find_all('tr'):
            cols = [td.get_text(strip=True) for td in tr.find_all('td')]
            if cols:
                rows.append(cols)
        
        if rows:
            max_cols = max(len(r) for r in rows)
            if not headers: headers = [f"Col_{i}" for i in range(max_cols)]
            elif len(headers) < max_cols: headers += [f"Col_{i}" for i in range(len(headers), max_cols)]
            
            return pd.DataFrame(rows, columns=headers[:max_cols])
        return pd.DataFrame()

# ==========================================
# 3. STREAMLIT UI
# ==========================================

st.set_page_config(page_title="FOIS Rake Tracker", layout="wide")

st.title("🚂 FOIS Rake Tracker")
st.markdown("""
This tool mimics the `com.hpvirtualreality.coalrakes` Android app logic:
1.  **Bypasses SSL Verification** (like the Java app).
2.  **Hardcodes Captcha** to `heebd` (like the Java app).
""")

# --- INPUTS ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("1. Credentials")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

with col2:
    st.subheader("2. Search Parameters")
    consignee = st.text_input("Consignee Code", value="TATA", help="e.g. TATA, SAIL, NTPC")
    station = st.text_input("Station Code", value="NDLS", help="e.g. NDLS, HWH")

st.info("ℹ️ **Note:** Connection errors usually mean you are blocked by the FOIS firewall. Run this script locally in India for best results.")

if st.button("🚀 Connect & Fetch Data", type="primary"):
    if not username or not password:
        st.error("Please enter Username and Password.")
    else:
        connector = FOISConnector()
        
        with st.status("Executing FOIS Protocol...", expanded=True) as status:
            
            st.write("🔹 Connecting to Server (SSL Bypassed)...")
            success, msg = connector.login(username, password)
            
            if success:
                st.write(f"✅ {msg}")
                st.write(f"🔹 Querying Insight for {consignee} @ {station}...")
                
                df = connector.fetch_rake_insight(station, consignee)
                status.update(label="Operation Complete", state="complete", expanded=False)
                
                if not df.empty:
                    st.success(f"Found {len(df)} Rakes!")
                    st.dataframe(df, use_container_width=True)
                    
                    # CSV Download
                    csv = df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download Data as CSV", csv, "fois_rakes.csv", "text/csv")
                else:
                    st.warning("No data found (or the hardcoded captcha 'heebd' is no longer accepted).")
            else:
                status.update(label="Login Failed", state="error")
                st.error(f"❌ {msg}")
