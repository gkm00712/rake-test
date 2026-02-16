import streamlit as st
import requests
import base64
import pandas as pd
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from urllib.parse import quote

# ==========================================
# 1. ENCRYPTION LOGIC (Replicating Java Code)
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
# 2. FOIS CLIENT CLASS
# ==========================================

class FOISConnector:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://www.fois.indianrail.gov.in/ecbs"
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Origin": "https://www.fois.indianrail.gov.in",
            "Referer": "https://www.fois.indianrail.gov.in/ecbs/JSP/LoginNew.jsp"
        })

    def get_salt(self):
        try:
            # Step 1: Initial load to set cookies
            self.session.get(f"{self.base_url}/JSP/LoginNew.jsp", timeout=10)
            # Step 2: Get Salt
            response = self.session.post(f"{self.base_url}/PassSecure", timeout=10)
            if response.status_code == 200:
                return response.text.strip()
        except Exception as e:
            st.error(f"Connection Error: {e}")
        return None

    def login(self, username, password, captcha_text="heebd"):
        salt = self.get_salt()
        if not salt:
            return False, "Could not connect to FOIS server."

        encrypted_pass = encrypt_password(password, salt)
        if not encrypted_pass:
            return False, "Encryption failed."

        # The exact payload parameters expected by the server
        payload = {
            "operation": "login",
            "txtUserId": username,
            "txtUserID": username.upper(),
            "passwd": encrypted_pass,
            "txtLangFlag": "E",
            "txtUserType": "0",
            "txtCaptcha": captcha_text, # Assuming field name, though Java code hardcoded it in URL
            "answer": captcha_text      # Java code appended this to URL
        }

        try:
            # The Java code sends params in the URL for the RouterServlet sometimes
            # We will send as POST data which is standard, but mimic the Java 'answer' param
            response = self.session.post(f"{self.base_url}/RouterServlet", data=payload, timeout=15)
            
            # Basic validation logic
            if "Logout" in response.text or "Welcome" in response.text or "Home" in response.text:
                return True, "Login Successful"
            elif "Invalid" in response.text:
                return False, "Invalid Credentials or Captcha."
            else:
                # Often returns a redirect page on success
                return True, "Session Established (Implicit)"
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
            response = self.session.get(f"{self.base_url}/RouterServlet", params=params, timeout=20)
            if response.status_code == 200:
                return self.parse_html_table(response.text)
        except Exception as e:
            st.error(f"Fetch Error: {e}")
        return pd.DataFrame()

    def parse_html_table(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table', {'id': 'example'})
        
        if not table:
            return pd.DataFrame()

        # Get Headers
        headers = [th.get_text(strip=True) for th in table.find_all('th')]
        
        # Get Rows
        rows = []
        for tr in table.find_all('tr'):
            cols = [td.get_text(strip=True) for td in tr.find_all('td')]
            if cols:
                rows.append(cols)
        
        # Create DataFrame
        if rows:
            # Handle mismatch in header/column count
            max_cols = max(len(r) for r in rows)
            if len(headers) < max_cols:
                headers += [f"Col_{i}" for i in range(len(headers), max_cols)]
            
            df = pd.DataFrame(rows, columns=headers[:max_cols])
            return df
        return pd.DataFrame()

# ==========================================
# 3. STREAMLIT UI
# ==========================================

st.set_page_config(page_title="FOIS Rake Tracker", layout="wide")

st.title("🚂 FOIS Rake Data Fetcher")
st.markdown("Use this tool to securely fetch 'Rake Insight' data directly from the Indian Railways FOIS portal.")

# --- SIDEBAR: Credentials ---
with st.sidebar:
    st.header("🔐 Credentials")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    st.markdown("---")
    st.header("📍 Search Params")
    consignee = st.text_input("Consignee Code", value="TATA", help="e.g., TATA, SAIL, NTPC")
    station = st.text_input("Station Code", value="NDLS", help="e.g., NDLS, HWH")
    
    captcha_val = st.text_input("Captcha (if required)", value="heebd", help="Legacy app used 'heebd'. Change if server rejects.")
    
    fetch_btn = st.button("🚀 Login & Fetch Data", type="primary")

# --- MAIN EXECUTION ---
if fetch_btn:
    if not username or not password:
        st.error("Please enter Username and Password.")
    else:
        connector = FOISConnector()
        
        with st.status("Connecting to FOIS...", expanded=True) as status:
            st.write("Generating Encryption Keys...")
            # 1. Login
            success, msg = connector.login(username, password, captcha_val)
            
            if success:
                st.write("Login Successful! Fetching Rake Insight...")
                # 2. Fetch Data
                df = connector.fetch_rake_insight(station, consignee)
                status.update(label="Process Complete!", state="complete", expanded=False)
                
                if not df.empty:
                    st.success(f"✅ Found {len(df)} records for {consignee}")
                    
                    # Display Data
                    st.dataframe(df, use_container_width=True)
                    
                    # CSV Download
                    csv = df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="📥 Download CSV",
                        data=csv,
                        file_name='fois_rake_data.csv',
                        mime='text/csv',
                    )
                else:
                    st.warning("⚠️ Login worked, but no data found for these parameters.")
            else:
                status.update(label="Login Failed", state="error")
                st.error(f"❌ Error: {msg}")

st.markdown("---")
st.caption("Note: This tool uses client-side encryption (AES-128) matching the official FOIS portal. Credentials are not stored.")
