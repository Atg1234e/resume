import streamlit as st
import sqlite3
import bcrypt
import json
import secrets
import string

# Set page layout
st.set_page_config(page_title="ProResume Builder", page_icon="📄", layout="wide")

# ==========================================
# 1. HELPER FUNCTIONS & DATABASE SETUP
# ==========================================
def generate_recovery_key():
    """Auto-generates a secure 16-character key (XXXX-XXXX-XXXX-XXXX)"""
    chars = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(chars) for _ in range(16))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:]}"

def hash_password(password: str) -> str:
    """Hashes password using Bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    """Verifies password against stored Bcrypt hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def init_db():
    """Initializes SQLite database and handles automatic schema migrations safely."""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    
    # Check if users table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = c.fetchone()

    if not table_exists:
        # Create fresh table with correct constraints
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                recovery_key TEXT DEFAULT ''
            )
        """)
    else:
        # Safely migrate older database schemas without SQLite constraint errors
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        if "email" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
        if "recovery_key" not in columns:
            c.execute("ALTER TABLE users ADD COLUMN recovery_key TEXT DEFAULT ''")
            
    c.execute("""
        CREATE TABLE IF NOT EXISTS resumes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE,
            data TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
        
    conn.commit()
    conn.close()

def register_user(email, username, password):
    """Registers new user with Email, Username, and Hashed Password"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    hashed_pass = hash_password(password)
    try:
        c.execute("INSERT INTO users (email, username, password, recovery_key) VALUES (?, ?, ?, ?)", 
                  (email.strip().lower(), username.strip(), hashed_pass, ""))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(email, password):
    """Authenticates user using Email and Bcrypt Password"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    c.execute("SELECT id, password, username FROM users WHERE email = ?", (email.strip().lower(),))
    row = c.fetchone()
    conn.close()
    if row and check_password(password, row[1]):
        return row[0], row[2]  # Returns (user_id, username)
    return None, None

def generate_reset_key_for_email(email):
    """Generates and persists a reset key when user submits their email"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email = ?", (email.strip().lower(),))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    
    new_key = generate_recovery_key()
    c.execute("UPDATE users SET recovery_key = ? WHERE email = ?", (new_key, email.strip().lower()))
    conn.commit()
    conn.close()
    return new_key

def reset_password_with_key(email, recovery_key, new_password):
    """Resets password using Email and generated Recovery Key"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    c.execute("SELECT recovery_key FROM users WHERE email = ?", (email.strip().lower(),))
    row = c.fetchone()
    if not row:
        conn.close()
        return "EMAIL_NOT_FOUND"
    
    db_key = row[0].strip().upper()
    user_key = recovery_key.strip().upper()
    
    if db_key and db_key == user_key:
        hashed_pass = hash_password(new_password)
        # Clear recovery key after successful reset
        c.execute("UPDATE users SET password = ?, recovery_key = '' WHERE email = ?", (hashed_pass, email.strip().lower()))
        conn.commit()
        conn.close()
        return "SUCCESS"
    else:
        conn.close()
        return "INVALID_KEY"

def save_resume(user_id, data_dict):
    """Saves or updates user's resume JSON in SQLite"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    json_data = json.dumps(data_dict)
    c.execute("""
        INSERT INTO resumes (user_id, data) VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET data = excluded.data
    """, (user_id, json_data))
    conn.commit()
    conn.close()

def load_resume(user_id):
    """Retrieves saved resume JSON for logged-in user"""
    conn = sqlite3.connect("resume_builder.db")
    c = conn.cursor()
    c.execute("SELECT data FROM resumes WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return json.loads(row[0]) if row else None

# Initialize SQLite database
init_db()

# ==========================================
# 2. CUSTOM CSS STYLING
# ==========================================
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        color: #f8fafc;
    }
    div[data-baseweb="input"] > div, div[data-baseweb="textarea"] > div {
        background: rgba(30, 41, 59, 0.7) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 8px !important;
        color: white !important;
    }
    .stButton > button {
        background: linear-gradient(90deg, #6366f1 0%, #a855f7 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.2rem !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3) !important;
    }
    .resume-preview {
        background-color: #ffffff;
        color: #1e293b;
        padding: 40px;
        border-radius: 12px;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    .resume-header { border-bottom: 3px solid #6366f1; padding-bottom: 10px; margin-bottom: 15px; }
    .resume-name { font-size: 26px; font-weight: 800; color: #0f172a; margin: 0; }
    .resume-title { font-size: 15px; font-weight: 600; color: #6366f1; margin-bottom: 8px; }
    .resume-contact { font-size: 12px; color: #64748b; display: flex; gap: 12px; flex-wrap: wrap; }
    .resume-section-title { font-size: 15px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 3px; margin-top: 15px; margin-bottom: 8px; }
    .badge { display: inline-block; background-color: #f1f5f9; color: #334155; border-radius: 4px; padding: 2px 6px; font-size: 11px; font-weight: 600; margin-right: 4px; margin-bottom: 4px; border: 1px solid #cbd5e1; }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = None
if "generated_key" not in st.session_state:
    st.session_state.generated_key = None

# ==========================================
# 3. AUTHENTICATION (UNAUTHENTICATED VIEW)
# ==========================================
if not st.session_state.user_id:
    st.title("⚡ ProResume Builder")
    st.caption("Secure Authentication with Email ID & Password Recovery.")
    
    tab_login, tab_signup, tab_reset = st.tabs(["🔒 Log In", "📝 Sign Up", "🔑 Forgot Password"])
    
    # LOGIN TAB (Email + Password)
    with tab_login:
        with st.form("login_form"):
            email_input = st.text_input("Email ID")
            pass_input = st.text_input("Password", type="password")
            submit_login = st.form_submit_button("Log In")
            
            if submit_login:
                if not email_input or not pass_input:
                    st.warning("Please fill in both fields.")
                else:
                    uid, uname = authenticate_user(email_input, pass_input)
                    if uid:
                        st.session_state.user_id = uid
                        st.session_state.username = uname
                        st.success("Authenticated successfully!")
                        st.rerun()
                    else:
                        st.error("Invalid email or password.")

    # SIGNUP TAB (Email + Username + Password)
    with tab_signup:
        with st.form("signup_form"):
            new_email = st.text_input("Email ID")
            new_user = st.text_input("Username")
            new_pass = st.text_input("Password", type="password")
            submit_signup = st.form_submit_button("Create Account")
            
            if submit_signup:
                if new_email and new_user and new_pass:
                    if register_user(new_email, new_user, new_pass):
                        st.success("Account created successfully! Switch to the Log In tab.")
                    else:
                        st.error("An account with this Email ID already exists.")
                else:
                    st.warning("Please complete all fields.")

    # FORGOT PASSWORD TAB (Generate Key + Reset)
    with tab_reset:
        st.subheader("Step 1: Request Reset Key")
        with st.form("request_key_form"):
            req_email = st.text_input("Enter your registered Email ID")
            submit_req = st.form_submit_button("Generate Reset Key")
            
            if submit_req:
                if req_email:
                    key = generate_reset_key_for_email(req_email)
                    if key:
                        st.session_state.generated_key = key
                        st.success("Reset key generated successfully!")
                    else:
                        st.error("No account found with this Email ID.")
                else:
                    st.warning("Please enter your Email ID.")

        if st.session_state.generated_key:
            st.info(f"🔑 **YOUR RESET KEY:** `{st.session_state.generated_key}`\n\nCopy and paste this key into Step 2 below.")
        
        st.divider()
        st.subheader("Step 2: Reset Password")
        with st.form("reset_pass_form"):
            reset_email = st.text_input("Confirm Email ID")
            rec_key = st.text_input("Reset Key")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            submit_reset = st.form_submit_button("Reset Password")
            
            if submit_reset:
                if not reset_email or not rec_key or not new_password or not confirm_password:
                    st.warning("Please complete all fields.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    status = reset_password_with_key(reset_email, rec_key, new_password)
                    if status == "SUCCESS":
                        st.session_state.generated_key = None
                        st.success("Password reset successful! You can now log in.")
                    elif status == "INVALID_KEY":
                        st.error("Invalid or expired Reset Key.")
                    else:
                        st.error("Email ID not found.")
    st.stop()

# ==========================================
# 4. DASHBOARD & LIVE EDITOR (LOGGED IN)
# ==========================================
top_left, top_right = st.columns([3, 1])
with top_left:
    st.title("📄 Resume Editor")
    st.caption(f"Logged in as: **{st.session_state.username}**")
with top_right:
    if st.button("Log Out"):
        st.session_state.user_id = None
        st.session_state.username = None
        st.rerun()

# Load saved resume data or defaults
saved_data = load_resume(st.session_state.user_id) or {}
col_builder, col_view = st.columns([1, 1], gap="medium")

with col_builder:
    st.subheader("🛠️ Personal Details")
    
    with st.expander("👤 Contact Details", expanded=True):
        name = st.text_input("Full Name", value=saved_data.get("name", "Jane Doe"))
        job_title = st.text_input("Job Title", value=saved_data.get("job_title", "Software Engineer"))
        email = st.text_input("Email", value=saved_data.get("email", "jane@example.com"))
        phone = st.text_input("Phone", value=saved_data.get("phone", "+1 555-0192"))
        location = st.text_input("Location", value=saved_data.get("location", "San Francisco, CA"))
        links = st.text_input("Links", value=saved_data.get("links", "github.com/janedoe"))

    with st.expander("📝 Summary", expanded=True):
        summary = st.text_area("Summary", value=saved_data.get("summary", "Experienced engineer specializing in cloud architecture."), height=80)

    with st.expander("💼 Experience", expanded=True):
        exp1_title = st.text_input("Role/Company", value=saved_data.get("exp1_title", "Senior Developer — Tech Corp"))
        exp1_date = st.text_input("Duration", value=saved_data.get("exp1_date", "2021 - Present"))
        exp1_desc = st.text_area("Responsibilities", value=saved_data.get("exp1_desc", "• Managed microservices infrastructure.\n• Reduced latency by 25%."), height=80)

    with st.expander("🎓 Education", expanded=False):
        edu = st.text_area("Education", value=saved_data.get("edu", "B.S. Computer Science — University of Tech (2017-2021)"), height=60)

    with st.expander("⚡ Skills", expanded=True):
        skills_raw = st.text_input("Comma-Separated Skills", value=saved_data.get("skills_raw", "Python, React, Docker, AWS, PostgreSQL"))

    if st.button("💾 Save Progress"):
        current_data = {
            "name": name, "job_title": job_title, "email": email, "phone": phone,
            "location": location, "links": links, "summary": summary,
            "exp1_title": exp1_title, "exp1_date": exp1_date, "exp1_desc": exp1_desc,
            "edu": edu, "skills_raw": skills_raw
        }
        save_resume(st.session_state.user_id, current_data)
        st.toast("Resume progress saved!", icon="🎉")

# Render Live Preview
skills_list = [s.strip() for s in skills_raw.split(",") if s.strip()]
skills_html = "".join([f'<span class="badge">{skill}</span>' for skill in skills_list])

resume_html = f"""
<div class="resume-preview">
    <div class="resume-header">
        <h1 class="resume-name">{name}</h1>
        <div class="resume-title">{job_title}</div>
        <div class="resume-contact">
            <span>📧 {email}</span>
            <span>📞 {phone}</span>
            <span>📍 {location}</span>
            <span>🔗 {links}</span>
        </div>
    </div>
    <div class="resume-section-title">Summary</div>
    <div style="font-size: 13px; color: #334155;">{summary}</div>
    <div class="resume-section-title">Experience</div>
    <div style="margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between; font-weight: 700; font-size: 13px;">
            <span>{exp1_title}</span>
            <span style="color: #64748b;">{exp1_date}</span>
        </div>
        <div style="font-size: 12.5px; color: #334155; whitespace: pre-line; margin-top: 3px;">{exp1_desc}</div>
    </div>
    <div class="resume-section-title">Education</div>
    <div style="font-size: 13px; color: #334155;">{edu}</div>
    <div class="resume-section-title">Skills</div>
    <div style="margin-top: 6px;">{skills_html}</div>
</div>
"""

with col_view:
    st.subheader("👁️ Live Preview")
    st.markdown(resume_html, unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    st.download_button(
        label="📥 Download HTML Resume",
        data=f"<!DOCTYPE html><html><head><title>{name} - Resume</title></head><body>{resume_html}</body></html>",
        file_name=f"{name.lower().replace(' ', '_')}_resume.html",
        mime="text/html"
    )
