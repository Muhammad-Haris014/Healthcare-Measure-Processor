# Healthcare Measure Processor

A secure, Streamlit-based application designed for processing healthcare measures with robust password-based authentication.

---

## 🚀 Overview

The Healthcare Measure Processor enables users to securely upload, process, and export healthcare data. Built in Python with Streamlit for an interactive frontend, it features role-based access control, strong security practices, and a user-friendly interface.

---

## 🔒 Authentication & Security Features

- **Strong password hashing:** PBKDF2-HMAC-SHA256, 100,000 iterations, 32-byte salt
- **Role-based access:** Admin and User roles
- **Brute-force protection:** Configurable lockout after multiple failed logins
- **Session management:** Persistent authentication during app usage
- **Admin security panel:** Manage failed attempts, credentials, and see session info


---

## 🗂️ Features

- Upload, validate, and process healthcare measure files
- Export processed data to Excel or other formats
- Clean, modern, and intuitive UI
- Admin/security panel for monitoring activity
- Easy password rotation and role management

---

## ⚡ Quick Start

### 1. **Clone and Install Requirements**

```bash
pip install -r requirements.txt
```

### 2. **Set Up Credentials**

Generate secure password hashes with:
```bash
python hash_password.py
```
Set the outputs as environment variables, or add them to a `.env` file at the root:

```
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_admin_password_hash_here
ADMIN_PASSWORD_SALT=your_admin_password_salt_here
# Optionally, regular user creds:
USER_USERNAME=user
USER_PASSWORD_HASH=your_user_password_hash_here
USER_PASSWORD_SALT=your_user_password_salt_here
```

> **Never commit your real credentials or `.env` file to version control.**

### 3. **(Optional) Configure Security**
Edit `auth_config.py` or use environment variables to change:
- `MAX_FAILED_ATTEMPTS` (default: 5)
- `LOCKOUT_DURATION_MINUTES` (default: 5)
- `PASSWORD_SALT_LENGTH` (default: 32)

### 4. **Activate Virtual Environment & Run**

On Windows PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
venv\Scripts\activate
```

Then start the app:
```bash
streamlit run app.py
```

---

## 🧪 Testing (Manual & Unit)

- Login with valid/invalid credentials
- Test brute-force and lockout
- Admin and user functionality
- Export, processing, and logout behavior

Check `AUTHENTICATION_README.md` and `IMPLEMENTATION_SUMMARY.md` for detailed test checklists and advanced usage.

---

## 👮 Security Best Practices

- **Never store credentials in code or commit secrets**
- **Rotate passwords regularly**
- **Monitor failed attempts** via the Admin Panel
- **Use HTTPS** in production

---

## 🛠️ Tech Stack
- Python 3.9+
- Streamlit
- pandas, openpyxl
- Custom authentication in `auth_config.py`

---

## 📂 Key Files
- `app.py` — Main Streamlit Application
- `auth_config.py` — Authentication logic/config
- `hash_password.py` — Generate secure password hashes
- `requirements.txt` — Python dependencies
- `AUTHENTICATION_README.md` — Security/user guide
- `IMPLEMENTATION_SUMMARY.md` — Build/developer summary
- `config.example.txt` — Example credential config

---

## 📝 Contribution & Support
- For issues, start by reviewing the documentation and code comments
- For configuration, check `auth_config.py` and all readme files
- PRs welcome! (remove sensitive data before sharing code)

---

## 📣 Notes & Future Directions
- The authentication system is a transparent, secure layer atop existing healthcare measure processing logic
- Plans for password reset, audit logging, 2FA, and improved user management

---

## 📜 License
This project is for demonstration/educational use. For production, review and address all security warnings.

