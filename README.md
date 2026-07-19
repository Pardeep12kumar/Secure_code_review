# Secure Code View

Secure Code View is a Flask-based web application designed to help developers perform secure code reviews by analyzing uploaded source code for common security vulnerabilities. The application provides an intuitive dashboard for managing uploaded files, scanning code, reviewing findings, and exporting security reports.

---

## Features

- User Registration and Login
- Secure Password Hashing
- Session Management
- Source Code Upload
- Automatic Programming Language Detection
- Static Security Analysis
- Vulnerability Detection
- Severity Classification (High, Medium, Low)
- Security Scan Dashboard
- Search and Filter Vulnerabilities
- Security Scan Reports
- PDF Report Export
- CSV Report Export
- File Management
- User Profile Dashboard

---

## Supported Languages

- Python
- Java
- C
- C++
- JavaScript

---

## Vulnerabilities Detected

The application currently detects several common secure coding issues, including:

- Use of `eval()`
- Use of `exec()`
- Insecure `pickle` deserialization
- Hardcoded passwords
- Hardcoded API keys
- Dangerous `subprocess` usage with `shell=True`

---

## Technology Stack

### Backend

- Python 3
- Flask
- Flask-SQLAlchemy
- Flask-Login
- SQLite

### Frontend

- HTML5
- Bootstrap 5
- CSS3
- Jinja2 Templates

### Reporting

- ReportLab
- CSV Export

---

## Project Structure

```text
SecureCodeView/
│
├── app/
│   ├── forms/
│   ├── routes/
│   ├── static/
│   ├── templates/
│   ├── utils/
│   └── __init__.py
│
├── models/
│   ├── uploaded_file.py
│   ├── scan_result.py
│   └── user.py
│
├── services/
│   ├── analyzer.py
│   ├── python_rules.py
│   └── java_rules.py
│
├── uploads/
├── instance/
├── config.py
├── app.py
├── requirements.txt
└── README.md
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/SecureCodeView.git

cd SecureCodeView
```

---

### 2. Create a Virtual Environment

#### Linux

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Run the Application

```bash
python app.py
```

---

Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## Application Workflow

1. Register a new account.
2. Log in securely.
3. Upload a supported source code file.
4. Start a security scan.
5. Review detected vulnerabilities.
6. Filter or search scan results.
7. Export reports in PDF or CSV format.
8. Manage uploaded files from the dashboard.

---

## Security Features

- Password hashing
- Secure file uploads
- File type validation
- Session-based authentication
- User authorization
- Access control
- CSRF protection through Flask-WTF
- SQLAlchemy ORM for database security

---

## Future Enhancements

- Bandit Integration
- Semgrep Integration
- Multi-language vulnerability engine
- AI-assisted vulnerability explanation
- Remediation suggestions
- Email report delivery
- Risk scoring dashboard
- Admin Panel
- Scan history
- Dark Mode

---

## Screenshots

Add screenshots of:

- Home Page
- Login Page
- Dashboard
- File Upload
- Scan Results
- PDF Report
- User Profile

---

## License

This project is developed for educational purposes and secure software development learning.

---

## Author

**Pardeep Kumar**

Cybersecurity Enthusiast

GitHub: https://github.com/Pardeep12kumar
