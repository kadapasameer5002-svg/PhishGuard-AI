# AI-Powered Phishing URL Detection System (SentinelURL)

SentinelURL is a professional cybersecurity application designed to identify and analyze potentially malicious or phishing URLs. The system aggregates static detection checks, calculates a weighted risk score, and utilizes the Groq Cloud API (Llama model) to provide natural language explanations of threat profiles, impacts, and recommendations.

---

## 🚀 Key Features

1. **6-Point Static Heuristic Check**:
   - **HTTPS Verification**: Identifies whether the site employs standard SSL/TLS encryption.
   - **IP Address Detection**: Detects direct IP-based links frequently used to bypass domain reputation checks.
   - **Suspicious Keyword Detection**: Scans for phishing terms like `login`, `secure`, `banking`, `verify`, and others.
   - **Risky TLD Analysis**: Identifies suspicious domains ending in TLDs like `.xyz`, `.tk`, `.ml`, etc.
   - **URL Length Analysis**: Flags long obfuscated URLs (greater than 50 characters).
   - **Special Character Analysis**: Detects userinfo syntax (`@`), excessive subdomains, url-encoding, and excessive hyphen usage.

2. **Weighted Risk Engine**:
   - Scores threats up to a maximum cap of `100`.
   - Categorizes threats into **LOW** (0-30), **MEDIUM** (31-60), and **HIGH** (61-100) risk levels.

3. **Llama-Powered AI Threat Analysis**:
   - Harnesses the Groq API (`llama-3.1-8b-instant`) to synthesize dynamic threat breakdowns, security impacts, and defenses.
   - Provides a rule-based fallback mode in case of API rate limits or network issues.

4. **Persistence & Auditing**:
   - Saves all scanned URLs and reports in a local **SQLite3** database.
   - Prevents SQL Injection via parameterized queries.

5. **Premium Cyberpunk Dashboard**:
   - A dark-theme responsive UI built with HTML5, CSS3, and Vanilla JavaScript.
   - Includes real-time history filtering and counting/glow animations for threat levels.

---

## 📁 Directory Structure

```
cyberpro/
├── app.py                     # Flask main application & server
├── database.db                # SQLite3 database (generated automatically)
├── requirements.txt           # Python dependency requirements
├── .env                       # Environment credentials (holds Groq API Key)
├── templates/
│   ├── index.html             # Dashboard URL input & scan page
│   ├── result.html            # Detailed threat report card
│   └── history.html           # Historical scan lists
├── static/
│   ├── style.css              # Cyber-themed CSS styles
│   └── script.js              # Interactivity, gauges, and filtering
└── utils/
    ├── __init__.py            # Package initializer
    ├── analyzer.py            # Static analysis checks implementation
    ├── risk_engine.py         # Weighted risk evaluation & thresholds
    └── ai_analyzer.py         # Groq AI analysis & fallback logic
```

---

## 🔧 Installation & Setup

1. **Prerequisites**: Ensure Python 3.8+ is installed on your system.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure Environment Variables**:
   Create a `.env` file in the root directory (this is already set up with your key):
   ```env
   GROQ_API_KEY=your_groq_api_key_here
   HOST=127.0.0.1
   PORT=5000
   ```
4. **Launch the Server**:
   ```bash
   python app.py
   ```
5. **Access the System**: Open `http://127.0.0.1:5000` in your web browser.

---

## 🛠️ Technology Stack
- **Backend**: Python Flask
- **Database**: SQLite3
- **AI Engine**: Groq Cloud API (Llama 3.1 8B Instant)
- **Frontend**: HTML5, CSS3 (Vanilla), Vanilla JavaScript, FontAwesome
- render live link : https://phishguard-ai-ppto.onrender.com
