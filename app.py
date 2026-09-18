import os
import sqlite3
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv

# Import utilities
from utils.analyzer import validate_url, analyze_url
from utils.risk_engine import calculate_risk
from utils.ai_analyzer import generate_ai_explanation

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "cybersecurity_phishing_detector_key_2026")

DATABASE = 'database.db'

def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    Enables Row factory to access columns by name.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the SQLite database and creates the scan_history table if it does not exist.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                detected_issues TEXT NOT NULL,
                ai_analysis TEXT NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Run database initialization
init_db()

@app.route('/')
def index():
    """
    Renders the main scanning dashboard (Home Page).
    """
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Validates and analyzes the submitted URL.
    Saves the report to SQLite3 and returns the details.
    Supports both traditional Form POST and JSON/AJAX requests.
    """
    # Check if request is JSON or form
    if request.is_json:
        data = request.get_json()
        url = data.get('url', '').strip()
    else:
        url = request.form.get('url', '').strip()

    # URL Validation
    if not url:
        error_msg = "URL cannot be empty."
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 400
        else:
            flash(error_msg, "error")
            return redirect(url_for('index'))

    if not validate_url(url):
        error_msg = "Invalid URL. Please enter a valid URL starting with http:// or https://"
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 400
        else:
            flash(error_msg, "error")
            return redirect(url_for('index'))

    try:
        # 1. Perform static analysis checks
        analysis_result = analyze_url(url)
        detected_issues = analysis_result["detected_issues"]

        # 2. Calculate risk score & classification
        risk_score, risk_level = calculate_risk(analysis_result)

        # 3. Call Groq API for threat explanation
        ai_explanation = generate_ai_explanation(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            detected_issues=detected_issues
        )

        # 4. Save results to the SQLite3 Database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Serialize detected issues list to JSON string for database storage
        issues_json = json.dumps(detected_issues)
        
        cursor.execute(
            '''
            INSERT INTO scan_history (url, risk_score, risk_level, detected_issues, ai_analysis)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (url, risk_score, risk_level, issues_json, ai_explanation)
        )
        conn.commit()
        scan_id = cursor.lastrowid
        conn.close()

        # Build response data structure
        # Format Recommendations based on risk score and level
        recommendations = []
        if risk_level == "HIGH":
            recommendations = [
                "Avoid entering passwords",
                "Avoid entering OTPs",
                "Verify website ownership",
                "Visit official websites only"
            ]
        elif risk_level == "MEDIUM":
            recommendations = [
                "Verify the domain name carefully (look for typos)",
                "Avoid entering financial details",
                "Do not download attachments from this page",
                "Use a web scanner to verify authenticity"
            ]
        else:
            recommendations = [
                "Regular security browsing guidelines apply",
                "Ensure your browser and extensions are up to date",
                "Always check for a valid SSL certificate"
            ]

        response_data = {
            "id": scan_id,
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detected_issues": detected_issues,
            "ai_analysis": ai_explanation,
            "recommendations": recommendations,
            "scan_time": "Just now"
        }

        if request.is_json:
            return jsonify({"success": True, "data": response_data})
        else:
            # Render templates/result.html with the parsed results
            return render_template('result.html', result=response_data)

    except Exception as e:
        logger.error(f"Error analyzing URL: {e}")
        error_msg = f"An internal error occurred during analysis: {str(e)}"
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 500
        else:
            flash(error_msg, "error")
            return redirect(url_for('index'))

@app.route('/history')
def history():
    """
    Renders the scan history table page.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, url, risk_score, risk_level, scan_time FROM scan_history ORDER BY scan_time DESC"
        )
        rows = cursor.fetchall()
        conn.close()
        
        scans = []
        for row in rows:
            scans.append({
                "id": row["id"],
                "url": row["url"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "scan_time": row["scan_time"]
            })
            
        return render_template('history.html', scans=scans)
    except Exception as e:
        logger.error(f"Error loading scan history: {e}")
        flash("Failed to load scan history.", "error")
        return render_template('history.html', scans=[])

@app.route('/report/<int:scan_id>')
def report(scan_id):
    """
    Renders the detailed phishing report page for a previous scan.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            flash("Report not found.", "error")
            return redirect(url_for('index'))

        detected_issues = json.loads(row["detected_issues"])
        risk_level = row["risk_level"]
        risk_score = row["risk_score"]

        # Recommendations assignment
        recommendations = []
        if risk_level == "HIGH":
            recommendations = [
                "Avoid entering passwords",
                "Avoid entering OTPs",
                "Verify website ownership",
                "Visit official websites only"
            ]
        elif risk_level == "MEDIUM":
            recommendations = [
                "Verify the domain name carefully (look for typos)",
                "Avoid entering financial details",
                "Do not download attachments from this page",
                "Use a web scanner to verify authenticity"
            ]
        else:
            recommendations = [
                "Regular security browsing guidelines apply",
                "Ensure your browser and extensions are up to date",
                "Always check for a valid SSL certificate"
            ]

        result_data = {
            "id": row["id"],
            "url": row["url"],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detected_issues": detected_issues,
            "ai_analysis": row["ai_analysis"],
            "recommendations": recommendations,
            "scan_time": row["scan_time"]
        }

        return render_template('result.html', result=result_data)
    except Exception as e:
        logger.error(f"Error loading report {scan_id}: {e}")
        flash("Failed to load report details.", "error")
        return redirect(url_for('history'))

@app.route('/api/history')
def api_history():
    """
    Returns scan history JSON data.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, url, risk_score, risk_level, scan_time, detected_issues FROM scan_history ORDER BY scan_time DESC"
        )
        rows = cursor.fetchall()
        conn.close()
        
        scans = []
        for row in rows:
            scans.append({
                "id": row["id"],
                "url": row["url"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "scan_time": row["scan_time"],
                "detected_issues": json.loads(row["detected_issues"])
            })
            
        return jsonify({"success": True, "data": scans})
    except Exception as e:
        logger.error(f"API Error loading history: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    # Retrieve configuration from environment variables or defaults
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    app.run(host=host, port=port, debug=True)
