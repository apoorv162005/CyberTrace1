import os
import re
import uuid
import hashlib
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB

ALLOWED_EXTENSIONS = {
    "txt", "log", "csv", "json", "xml",
    "pdf", "docx", "jpg", "jpeg", "png",
    "zip", "py", "js", "html", "md"
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIME_RE = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"|\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})\b"
)
USER_RE = re.compile(r"(?:user(?:name)?|account|login)\s*[=:]\s*([A-Za-z0-9_.@-]+)", re.I)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_hashes(path):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def get_file_metadata(path):
    stat = path.stat()
    return {
        "name": path.name,
        "size": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension": path.suffix.lower() or "none",
    }


def extract_log_data(text):
    ips = sorted(set(IP_RE.findall(text)))

    # Keep only valid-looking IPv4 addresses.
    valid_ips = []
    for ip in ips:
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)

    timestamps = TIME_RE.findall(text)
    usernames = sorted(set(m.group(1) for m in USER_RE.finditer(text)))

    failed_keywords = [
        "failed login", "login failed", "authentication failure",
        "invalid password", "access denied", "failed authentication"
    ]
    failed_count = sum(
        text.lower().count(keyword) for keyword in failed_keywords
    )

    suspicious_lines = []
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in failed_keywords):
            suspicious_lines.append(line.strip()[:250])

    return {
        "ips": valid_ips,
        "timestamps": timestamps[:100],
        "usernames": usernames[:100],
        "failed_count": failed_count,
        "suspicious_lines": suspicious_lines[:50],
    }


def analyze_file(path):
    md5, sha256 = calculate_hashes(path)
    metadata = get_file_metadata(path)

    result = {
        **metadata,
        "md5": md5,
        "sha256": sha256,
        "log_analysis": None,
        "risk": "LOW",
        "risk_reasons": []
    }

    # Only inspect text/log-like files as text.
    if path.suffix.lower() in {".txt", ".log", ".csv", ".json", ".xml", ".md"}:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            log_data = extract_log_data(text)
            result["log_analysis"] = log_data

            if log_data["failed_count"] >= 10:
                result["risk"] = "HIGH"
                result["risk_reasons"].append(
                    f"{log_data['failed_count']} failed-login/authentication events found"
                )
            elif log_data["failed_count"] >= 5:
                result["risk"] = "MEDIUM"
                result["risk_reasons"].append(
                    f"{log_data['failed_count']} failed-login/authentication events found"
                )

            if len(log_data["ips"]) >= 10:
                result["risk"] = "HIGH"
                result["risk_reasons"].append(
                    f"{len(log_data['ips'])} unique IP addresses detected"
                )
            elif len(log_data["ips"]) >= 5 and result["risk"] == "LOW":
                result["risk"] = "MEDIUM"
                result["risk_reasons"].append(
                    f"{len(log_data['ips'])} unique IP addresses detected"
                )

            if not result["risk_reasons"]:
                result["risk_reasons"].append(
                    "No predefined suspicious log pattern was detected"
                )
        except Exception as exc:
            result["risk_reasons"].append(f"Text analysis skipped: {exc}")
    else:
        result["risk_reasons"].append(
            "Metadata and cryptographic hashes generated; deep content analysis not enabled for this file type."
        )

    return result


def create_pdf_report(result, case_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return None

    output = REPORT_DIR / f"{case_id}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(output), pagesize=A4)
    story = [
        Paragraph("CyberTrace - Digital Forensics Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Case ID: {case_id}", styles["Normal"]),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        ),
        Spacer(1, 12),
    ]

    data = [
        ["Field", "Value"],
        ["File", result["name"]],
        ["Size", f"{result['size']} bytes"],
        ["Type", result["extension"]],
        ["Created", result["created"]],
        ["Modified", result["modified"]],
        ["MD5", result["md5"]],
        ["SHA-256", result["sha256"]],
        ["Risk", result["risk"]],
    ]

    table = Table(data, colWidths=[110, 390])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Risk indicators", styles["Heading2"]))

    for reason in result["risk_reasons"]:
        story.append(Paragraph(f"• {reason}", styles["Normal"]))

    if result["log_analysis"]:
        la = result["log_analysis"]
        story.append(Spacer(1, 10))
        story.append(Paragraph("Log analysis", styles["Heading2"]))
        story.append(Paragraph(
            f"Unique IP addresses: {len(la['ips'])}", styles["Normal"]
        ))
        story.append(Paragraph(
            f"Usernames found: {', '.join(la['usernames']) or 'None'}",
            styles["Normal"]
        ))
        story.append(Paragraph(
            f"Failed authentication events: {la['failed_count']}",
            styles["Normal"]
        ))

    doc.build(story)
    return output


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("evidence")

    if not uploaded or not uploaded.filename:
        flash("Please select an evidence file.")
        return redirect(url_for("index"))

    if not allowed_file(uploaded.filename):
        flash("Unsupported file type.")
        return redirect(url_for("index"))

    original_name = secure_filename(uploaded.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    path = UPLOAD_DIR / unique_name
    uploaded.save(path)

    try:
        result = analyze_file(path)
    except Exception as exc:
        path.unlink(missing_ok=True)
        flash(f"Analysis failed: {exc}")
        return redirect(url_for("index"))

    case_id = f"CT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    return render_template("result.html", result=result, case_id=case_id)


@app.route("/report", methods=["POST"])
def report():
    # Reconstruct report from form fields so no server-side result object is required.
    result = {
        "name": request.form["name"],
        "size": int(request.form["size"]),
        "extension": request.form["extension"],
        "created": request.form["created"],
        "modified": request.form["modified"],
        "md5": request.form["md5"],
        "sha256": request.form["sha256"],
        "risk": request.form["risk"],
        "risk_reasons": request.form.getlist("risk_reason"),
        "log_analysis": None
    }

    case_id = request.form["case_id"]
    output = create_pdf_report(result, case_id)

    if output is None:
        flash("Install reportlab first: pip install reportlab")
        return redirect(url_for("index"))

    return send_file(output, as_attachment=True, download_name=f"{case_id}.pdf")


@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum size is 25 MB.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
