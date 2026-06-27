import os
import json
import pandas as pd
from flask import Flask, render_template, send_from_directory, request, redirect, url_for, jsonify

app = Flask(__name__)

HISTORY_FILE = "qr_detection_history.csv"
EVIDENCE_DIR = "evidence"
TRUSTED_UPI_FILE = "trusted_upi.json"


def load_trusted_upi():
    if not os.path.exists(TRUSTED_UPI_FILE):
        return []

    with open(TRUSTED_UPI_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return data.get("trusted_upi_ids", [])


def save_trusted_upi(upi_list):
    with open(TRUSTED_UPI_FILE, "w", encoding="utf-8") as f:
        json.dump({"trusted_upi_ids": upi_list}, f, indent=2)


def load_data():
    cols = [
        "timestamp",
        "qr_data",
        "result",
        "risk_score",
        "reasons",
        "score_breakdown",
        "evidence_path"
    ]

    if not os.path.exists(HISTORY_FILE):
        return pd.DataFrame(columns=cols)

    try:
        df = pd.read_csv(HISTORY_FILE)
    except Exception:
        return pd.DataFrame(columns=cols)

    for col in cols:
        if col not in df.columns:
            df[col] = ""

    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0).astype(int)

    return df


@app.route("/")
def home():
    df = load_data()

    total = len(df)
    safe = len(df[df["result"] == "SAFE"])
    suspicious = len(df[df["result"] == "SUSPICIOUS"])
    high_risk = len(df[df["result"] == "HIGH RISK"])

    latest = None
    latest_image = None

    if total > 0:
        latest = df.iloc[-1].to_dict()
        evidence_path = str(latest.get("evidence_path", ""))

        if evidence_path and evidence_path != "nan":
            latest_image = os.path.basename(evidence_path)

    records = df.tail(30).iloc[::-1].to_dict(orient="records")
    trusted_upi_ids = load_trusted_upi()

    return render_template(
        "index.html",
        total=total,
        safe=safe,
        suspicious=suspicious,
        high_risk=high_risk,
        latest=latest,
        latest_image=latest_image,
        records=records,
        trusted_upi_ids=trusted_upi_ids
    )


@app.route("/gallery")
def gallery():
    df = load_data()

    risky = df[
        (df["evidence_path"].notna()) &
        (df["evidence_path"] != "")
    ]

    records = risky.sort_values("timestamp", ascending=False).to_dict(orient="records")

    return render_template("gallery.html", records=records)


@app.route("/add_upi", methods=["POST"])
def add_upi():
    upi_id = request.form.get("upi_id", "").strip().lower()
    upi_list = load_trusted_upi()

    if upi_id and upi_id not in upi_list:
        upi_list.append(upi_id)
        save_trusted_upi(upi_list)

    return redirect(url_for("home"))


@app.route("/delete_upi/<path:upi_id>")
def delete_upi(upi_id):
    upi_list = load_trusted_upi()
    upi_list = [x for x in upi_list if x != upi_id]
    save_trusted_upi(upi_list)

    return redirect(url_for("home"))


@app.route("/api/data")
def api_data():
    df = load_data()
    return jsonify(df.tail(30).iloc[::-1].to_dict(orient="records"))


@app.route("/evidence/<path:filename>")
def evidence(filename):
    return send_from_directory(EVIDENCE_DIR, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)