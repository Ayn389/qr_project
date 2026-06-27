import re
import os
import csv
import time
import cv2
import json
import requests
import threading
import numpy as np
from datetime import datetime
from urllib.parse import urlparse, parse_qs

ESP32_IP = "172.20.10.3"

CAPTURE_URL = f"http://{ESP32_IP}/capture"
FAKE_QR_LED_URL = f"http://{ESP32_IP}/fake_qr_led"

HISTORY_FILE = "qr_detection_history.csv"
EVIDENCE_DIR = "evidence"
TRUSTED_UPI_FILE = "trusted_upi.json"

os.makedirs(EVIDENCE_DIR, exist_ok=True)

ENABLE_VOICE_ALERT = True
ENABLE_NTFY_ALERT = True

NTFY_TOPIC = "qr-scam-detector-ayann"
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}"

suspicious_words = [
    "verify", "login", "bank", "prize", "claim",
    "winner", "gift", "urgent", "free", "update",
    "password", "account", "otp", "kyc"
]

shorteners = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "ow.ly", "shorturl.at", "rebrand.ly"
]


def get_frame_from_capture():
    try:
        response = requests.get(CAPTURE_URL, timeout=5)

        if response.status_code != 200:
            print("Capture HTTP error:", response.status_code)
            return None

        img_array = np.frombuffer(response.content, np.uint8)
        return cv2.imdecode(img_array, cv2.IMREAD_COLOR)

    except Exception as e:
        print("Capture error:", e)
        return None


def blink_fake_qr_led():
    try:
        r = requests.get(FAKE_QR_LED_URL, timeout=2)
        print("GPIO 13 LED alert:", r.text)
    except Exception as e:
        print("GPIO 13 LED Error:", e)


def speak_alert(text):
    if not ENABLE_VOICE_ALERT:
        return

    try:
        os.system(f'say "{text}"')
    except Exception as e:
        print("Voice alert error:", e)


def send_mobile_alert(qr_url, result, score, reasons):
    if not ENABLE_NTFY_ALERT:
        return

    try:
        reason_text = "\n".join("- " + r for r in reasons) if reasons else "No reason listed"

        message = f"""🚨 QR SCAM ALERT

Risk Level: {result}
Risk Score: {score}/100

QR Content:
{qr_url}

Reasons:
{reason_text}
"""

        response = requests.post(
            NTFY_URL,
            data=message.encode("utf-8"),
            headers={
                "Title": "QR Scam Detector",
                "Priority": "urgent",
                "Tags": "warning"
            },
            timeout=5
        )

        print("ntfy notification sent:", response.status_code)

    except Exception as e:
        print("ntfy notification error:", e)


def load_trusted_upi_ids():
    try:
        if not os.path.exists(TRUSTED_UPI_FILE):
            return []

        with open(TRUSTED_UPI_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return [x.lower() for x in data.get("trusted_upi_ids", [])]

    except Exception as e:
        print("Trusted UPI load error:", e)
        return []


def check_upi_whitelist(qr_data):
    qr_lower = qr_data.lower().strip()

    if not qr_lower.startswith("upi://"):
        return None, 0, []

    parsed = urlparse(qr_data)
    params = parse_qs(parsed.query)

    upi_id = params.get("pa", [""])[0].lower().strip()

    if not upi_id:
        return "SUSPICIOUS", 50, ["UPI QR missing payee address"]

    trusted = load_trusted_upi_ids()

    if upi_id in trusted:
        return "SAFE", 0, [f"Trusted UPI ID matched: {upi_id}"]

    return "HIGH RISK", 90, [
        f"Unknown UPI ID: {upi_id}",
        "Possible shop QR tampering detected"
    ]


def calculate_rule_risk(url):
    score = 0
    reasons = []
    breakdown = []
    u = url.lower().strip()

    valid_schemes = ("http://", "https://", "upi://")

    if not u.startswith(valid_schemes):
        score += 20
        reasons.append("Missing valid protocol")
        breakdown.append("Missing valid protocol +20")

    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", u):
        score += 35
        reasons.append("Uses IP address")
        breakdown.append("Raw IP address +35")

    for s in shorteners:
        if s in u:
            score += 25
            reasons.append("Uses URL shortener")
            breakdown.append("URL shortener +25")
            break

    for word in suspicious_words:
        if word in u:
            score += 10
            reasons.append(f"Contains suspicious word '{word}'")
            breakdown.append(f"Suspicious word '{word}' +10")

    if "www." in u and not re.search(r"\.(com|in|org|net|co|io|edu|gov)", u):
        score += 25
        reasons.append("Domain extension is missing or unusual")
        breakdown.append("Missing/unusual domain extension +25")

    if len(u) > 80:
        score += 10
        reasons.append("Very long URL")
        breakdown.append("Very long URL +10")

    score = min(score, 100)

    if score >= 70:
        result = "HIGH RISK"
    elif score >= 30:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    return result, score, reasons, breakdown


def final_risk_check(qr_data):
    upi_result, upi_score, upi_reasons = check_upi_whitelist(qr_data)

    if upi_result:
        return upi_result, upi_score, upi_reasons, upi_reasons

    return calculate_rule_risk(qr_data)


def save_evidence(frame, result):
    if result == "SAFE":
        return ""

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{result.replace(' ', '_').lower()}_{ts}.jpg"
    path = os.path.join(EVIDENCE_DIR, filename)

    cv2.imwrite(path, frame)
    return path


def save_detection(qr_data, result, score, reasons, score_breakdown, evidence_path):
    file_exists = os.path.exists(HISTORY_FILE)

    with open(HISTORY_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp",
                "qr_data",
                "result",
                "risk_score",
                "reasons",
                "score_breakdown",
                "evidence_path"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            qr_data,
            result,
            score,
            " | ".join(reasons),
            " | ".join(score_breakdown),
            evidence_path
        ])


def decode_qr(frame, detector):
    data, points, _ = detector.detectAndDecode(frame)

    if data:
        return data, points

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    data, points, _ = detector.detectAndDecode(gray)

    if data:
        return data, points

    gray_eq = cv2.equalizeHist(gray)
    data, points, _ = detector.detectAndDecode(gray_eq)

    if data:
        return data, points

    blur = cv2.GaussianBlur(gray_eq, (3, 3), 0)
    sharp = cv2.addWeighted(gray_eq, 1.8, blur, -0.8, 0)

    data, points, _ = detector.detectAndDecode(sharp)

    if data:
        return data, points

    big = cv2.resize(sharp, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    data, points, _ = detector.detectAndDecode(big)

    if data and points is not None:
        points = points / 2

    return data, points


def draw_qr_box(frame, points, color):
    if points is None:
        return

    try:
        pts = points.astype(int)

        for i in range(4):
            pt1 = tuple(pts[0][i])
            pt2 = tuple(pts[0][(i + 1) % 4])
            cv2.line(frame, pt1, pt2, color, 3)

        center_x = int(sum(p[0] for p in pts[0]) / 4)
        center_y = int(sum(p[1] for p in pts[0]) / 4)

        cv2.circle(frame, (center_x, center_y), 7, color, -1)

    except Exception:
        pass


detector = cv2.QRCodeDetector()

print("===================================")
print("AI QR Code Scam Detector Started")
print("Risk Score + Evidence + Voice Enabled")
print("Press ESC to Exit")
print("===================================")

last_data = ""
last_scan_time = 0
SCAN_RESET_SECONDS = 5

try:
    while True:
        frame = get_frame_from_capture()

        if frame is None:
            print("Frame not received")
            time.sleep(1)
            continue

        frame = cv2.resize(frame, None, fx=2, fy=2)

        data, points = decode_qr(frame, detector)

        if time.time() - last_scan_time > SCAN_RESET_SECONDS:
            last_data = ""

        if data:
            result, risk_score, reasons, score_breakdown = final_risk_check(data)

            if result == "SAFE":
                color = (0, 255, 0)
            elif result == "SUSPICIOUS":
                color = (0, 255, 255)
            else:
                color = (0, 0, 255)

            draw_qr_box(frame, points, color)

            if data != last_data:
                evidence_path = save_evidence(frame, result)

                save_detection(
                    data,
                    result,
                    risk_score,
                    reasons,
                    score_breakdown,
                    evidence_path
                )

                print("\n========================")
                print("QR CODE DETECTED:")
                print(data)
                print("Result:", result)
                print("Risk Score:", risk_score)

                if reasons:
                    print("Reasons:")
                    for r in reasons:
                        print("-", r)

                if score_breakdown:
                    print("Score Breakdown:")
                    for b in score_breakdown:
                        print("-", b)

                if evidence_path:
                    print("Evidence saved:", evidence_path)

                print("========================")

                if result in ["SUSPICIOUS", "HIGH RISK"]:
                    threading.Thread(target=blink_fake_qr_led, daemon=True).start()

                    threading.Thread(
                        target=send_mobile_alert,
                        args=(data, result, risk_score, reasons),
                        daemon=True
                    ).start()

                    threading.Thread(
                        target=speak_alert,
                        args=(f"Warning. {result} QR code detected. Risk score {risk_score} out of 100.",),
                        daemon=True
                    ).start()

                last_data = data
                last_scan_time = time.time()

            cv2.putText(
                frame,
                f"{result} | Risk: {risk_score}/100",
                (20, 60),
                cv2.FONT_HERSHEY_SIMPLEX,
                1.0,
                color,
                3
            )

            cv2.putText(
                frame,
                data[:55],
                (20, 110),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                color,
                2
            )

        else:
            cv2.putText(
                frame,
                "Looking for QR...",
                (20, 60),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8,
                (255, 255, 255),
                2
            )

        cv2.imshow("AI QR Code Scam Detector", frame)

        if cv2.waitKey(1) == 27:
            break

except KeyboardInterrupt:
    print("\nProgram stopped by user.")

finally:
    cv2.destroyAllWindows()