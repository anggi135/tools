import os
import re
import io
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, abort
from dotenv import load_dotenv
import google.generativeai as genai
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY belum diset. Isi file .env Anda.")

# Konfigurasi Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(GEMINI_MODEL)

app = Flask(__name__)

# ====== In-memory store (demo) ======
# sessions: { session_id: {"messages": [(role, text, ts)], "report": {...}} }
sessions = {}

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

# ====== Prompt Dasar / Guardrails ======
SOP_PENTEST = r"""
Anda adalah Chatbot Pentesting etis. Ikuti SOP ringkas ini, bertahap dan aman:
1) Pra-Engagement & Scope: minta izin dan batasan (domain/subdomain/IP, waktu, larangan DoS, data sensitif).
2) Recon: pasif → aktif terukur.
3) Threat Modeling: aktor, aset, alur kritis, kontrol.
4) Scanning/Enumerasi: TLS, header, cookie, endpoint, metode HTTP, schema. Low & slow.
5) Uji OWASP: AuthZ/IDOR, Authn & session, Injeksi, XSS, CSRF, Upload, SSRF/XXE, API, Kripto, Logging/Monitoring.
6) Eksploitasi terbatas: PoC aman (tanpa destruksi, dummy data).
7) Pasca-eksploitasi: validasi chain/pivot aman & cleanup.
8) Risk rating: CVSS 3.1 + konteks bisnis, prioritas P1..P4.
9) Rekomendasi perbaikan: akar masalah → perbaikan → verifikasi.
10) Laporan & re-test.
Aturan: hanya untuk target dengan izin tertulis. Jangan berikan instruksi/payload destruktif, malware, DoS, atau akses tanpa izin. Fokus edukasi defensif dan hardening.
"""

STRUCTURED_OUTPUT_INSTRUCTION = r"""
Setiap jawaban harus diakhiri dengan blok JSON bertanda ```json REPORT_STATE``` berisi ringkasan terstruktur **tambahan** (bukan pengganti penjelasan):
{
  "phase": "Pra-Engagement | Recon | Threat-Modeling | Scanning | Testing | Exploitation | Post-Exploitation | Risk | Recommendation | Report",
  "target": "(jika ada)",
  "findings": [
    {"id": "FX-001", "title": "", "category": "OWASP/Config/Network", "severity": "P1|P2|P3|P4", "cvss": null, "evidence": "ringkas", "status": "Open|Mitigated|Accepted"}
  ],
  "recommendations": ["..."],
  "next_actions": ["..."]
}
Jika belum ada temuan, pakai array kosong dan tetap set "phase" sesuai konteks.
"""

SYSTEM_PROMPT = f"""
{SOP_PENTEST}
\nInstruksi format:
- Gunakan bahasa Indonesia yang jelas.
- Beri langkah-langkah konkret, aman, dan verifiable.
- Hindari data sensitif; gunakan contoh/dummy.
- Selalu minta/konfirmasi target & scope di awal sesi jika belum ada.
\n{STRUCTURED_OUTPUT_INSTRUCTION}
"""

# ====== Util: Extract REPORT_STATE JSON ======
REPORT_BLOCK_RE = re.compile(r"```json REPORT_STATE\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)

import json

def extract_report_state(text: str):
    match = REPORT_BLOCK_RE.search(text or "")
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except Exception:
        return None

# Merge report states (appenditive, by finding id)
def merge_report(base: dict, update: dict):
    if not update:
        return base
    base = base or {"phase": None, "target": None, "findings": [], "recommendations": [], "next_actions": []}
    base["phase"] = update.get("phase") or base.get("phase")
    base["target"] = update.get("target") or base.get("target")

    # merge findings by id
    existing = {f.get("id"): f for f in base.get("findings", []) if f.get("id")}
    for f in update.get("findings", []) or []:
        fid = f.get("id")
        if fid and fid in existing:
            existing[fid].update({k: v for k, v in f.items() if v is not None})
        else:
            base.setdefault("findings", []).append(f)

    # merge lists (dedupe)
    for key in ("recommendations", "next_actions"):
        combined = list(base.get(key, [])) + list(update.get(key, []) or [])
        dedup = []
        seen = set()
        for item in combined:
            s = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
            if s not in seen:
                seen.add(s)
                dedup.append(item)
        base[key] = dedup
    return base

# ====== Routes ======
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    user_msg = data.get("message", "").strip()
    if not session_id or not user_msg:
        return jsonify({"error": "session_id dan message wajib"}), 400

    state = sessions.setdefault(session_id, {"messages": [], "report": None})

    # rakit history untuk Gemini (role: user/assistant)
    history = []
    for role, text, _ in state["messages"]:
        history.append({"role": role, "parts": [text]})

    # prepend system prompt di awal percakapan
    prompt = SYSTEM_PROMPT + "\n\nUser: " + user_msg

    try:
        # gunakan generate_content dengan history ringkas
        response = model.generate_content([
            {"role": "user", "parts": [SYSTEM_PROMPT]},
            *history,
            {"role": "user", "parts": [user_msg]},
        ])
        bot_text = response.text or "(Tidak ada respons)"
    except Exception as e:
        bot_text = f"Maaf, terjadi kendala saat menghubungi model: {e}"

    # simpan pesan
    ts = now_iso()
    state["messages"].append(("user", user_msg, ts))
    state["messages"].append(("assistant", bot_text, ts))

    # coba ekstrak REPORT_STATE dan merge
    rs = extract_report_state(bot_text)
    state["report"] = merge_report(state.get("report"), rs)

    return jsonify({"response": bot_text})

@app.route("/export/pdf", methods=["GET"])
def export_pdf():
    session_id = request.args.get("session_id")
    if not session_id or session_id not in sessions:
        return abort(404)

    state = sessions[session_id]
    report = state.get("report") or {}
    messages = state.get("messages", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    title = "Laporan Ringkas Penetration Testing (Chatbot Pentest)"
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 0.4*cm))

    meta = [
        ["Tanggal", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Session ID", session_id],
        ["Target", report.get("target") or "-"],
        ["Fase Terakhir", report.get("phase") or "-"],
    ]
    t = Table(meta, hAlign='LEFT', colWidths=[4*cm, 10*cm])
    t.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
        ('BACKGROUND', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Ringkasan Temuan", styles["Heading2"]))
    findings = report.get("findings") or []
    if findings:
        rows = [["ID", "Judul", "Kategori", "Severity", "CVSS", "Status", "Evidences"]]
        for f in findings:
            rows.append([
                f.get("id") or "-",
                f.get("title") or "-",
                f.get("category") or "-",
                f.get("severity") or "-",
                str(f.get("cvss") or "-"),
                f.get("status") or "Open",
                (f.get("evidence") or "-")[:120]
            ])
        ft = Table(rows, repeatRows=1)
        ft.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(ft)
    else:
        story.append(Paragraph("Belum ada temuan yang tercatat.", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Rekomendasi", styles["Heading2"]))
    recs = report.get("recommendations") or []
    if recs:
        for r in recs:
            story.append(Paragraph(f"• {r}", styles["Normal"]))
    else:
        story.append(Paragraph("Belum ada rekomendasi.", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Tindak Lanjut Berikutnya", styles["Heading2"]))
    nas = report.get("next_actions") or []
    if nas:
        for n in nas:
            story.append(Paragraph(f"• {n}", styles["Normal"]))
    else:
        story.append(Paragraph("Belum ada tindak lanjut.", styles["Normal"]))
    story.append(Spacer(1, 0.7*cm))

    story.append(Paragraph("Lampiran: Transkrip Percakapan (ringkas)", styles["Heading2"]))
    for role, text, ts in messages[-50:]:  # batasi 50 pesan terakhir
        who = "Pengguna" if role == "user" else "Asisten"
        story.append(Paragraph(f"<b>{who}</b> [{ts}]", styles["Normal"]))
        story.append(Paragraph(text.replace('\n', '<br/>'), styles["Normal"]))
        story.append(Spacer(1, 0.2*cm))

    doc.build(story)
    buf.seek(0)

    filename = f"laporan_pentest_{session_id[:8]}.pdf"
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name=filename)

@app.route("/reset", methods=["POST"])
def reset():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    if session_id in sessions:
        sessions.pop(session_id, None)
        return jsonify({"status": "reset"})
    return jsonify({"status": "not-found"}), 404

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # Untuk dev: app.run(debug=True). Produksi: waitress-serve
    app.run(host="0.0.0.0", port=port, debug=True)
    # Alternatif produksi:
    # from waitress import serve
    # serve(app, host="0.0.0.0", port=port)
