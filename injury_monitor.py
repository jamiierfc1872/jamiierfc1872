import os
import re
import time
import json
import hashlib
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader

NBA_PAGE = "https://official.nba.com/nba-injury-report-2025-26-season/"
AK_BASE = "https://ak-static.cms.nba.com/referee/injury/"

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

PDF_STATE_FILE = "state.json"
TEAM_STATE_FILE = "team_state.json"
DEBUG_EXTRACT_FILE = "debug_extract.txt"

WINDOW_SECONDS = 180
CHECK_EVERY_SECONDS = 15
USER_AGENT = "Mozilla/5.0 (compatible; nba-injury-watcher/19.0)"

NOT_ON_REPORT = "NOT ON INJURY REPORT"

STATUS_WORDS = ("Out", "Questionable", "Doubtful", "Probable", "Available")
STATUS_MAP = {
    "out": "OUT",
    "questionable": "QUESTIONABLE",
    "doubtful": "DOUBTFUL",
    "probable": "PROBABLE",
    "available": "AVAILABLE",
}

TEAM_NAMES = [
    "Atlanta Hawks","Boston Celtics","Brooklyn Nets","Charlotte Hornets","Chicago Bulls",
    "Cleveland Cavaliers","Dallas Mavericks","Denver Nuggets","Detroit Pistons","Golden State Warriors",
    "Houston Rockets","Indiana Pacers","LA Clippers","Los Angeles Lakers","Memphis Grizzlies","Miami Heat",
    "Milwaukee Bucks","Minnesota Timberwolves","New Orleans Pelicans","New York Knicks",
    "Oklahoma City Thunder","Orlando Magic","Philadelphia 76ers","Phoenix Suns","Portland Trail Blazers",
    "Sacramento Kings","San Antonio Spurs","Toronto Raptors","Utah Jazz","Washington Wizards",
]

TEAM_NAMES_SORTED = sorted(TEAM_NAMES, key=len, reverse=True)
TEAM_LOWER_TO_PROPER = {t.lower(): t for t in TEAM_NAMES_SORTED}

TEAM_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in TEAM_NAMES_SORTED) + r")\b",
    flags=re.IGNORECASE
)

PLAYER_SAMELINE_REGEX = re.compile(
    r"^.*?([A-Za-zÀ-ÖØ-öø-ÿ' .-]+),\s*([A-Za-zÀ-ÖØ-öø-ÿ' .-]+)\s+("
    + "|".join(STATUS_WORDS)
    + r")\b",
    flags=re.IGNORECASE
)

NOT_YET_SUBMITTED_REGEX = re.compile(r"\bNOT YET SUBMITTED\b", flags=re.IGNORECASE)

HEADER_LINE_REGEX = re.compile(r"^Injury Report:", flags=re.IGNORECASE)
PAGE_LINE_REGEX = re.compile(r"^Page\s+\d+\s+of\s+\d+", flags=re.IGNORECASE)

LAST_SUFFIXES = {"JR", "JR.", "SR", "SR.", "II", "III", "IV", "V"}

FILENAME_DT_REGEX = re.compile(
    r"Injury-Report_(\d{4}-\d{2}-\d{2})_(\d{2})_(\d{2})(AM|PM)\.pdf",
    flags=re.IGNORECASE
)


def http_get(url: str) -> requests.Response:
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
    r.raise_for_status()
    return r


def http_try_get(url: str) -> requests.Response | None:
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=25)
        return r if r.status_code == 200 else None
    except Exception:
        return None


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def extract_pdf_text(pdf_bytes: bytes) -> str:
    tmp = "_tmp_injury.pdf"
    with open(tmp, "wb") as f:
        f.write(pdf_bytes)

    reader = PdfReader(tmp)
    parts = [(page.extract_text() or "") for page in reader.pages]

    try:
        os.remove(tmp)
    except OSError:
        pass

    return "\n".join(parts)


def normalize_lines(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if not line:
            continue
        if HEADER_LINE_REGEX.match(line):
            continue
        if PAGE_LINE_REGEX.match(line):
            continue
        out.append(line)
    return out


def parse_filename_dt(url: str) -> datetime | None:
    m = FILENAME_DT_REGEX.search(url)
    if not m:
        return None
    date_s, hh, mm, ap = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4).upper()
    if ap == "AM":
        hour = 0 if hh == 12 else hh
    else:
        hour = 12 if hh == 12 else hh + 12
    base = datetime.strptime(date_s, "%Y-%m-%d")
    return base.replace(hour=hour, minute=mm, second=0)


def format_dt_to_ak_url(dt: datetime) -> str:
    hour24 = dt.hour
    ap = "AM" if hour24 < 12 else "PM"
    hour12 = hour24 % 12
    if hour12 == 0:
        hour12 = 12
    return f"{AK_BASE}Injury-Report_{dt:%Y-%m-%d}_{hour12:02d}_{dt.minute:02d}{ap}.pdf"


def next_expected_url_from_base(base_url: str) -> str | None:
    dt = parse_filename_dt(base_url)
    if not dt:
        return None
    return format_dt_to_ak_url(dt + timedelta(minutes=15))


def find_latest_pdf_url_from_page() -> str | None:
    html = http_get(NBA_PAGE).text
    soup = BeautifulSoup(html, "html.parser")

    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "Injury-Report_" in href and href.lower().endswith(".pdf"):
            links.append(requests.compat.urljoin(NBA_PAGE, href))

    if not links:
        return None

    dated = []
    for u in links:
        dt = parse_filename_dt(u)
        if dt:
            dated.append((dt, u))

    if dated:
        dated.sort(key=lambda x: x[0])
        return dated[-1][1]

    return links[-1]


def escape_html(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def send_telegram_html(message_html: str):
    if not BOT_TOKEN or not CHAT_ID:
        print("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID.")
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message_html[:3900],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    
    try:
        r = requests.post(url, json=payload, timeout=25)
        r.raise_for_status()
        print(f"Message sent successfully to chat {CHAT_ID}")
    except Exception as e:
        print(f"Failed to send Telegram message: {e}")
        print(f"Bot token length: {len(BOT_TOKEN)}, Chat ID: {CHAT_ID}")


def _looks_like_team_or_header(line: str) -> bool:
    if TEAM_REGEX.search(line):
        return True
    if NOT_YET_SUBMITTED_REGEX.search(line):
        return True
    if "(" in line or ")" in line:
        return True
    return False


def _rebuild_last_name(lines: list[str], i: int, last_no_comma: str) -> str:
    last = last_no_comma.strip()
    if i <= 0:
        return last

    prev = lines[i - 1].strip()
    if _looks_like_team_or_header(prev):
        return last

    if prev.endswith("-"):
        return (prev + last).strip()

    if last.upper() in LAST_SUFFIXES:
        if re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ' .-]+", prev):
            return f"{prev} {last}".strip()

    return last


def parse_pdf_to_team_players(pdf_text: str):
    lines = normalize_lines(pdf_text)

    if os.environ.get("DEBUG_PARSE") == "1":
        with open(DEBUG_EXTRACT_FILE, "w", encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")

    team_players: dict[str, dict[str, str]] = {}
    team_submitted: dict[str, bool] = {}
    teams_seen: set[str] = set()
    current_team: str | None = None

    def maybe_set_team(idx: int):
        nonlocal current_team
        chunk = " ".join(lines[idx:idx + 4])
        matches = list(TEAM_REGEX.finditer(chunk))
        if not matches:
            return

        m = matches[0]
        proper = TEAM_LOWER_TO_PROPER.get(m.group(1).lower(), m.group(1))

        current_team = proper
        teams_seen.add(proper)
        team_players.setdefault(proper, {})
        team_submitted.setdefault(proper, True)

        if NOT_YET_SUBMITTED_REGEX.search(chunk):
            team_submitted[proper] = False

    i = 0
    while i < len(lines):
        maybe_set_team(i)
        line = lines[i]

        # Split-line player: "Last," / "First" / "Status"
        if line.endswith(",") and i + 2 < len(lines):
            last_no_comma = line[:-1].strip()
            first = lines[i + 1].strip()
            st_raw = lines[i + 2].strip().lower()

            if st_raw in STATUS_MAP and current_team:
                last_fixed = _rebuild_last_name(lines, i, last_no_comma)
                player = f"{first} {last_fixed}".strip()
                team_players[current_team][player] = STATUS_MAP[st_raw]
                team_submitted[current_team] = True
                i += 3
                continue

        # Same-line player
        pm = PLAYER_SAMELINE_REGEX.match(line)
        if pm and current_team:
            last = pm.group(1).strip()
            first = pm.group(2).strip()
            st_raw = pm.group(3).strip().lower()
            status = STATUS_MAP.get(st_raw, st_raw.upper())
            player = f"{first} {last}".strip()
            team_players[current_team][player] = status
            team_submitted[current_team] = True

        i += 1

    # keep teams with players; teams_seen keeps track of who was present in the PDF at all
    team_players = {t: p for t, p in team_players.items() if p}
    return team_players, team_submitted, teams_seen


def compute_team_changes(old_team: dict, new_team: dict):
    severity = {
        NOT_ON_REPORT: 0,
        "AVAILABLE": 0,
        "PROBABLE": 1,
        "QUESTIONABLE": 2,
        "DOUBTFUL": 3,
        "OUT": 4,
    }

    changes = []
    all_players = set(old_team.keys()) | set(new_team.keys())
    for player in all_players:
        old_s = old_team.get(player, NOT_ON_REPORT)
        new_s = new_team.get(player, NOT_ON_REPORT)
        if old_s == new_s:
            continue

        o = severity.get(old_s, 99)
        n = severity.get(new_s, 99)
        arrow = "⬆️" if n < o else "⬇️"
        changes.append((player, old_s, new_s, arrow))

    changes.sort(key=lambda x: x[0].lower())
    return changes


def reseed_baseline_from_url(pdf_url: str, pdf_state: dict):
    """
    Sets baseline WITHOUT sending notifications:
      - downloads pdf_url
      - parses team players
      - writes TEAM_STATE_FILE
      - updates state.json
    """
    r = http_try_get(pdf_url)
    if r is None:
        return False

    pdf_bytes = r.content
    pdf_sha = sha256_bytes(pdf_bytes)
    pdf_text = extract_pdf_text(pdf_bytes)
    text_sha = sha256_bytes(pdf_text.encode("utf-8", errors="ignore"))

    new_team_players, team_submitted, teams_seen = parse_pdf_to_team_players(pdf_text)

    # baseline only includes teams that actually have players in the report
    save_json(TEAM_STATE_FILE, new_team_players)

    pdf_state["last_pdf_url"] = pdf_url
    pdf_state["last_pdf_sha"] = pdf_sha
    pdf_state["last_text_sha"] = text_sha
    save_json(PDF_STATE_FILE, pdf_state)

    return True


def run_window():
    pdf_state = load_json(PDF_STATE_FILE, {"last_pdf_url": None, "last_pdf_sha": None, "last_text_sha": None})
    old_state = load_json(TEAM_STATE_FILE, {})

    # 1) ALWAYS scrape NBA page first
    page_latest = find_latest_pdf_url_from_page()
    if not page_latest:
        return

    # 1b) If our stored state is actually newer than the page (page lag), keep the newer one as base,
    # but we still scraped the page like you requested.
    base_url = page_latest
    base_dt = parse_filename_dt(page_latest)

    if pdf_state.get("last_pdf_url"):
        last_dt = parse_filename_dt(pdf_state["last_pdf_url"])
        if last_dt and base_dt and last_dt > base_dt:
            base_url = pdf_state["last_pdf_url"]
            base_dt = last_dt

    # 2) If this is a new day / you missed time blocks, reseed baseline to the current newest page report
    # (so you don't chase a "next" based off an old day)
    last_dt = parse_filename_dt(pdf_state["last_pdf_url"]) if pdf_state.get("last_pdf_url") else None
    if (not last_dt) or (base_dt and last_dt and base_dt.date() != last_dt.date()) or (base_dt and last_dt and base_dt > last_dt):
        # reseed baseline to page_latest specifically (not base_url), so your baseline matches the day's newest
        reseed_baseline_from_url(page_latest, pdf_state)
        pdf_state = load_json(PDF_STATE_FILE, {"last_pdf_url": None, "last_pdf_sha": None, "last_text_sha": None})
        old_state = load_json(TEAM_STATE_FILE, {})
        base_url = page_latest
        base_dt = parse_filename_dt(page_latest)

    # 3) Build next expected (+15min) from base
    target_url = next_expected_url_from_base(base_url)
    if not target_url:
        return

    # 4) Poll ONLY that target for up to 3 minutes
    start = time.time()
    pdf_bytes = None
    while (time.time() - start) < WINDOW_SECONDS:
        r = http_try_get(target_url)
        if r is not None:
            pdf_bytes = r.content
            break
        time.sleep(CHECK_EVERY_SECONDS)

   if pdf_bytes is None:
    # If next report isn't ready after 3 minutes, use the latest from the page as fallback
    print(f"Next report not available yet: {target_url}")
    print(f"Falling back to latest report from page: {page_latest}")
    r = http_try_get(page_latest)
    if r is None:
        return  # Can't get fallback either
    pdf_bytes = r.content
    target_url = page_latest  # Update target_url so we save the right one

    # 5) Parse + compare + notify
    pdf_sha = sha256_bytes(pdf_bytes)
    pdf_text = extract_pdf_text(pdf_bytes)
    text_sha = sha256_bytes(pdf_text.encode("utf-8", errors="ignore"))

    # If content hasn't changed, just update last markers and stop
    if text_sha == pdf_state.get("last_text_sha"):
        pdf_state["last_pdf_url"] = target_url
        pdf_state["last_pdf_sha"] = pdf_sha
        save_json(PDF_STATE_FILE, pdf_state)
        return

    new_team_players, team_submitted, teams_seen = parse_pdf_to_team_players(pdf_text)

    # If we have no baseline yet, set it and stop
    if not os.path.exists(TEAM_STATE_FILE) or old_state == {}:
        save_json(TEAM_STATE_FILE, new_team_players)
        pdf_state["last_pdf_url"] = target_url
        pdf_state["last_pdf_sha"] = pdf_sha
        pdf_state["last_text_sha"] = text_sha
        save_json(PDF_STATE_FILE, pdf_state)
        return

    # Only iterate teams that were actually seen in THIS PDF
    for team in sorted(teams_seen):
        # If not yet submitted, do NOT touch state and do NOT message
        if team_submitted.get(team) is False:
            continue

        old_team = old_state.get(team, {})
        new_team = new_team_players.get(team, {})

        # If both old and new are empty -> no point messaging
        if not old_team and not new_team:
            continue

        changes = compute_team_changes(old_team, new_team)
        if changes:
            msg_lines = [f"<b>{escape_html(team)}</b>"]
            for player, old_s, new_s, arrow in changes:
                # Always show OLD -> NEW (so Questionable -> Available is clear)
                msg_lines.append(f"{escape_html(player)} ({escape_html(old_s)} → {escape_html(new_s)}) {arrow}")
            msg_lines.append("")
            msg_lines.append(escape_html(target_url))
            send_telegram_html("\n".join(msg_lines))

        # Update state for this team (submitted teams only)
        old_state[team] = new_team

    save_json(TEAM_STATE_FILE, old_state)

    pdf_state["last_pdf_url"] = target_url
    pdf_state["last_pdf_sha"] = pdf_sha
    pdf_state["last_text_sha"] = text_sha
    save_json(PDF_STATE_FILE, pdf_state)


def run_once_try():
    # single attempt (no 3-min loop) – useful for quick testing
    pdf_state = load_json(PDF_STATE_FILE, {"last_pdf_url": None, "last_pdf_sha": None, "last_text_sha": None})

    page_latest = find_latest_pdf_url_from_page()
    if not page_latest:
        print("Could not find latest PDF on page.")
        return

    base_url = page_latest
    base_dt = parse_filename_dt(page_latest)
    if pdf_state.get("last_pdf_url"):
        last_dt = parse_filename_dt(pdf_state["last_pdf_url"])
        if last_dt and base_dt and last_dt > base_dt:
            base_url = pdf_state["last_pdf_url"]

    target_url = next_expected_url_from_base(base_url)
    if not target_url:
        print("Could not build next URL.")
        return

    r = http_try_get(target_url)
    if r is None:
        print("Next report not live yet:", target_url)
        return

    # If it is live, run full window logic (so it sends notifications correctly)
    run_window()


if __name__ == "__main__":
    if os.environ.get("RUN_ONCE") == "1":
        run_once_try()
    else:
        run_window()
