import json
import datetime
import urllib.request
import urllib.error
import urllib.parse
from xml.etree import ElementTree
import requests # type: ignore
import os

KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BLEEPING_RSS = "https://www.bleepingcomputer.com/feed/"
GITHUB_ADVISORY_API = "https://api.github.com/advisories"
VULNCHECK_KEV_API = "https://api.vulncheck.com/v3/index/vulncheck-kev"
WEBEX_BOT_TOKEN = os.environ.get("WEBEX_BOT_TOKEN")
WEBEX_ROOM_ID = os.environ.get("WEBEX_ROOM_ID")
WEBEX_API = "https://webexapis.com/v1/messages"
VULNCHECK_API_TOKEN = os.environ.get("VULNCHECK_API_TOKEN")

if not WEBEX_BOT_TOKEN or not WEBEX_ROOM_ID:
    raise EnvironmentError(
        "Missing required environment variables WEBEX_BOT_TOKEN and/or WEBEX_ROOM_ID. Please set them before running the script."
    )

# Only report GitHub advisories at or above this severity.
# Options: "low", "medium", "high", "critical"
GITHUB_MIN_SEVERITY = "critical"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def fetch_cisa_kev():
    """Fetch CISA KEV data using urllib."""
    try:
        req = urllib.request.Request(
            KEV_API,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data["vulnerabilities"]
    except urllib.error.URLError as e:
        print(f"Error fetching KEV data: {e}")
        return []


def fetch_bleeping_rss():
    """Parse BleepingComputer RSS feed using built-in XML parser."""
    try:
        req = urllib.request.Request(
            BLEEPING_RSS,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                )
            },
        )
        with urllib.request.urlopen(req) as response:
            xml_data = response.read().decode("utf-8")

        root = ElementTree.fromstring(xml_data)
        entries = []

        for item in root.findall(".//item"):
            title_elem = item.find("title")
            link_elem = item.find("link")
            pubdate_elem = item.find("pubDate")
            description_elem = item.find("description")

            entry = {
                "title": title_elem.text if title_elem is not None else "No title",
                "link": link_elem.text if link_elem is not None else "",
                "published": pubdate_elem.text if pubdate_elem is not None else "",
                "description": description_elem.text if description_elem is not None else "",
            }
            entries.append(entry)

        return entries
    except urllib.error.URLError as e:
        print(f"Error fetching RSS feed: {e}")
        return []
    except ElementTree.ParseError as e:
        print(f"Error parsing RSS feed: {e}")
        return []


def fetch_github_advisories(cutoff: datetime.datetime):
    """
    Fetch GitHub Security Advisories published within the last 24 hours.

    Uses the `published` query parameter to ask the API to filter server-side,
    then applies a local severity filter to reduce noise.

    Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
    """
    # Format cutoff as ISO 8601 for the API's `published` range parameter.
    # The API accepts "YYYY-MM-DDTHH:MM:SSZ..YYYY-MM-DDTHH:MM:SSZ" range syntax.
    now = datetime.datetime.now(datetime.timezone.utc)
    published_range = f"{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}..{now.strftime('%Y-%m-%dT%H:%M:%SZ')}"

    params = f"?published={urllib.parse.quote(published_range)}&per_page=100"
    url = GITHUB_ADVISORY_API + params

    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "security-digest-bot/1.0",
            },
        )
        with urllib.request.urlopen(req) as response:
            advisories = json.loads(response.read().decode("utf-8"))

        # Filter locally by minimum severity threshold.
        min_rank = SEVERITY_RANK.get(GITHUB_MIN_SEVERITY, 4)
        filtered = [
            a for a in advisories
            if SEVERITY_RANK.get((a.get("severity") or "").lower(), 0) >= min_rank
        ]

        return filtered

    except urllib.error.URLError as e:
        print(f"Error fetching GitHub advisories: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing GitHub advisory response: {e}")
        return []


def fetch_vulncheck_kev(cutoff: datetime.datetime):
    """Fetch VulnCheck KEV entries added since cutoff. Requires VULNCHECK_API_TOKEN."""
    if not VULNCHECK_API_TOKEN:
        print("VULNCHECK_API_TOKEN not set, skipping VulnCheck KEV.")
        return []

    results = []
    cursor = None

    while True:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        url = VULNCHECK_KEV_API + "?" + urllib.parse.urlencode(params)

        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {VULNCHECK_API_TOKEN}",
                    "Accept": "application/json",
                    "User-Agent": "security-digest-bot/1.0",
                },
            )
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            print(f"Error fetching VulnCheck KEV: {e}")
            break
        except json.JSONDecodeError as e:
            print(f"Error parsing VulnCheck KEV response: {e}")
            break

        entries = data.get("data", [])
        if not entries:
            break

        page_has_recent = False
        for entry in entries:
            date_str = entry.get("date_added", "")
            try:
                added = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                    tzinfo=datetime.timezone.utc
                )
            except ValueError:
                try:
                    added = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc
                    )
                except ValueError:
                    continue

            if added >= cutoff:
                results.append(entry)
                page_has_recent = True

        # VulnCheck returns newest-first; stop paginating once entries are older than cutoff.
        if not page_has_recent:
            break

        cursor = data.get("_next")
        if not cursor:
            break

    return results


def send_to_webex(markdown_message):
    """Send a Markdown-formatted message to a Webex room."""
    headers = {
        "Authorization": f"Bearer {WEBEX_BOT_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "roomId": WEBEX_ROOM_ID,
        "markdown": markdown_message,
    }
    response = requests.post(WEBEX_API, headers=headers, json=payload)
    if response.status_code != 200:
        print("Error sending to WebEx:", response.text)


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.isoformat()
    cutoff = now - datetime.timedelta(hours=24)

    print("Fetching CISA KEV data...")
    kev_data = fetch_cisa_kev()

    print("Fetching BleepingComputer RSS...")
    bleep_data = fetch_bleeping_rss()

    print("Fetching GitHub Security Advisories...")
    github_advisories = fetch_github_advisories(cutoff)

    print("Fetching VulnCheck KEV data...")
    vulncheck_kev = fetch_vulncheck_kev(cutoff)

    # --- CISA KEV: compare dates only to avoid timezone/time-of-day false negatives ---
    cutoff_date = cutoff.date()
    recent_kev = [
        entry for entry in kev_data
        if datetime.datetime.strptime(entry["dateAdded"], "%Y-%m-%d").date() >= cutoff_date
    ]

    # --- BleepingComputer: full datetime comparison ---
    recent_bleep = []
    for entry in bleep_data:
        try:
            pub_date = datetime.datetime.strptime(entry["published"], "%a, %d %b %Y %H:%M:%S %z")
            if pub_date >= cutoff:
                recent_bleep.append(entry)
        except ValueError:
            pass

    # GitHub advisories are already filtered by the API + local severity check.
    recent_github = github_advisories

    if not recent_kev and not recent_bleep and not recent_github and not vulncheck_kev:
        print("No new updates in the last 24 hours, skipping Webex message.")
        return

    # --- Build Markdown digest ---
    markdown = f"""## 🔔 Daily Vulnerability Digest

**Timestamp (UTC):** {timestamp}

---

### 🚨 CISA KEV
New entries in last 24 hours: **{len(recent_kev)}**

#### Recent KEV Entries:
"""
    if recent_kev:
        for entry in recent_kev:
            markdown += (
                f"- **{entry['cveID']}** — {entry['vulnerabilityName']} "
                f"({entry['vendorProject']}) — Added: {entry['dateAdded']}\n"
            )
    else:
        markdown += "- No new KEV entries in the last 24 hours\n"

    markdown += f"""
---

### 📰 BleepingComputer
New articles in last 24 hours: **{len(recent_bleep)}**

#### Top Headlines:
"""
    if recent_bleep:
        for entry in recent_bleep:
            markdown += f"- [{entry['title']}]({entry['link']})\n"
    else:
        markdown += "- No new articles in the last 24 hours\n"

    markdown += f"""
---

### 🛡️ GitHub Security Advisories
New advisories (severity ≥ {GITHUB_MIN_SEVERITY}) in last 24 hours: **{len(recent_github)}**

#### Recent Advisories:
"""
    if recent_github:
        for adv in recent_github:
            ghsa_id = adv.get("ghsa_id", "N/A")
            cve_id = adv.get("cve_id") or "No CVE"
            severity = (adv.get("severity") or "unknown").capitalize()
            summary = adv.get("summary", "No summary available")
            html_url = adv.get("html_url", "")

            # Extract affected packages for context
            vulns = adv.get("vulnerabilities", [])
            packages = ", ".join(
                f"{v['package']['name']} ({v['package']['ecosystem']})"
                for v in vulns
                if v.get("package")
            ) if vulns else "Unknown package"

            markdown += (
                f"- **{packages}** — [{ghsa_id}]({html_url}) ({cve_id}) — "
                f"**{severity}** — {summary}\n"
            )
    else:
        markdown += f"- No new advisories at or above **{GITHUB_MIN_SEVERITY}** severity in the last 24 hours\n"

    markdown += f"""
---

### 🔍 VulnCheck KEV
New entries in last 24 hours: **{len(vulncheck_kev)}**

#### Recent VulnCheck KEV Entries:
"""
    if vulncheck_kev:
        for entry in vulncheck_kev:
            cve_id = entry.get("cve", "N/A")
            name = entry.get("vulnerability_name") or entry.get("name", "Unknown")
            vendor = entry.get("vendor_project") or entry.get("vendor", "Unknown")
            added = entry.get("date_added", "")[:10]
            markdown += f"- **{cve_id}** — {name} ({vendor}) — Added: {added}\n"
    else:
        markdown += "- No new VulnCheck KEV entries in the last 24 hours\n"

    send_to_webex(markdown)
    print("Message sent to Webex successfully.")


if __name__ == "__main__":
    main()