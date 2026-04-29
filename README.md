# vulncrier

A Python script that aggregates security intelligence from multiple sources and delivers a daily digest to a Cisco Webex room. It pulls from CISA's Known Exploited Vulnerabilities catalog, BleepingComputer's RSS feed, GitHub Security Advisories, VulnCheck's KEV dataset, and a broad search of the YCombinator news feed, then formats everything into a single Markdown-formatted Webex message.

---

## Features

- **CISA KEV** — New Known Exploited Vulnerabilities added in the last 24 hours
- **BleepingComputer** — Top security headlines from the last 24 hours
- **GitHub Security Advisories** — New advisories filtered by severity (configurable, default: critical), including affected package and ecosystem
- **VulnCheck KEV** — New entries from VulnCheck's expanded KEV dataset
- **Catch-all** — Security-relevant posts filtered by keyword

---

## Requirements

- Python 3.9 or higher
- A Cisco Webex bot token and room ID
- A VulnCheck API token

### Python Dependencies

```bash
pip install python-dotenv defusedxml
```

`requests` is **not** required — all HTTP calls use the Python standard library (`urllib`).

---

## Configuration

The script reads credentials from environment variables so they are never hardcoded in source. Three variables are required:

| Variable | Description |
|---|---|
| `WEBEX_BOT_TOKEN` | Your Webex bot Bearer token |
| `WEBEX_ROOM_ID` | The ID of the Webex room to post into |
| `VULNCHECK_API_TOKEN` | Your VulnCheck API token |

The script will exit immediately with a clear error message if any of these are missing.

Two constants at the top of the script control filtering behaviour:

| Constant | Default | Description |
|---|---|---|
| `GITHUB_MIN_SEVERITY` | `"critical"` | Minimum severity for GitHub advisories. Options: `"low"`, `"medium"`, `"high"`, `"critical"` |
| `NEWS_KEYWORDS` | *(list)* | Keywords used to filter cybersecurity-related posts. Add or remove terms to tune signal-to-noise ratio. |

---

## Setting Environment Variables

### Using a .env File (Recommended for All Platforms)

Create a `.env` file in the same directory as the script:

```
WEBEX_BOT_TOKEN=your_token_here
WEBEX_ROOM_ID=your_room_id_here
VULNCHECK_API_TOKEN=your_token_here
```

The script loads this file automatically via `python-dotenv`.

> **Important:** Never commit your `.env` file to version control. Add it to `.gitignore`:
> ```
> .env
> ```

---

### Windows

**Option A — Current session only (Command Prompt):**
```cmd
set WEBEX_BOT_TOKEN=your_token_here
set WEBEX_ROOM_ID=your_room_id_here
set VULNCHECK_API_TOKEN=your_token_here
```

**Option B — Persistent (PowerShell, survives reboots):**
```powershell
[System.Environment]::SetEnvironmentVariable("WEBEX_BOT_TOKEN", "your_token_here", "User")
[System.Environment]::SetEnvironmentVariable("WEBEX_ROOM_ID", "your_room_id_here", "User")
[System.Environment]::SetEnvironmentVariable("VULNCHECK_API_TOKEN", "your_token_here", "User")
```

**Option C — Via the GUI:**
1. Open the Start menu and search for **Edit the system environment variables**
2. Click **Environment Variables...**
3. Under **User variables**, click **New** and add each variable
4. Restart any open terminals for the changes to take effect

---

### macOS

**Option A — Current session only:**
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
export VULNCHECK_API_TOKEN="your_token_here"
```

**Option B — Persistent (add to shell profile):**

For Zsh (default on macOS Catalina and later), add to `~/.zshrc`:
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
export VULNCHECK_API_TOKEN="your_token_here"
```

Then reload: `source ~/.zshrc`

---

### Linux

**Option A — Current session only:**
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
export VULNCHECK_API_TOKEN="your_token_here"
```

**Option B — Persistent (add to `~/.bashrc` or `~/.zshrc`):**
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
export VULNCHECK_API_TOKEN="your_token_here"
```

Then reload: `source ~/.bashrc`

**Option C — For cron jobs:**

Shell profile variables are not available to cron by default. Set them directly in your crontab or use a `.env` file (recommended).

---

## Running the Script

```bash
python vulncrier.py
```

---

## Scheduling

### Windows — Task Scheduler

1. Open **Task Scheduler** and click **Create Basic Task**
2. Set the trigger to **Daily** at your preferred time
3. Set the action to **Start a Program**
4. Set the program to your Python executable (e.g. `C:\Python311\python.exe`) and the argument to the full path of `vulncrier.py`
5. Ensure credentials are set as persistent **User** or **System** environment variables, or use a `.env` file

### macOS / Linux — cron

Run daily at 8:00 AM:
```bash
crontab -e
```
```
0 8 * * * /usr/bin/python3 /path/to/vulncrier.py >> /var/log/vulncrier.log 2>&1
```

If credentials are not available system-wide, set them at the top of the crontab file or use a `.env` file in the script directory.

---

## Project Structure

```
.
├── vulncrier.py    # Main script
├── .env            # Local credentials (never commit this)
├── .gitignore      # Should include .env
└── README.md       # This file
```

---

## Security Notes

- Credentials are loaded from environment variables or a `.env` file and are never hardcoded in source
- All HTTP requests enforce a 15-second timeout to prevent the script from hanging on slow or unresponsive feeds
- XML feeds are parsed with [`defusedxml`](https://pypi.org/project/defusedxml/) to guard against XML bomb payloads
- All text and URLs from external feeds are sanitized before being embedded in the Webex message to prevent Markdown injection; only `https://` URLs are rendered as links
- The GitHub Advisory and CISA KEV APIs are public endpoints; VulnCheck requires a Bearer token passed via the `Authorization` header

---

## License

MIT
