# Daily Security Digest Bot

A Python script that aggregates security intelligence from multiple sources and delivers a daily digest to a Webex room. It pulls from CISA's Known Exploited Vulnerabilities (KEV) catalog, BleepingComputer's RSS feed, and the GitHub Security Advisory Database, then formats everything into a single Markdown-formatted Webex message.

---

## Features

- **CISA KEV** — Alerts on newly added Known Exploited Vulnerabilities from the last 24 hours
- **BleepingComputer** — Top security headlines from the last 24 hours
- **GitHub Security Advisories** — New advisories filtered by severity (default: High and above), including affected package and ecosystem

---

## 🛠️ Requirements

- Python 3.8 or higher
- A Webex Bot token and Room ID

### Python Dependencies

Install required packages with:

```bash
pip install requests python-dotenv
```

All other dependencies (`json`, `datetime`, `urllib`, `xml.etree.ElementTree`, `os`) are part of the Python standard library.

---

## Configuration

The script reads sensitive credentials from environment variables so they are never hardcoded in source. You will need to set two variables before running:

| Variable | Description |
|---|---|
| `WEBEX_BOT_TOKEN` | Your Webex Bot Bearer token |
| `WEBEX_ROOM_ID` | The ID of the Webex room to post into |

You can also optionally adjust the `GITHUB_MIN_SEVERITY` constant inside the script to control the minimum advisory severity that gets reported. Accepted values are `low`, `medium`, `high`, and `critical`. The default is `high`.

---

## Setting Environment Variables

### Windows

**Option A — Current session only (Command Prompt):**
```cmd
set WEBEX_BOT_TOKEN=your_token_here
set WEBEX_ROOM_ID=your_room_id_here
```

**Option B — Persistent (PowerShell, survives reboots):**
```powershell
[System.Environment]::SetEnvironmentVariable("WEBEX_BOT_TOKEN", "your_token_here", "User")
[System.Environment]::SetEnvironmentVariable("WEBEX_ROOM_ID", "your_room_id_here", "User")
```

**Option C — Via the GUI:**
1. Open the Start menu and search for **Edit the system environment variables**
2. Click **Environment Variables...**
3. Under **User variables**, click **New**
4. Enter the variable name and value, then click **OK**
5. Repeat for the second variable
6. Restart any open terminals for the changes to take effect

---

### macOS

**Option A — Current session only:**
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
```

**Option B — Persistent (add to your shell profile):**

For Zsh (default on macOS Catalina and later), add to `~/.zshrc`:
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
```

For Bash, add to `~/.bash_profile` or `~/.bashrc` instead. Then reload the file:
```bash
source ~/.zshrc   # or source ~/.bash_profile
```

---

### Linux

**Option A — Current session only:**
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
```

**Option B — Persistent (add to your shell profile):**

Add to `~/.bashrc` (or `~/.zshrc` if using Zsh):
```bash
export WEBEX_BOT_TOKEN="your_token_here"
export WEBEX_ROOM_ID="your_room_id_here"
```

Then reload:
```bash
source ~/.bashrc
```

**Option C — For cron jobs:**

Shell profile variables are not available to cron by default. Set them directly in your crontab:
```bash
crontab -e
```
Add at the top of the file:
```
WEBEX_BOT_TOKEN=your_token_here
WEBEX_ROOM_ID=your_room_id_here
```

---

### Using a .env File (All Platforms)

If you prefer to manage credentials in a file (recommended for scheduled tasks on any OS), create a `.env` file in the same directory as the script:

```
WEBEX_BOT_TOKEN=your_token_here
WEBEX_ROOM_ID=your_room_id_here
```

The script will automatically load this file via `python-dotenv`.

> ⚠️ **Important:** Never commit your `.env` file to version control. Add it to `.gitignore`:
> ```
> .env
> ```

---

## Running the Script

```bash
python security_digest.py
```

If required environment variables are missing, the script will exit immediately with a clear error message rather than failing silently.

---

## Scheduling

### Windows — Task Scheduler

1. Open **Task Scheduler** and click **Create Basic Task**
2. Set the trigger to **Daily** at your preferred time
3. Set the action to **Start a Program**
4. Set the program to your Python executable (e.g. `C:\Python311\python.exe`) and the argument to the full path of `security_digest.py`
5. Ensure your environment variables are set as persistent **User** or **System** variables (see above)

### macOS / Linux — cron

Run daily at 8:00 AM:
```bash
crontab -e
```
```
0 8 * * * /usr/bin/python3 /path/to/security_digest.py
```

Remember to set variables in the crontab itself if they are not available system-wide (see Linux Option C above).

---

## Project Structure

```
.
├── security_digest.py   # Main script
├── .env                 # Local credentials (never commit this)
├── .gitignore           # Should include .env
└── README.md            # This file
```

---

## Security Notes

- Credentials are loaded from environment variables or a `.env` file and are never hardcoded in source
- The GitHub Advisory API is accessed without authentication, as only public data is consumed
- The CISA KEV and BleepingComputer feeds are public endpoints requiring no credentials

---

## License

MIT
