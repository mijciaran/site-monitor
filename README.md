# Site integrity monitor

This repository checks www.myirishjeweler.com every 5 minutes from GitHub's servers, not from your web server. It opens a GitHub issue, which sends you an email and a phone notification, when:

- any of the site's JavaScript files changes (compared by SHA-256 hash)
- a monitored page loads a script from a domain that isn't on the allowed list, or from an unknown local path
- a page contains the skimmer indicators (`balkhub`, `wss://`, or inline `WebSocket` / `new Function`)
- the webshell paths (`/order-export.php` and others) stop returning 404
- optionally, the Content-Security-Policy header goes missing

You get one alert per incident. It won't email you every 5 minutes. When the checks pass again, the issue closes itself with a comment.

## Setup (about 10 minutes)

1. Sign in to GitHub and create a new **public** repository, for example `site-monitor`. Public repositories get unlimited free Actions minutes. A private repository would use up the free monthly minutes at this frequency. Nothing in these files is secret.
2. Upload the files, keeping the folder structure exactly:
   - `.github/workflows/site-monitor.yml`
   - `monitor/check_site.py`
   - `monitor/config.json`
   - `README.md`

   In the web interface, use **Add file → Create new file** and type the full path (e.g. `.github/workflows/site-monitor.yml`) as the name, then paste the contents.
3. Go to the **Actions** tab. If asked, enable workflows. Open **Site integrity monitor** and click **Run workflow** to test it once. It should finish green.
4. Make sure you'll be notified:
   - On the repository page, click **Watch → All Activity**.
   - In GitHub **Settings → Notifications**, make sure email (and/or GitHub Mobile push) is on for "Watching" and for "Actions".
   - Install the **GitHub Mobile** app if you want phone push alerts.
5. Test the alert: in `monitor/config.json`, change one character of the `main.js` hash and commit. Run the workflow by hand. An issue should open and you should get an email. Change the hash back and the issue will close on the next run.

## When your developer changes a file on purpose

The monitor will raise an alert, because it can't tell your developer's edit from the attacker's. Read the issue: it shows the new size and hash. Confirm the change was yours, paste the new hash into `monitor/config.json`, and close the issue.

If the site starts loading a new third-party script (a new chat widget, say), add its domain to `allowed_script_hosts`.

## After the CSP header is live

Set `"require_csp": true` in `monitor/config.json` so you're alerted if the header disappears. Someone with server access can remove it by editing `.htaccess`.

## Limits

- GitHub sometimes runs scheduled jobs several minutes late during busy periods.
- GitHub disables scheduled workflows in public repositories after 60 days without repository activity. Make a small commit now and then, or re-enable the workflow from the Actions tab if it stops.
- The monitor sees what an anonymous visitor sees. It doesn't check the checkout payment step, which needs a cart and an address, so a skimmer injected only there would be missed unless it's in one of the JavaScript files the monitor already checks.
- If the site rate-limits or blocks GitHub's IP addresses, you'll get "HTTP 429/403" alerts. If that happens, ask Liquid Web to allow the requests (they use a normal Chrome user agent).
