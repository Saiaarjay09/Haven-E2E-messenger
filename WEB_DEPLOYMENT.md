# Deploying Haven on the web

This covers getting the hosted web app (`webapp/`) live so a friend can
open a URL, sign up, and start texting you — no install needed on their
end. Read `webapp/README.md` first if you haven't: the web app is a
genuinely different trust model from the desktop app (a browser trusts
whatever code the server sends it, fresh, on every page load), and
that's worth understanding before you rely on it for anything sensitive.

There are three separate processes to run:

1. **Accounts service** (`webapp/accounts_server.py`) — signup/login/
   password recovery. Needs Python + `webapp/requirements.txt`.
2. **Relay server** (`haven/relay_server.py`) — routes encrypted messages
   between clients. Needs Python + `requirements.txt`. Run it with
   `--ws-port` so browsers (which can't open raw TCP) can connect.
3. **Static file server** — just serves the HTML/JS in `webapp/static/`.
   Any web server works; you don't need Python for this one specifically.

None of the three ever see a password, a private key, or message
plaintext — see `webapp/README.md` for exactly why that's true.

## Option A: quick start, no domain, no TLS (good for testing today)

Use this to get your friend texting you *today*. Upgrade to Option B
before relying on this for anything you actually care about keeping
private — plain HTTP means a network attacker between your friend and
your server could tamper with the JavaScript your server sends them,
which is the same "browser trusts server code" risk from
`webapp/README.md`, made worse by having no transport encryption at all.

**On a machine with a public IP** (a cheap VPS is easiest — DigitalOcean,
Linode, Oracle Cloud's free tier, AWS Lightsail; a home computer works
too with router port-forwarding, see the "Reaching friends in other
countries" section of `README.md` for that tradeoff):

```bash
git clone https://github.com/Saiaarjay09/Haven-E2E-messenger.git
cd Haven-E2E-messenger
pip3 install -r requirements.txt -r webapp/requirements.txt

# Terminal/service 1 — accounts service, reachable from anywhere:
uvicorn webapp.accounts_server:app --host 0.0.0.0 --port 8000

# Terminal/service 2 — relay, TCP for desktop clients + WebSocket for browsers:
python3 -m haven.relay_server --port 8443 --ws-port 8444

# Terminal/service 3 — the web client itself, just static files:
python3 -m http.server 8899 --directory webapp/static
```

Open your firewall/security group for ports **8000, 8444, and 8899**
(8443 only if you also want desktop clients on this same relay).

**Tell your friend to:**
1. Open `http://YOUR_SERVER_IP:8899` in their browser.
2. Click **Create account**, pick a username and password.
3. In the two URL fields, enter:
   - Accounts server URL: `http://YOUR_SERVER_IP:8000`
   - Relay WebSocket URL: `ws://YOUR_SERVER_IP:8444`
   (only needed if they don't match the page's own address automatically)
4. **Write down the 12-word recovery phrase shown once at signup** —
   it's the only way back into the account if the password is forgotten.
5. Click **My contact card**, copy it, and send it to you (over anything
   — text, email, in person).
6. You do the same on your end and send them your card.
7. Each of you clicks **Add contact…** and pastes the other's card in.
8. Open the chat, and **read the safety number to each other over a call
   or in person** before trusting it — this is what actually proves
   nobody tampered with the exchange, the same way it works on the
   desktop app.

That's it — messages from here are genuinely end-to-end encrypted; the
accounts service and relay both see ciphertext they cannot read.

## Option B: recommended — a domain + automatic HTTPS

Same three processes, but fronted by a reverse proxy that gets you free,
auto-renewing TLS and lets everything live under one domain. This
example uses [Caddy](https://caddyserver.com) because its config is
short and it handles certificates automatically; nginx + certbot works
too if you already know that stack.

1. Point a domain (or subdomain, e.g. `haven.yourdomain.com`) at your
   server's IP address.
2. Run the three processes as **systemd services** so they survive
   reboots and restart on crash — `deploy/haven-accounts.service` and
   `deploy/haven-relay.service` are ready to use (edit the paths inside
   for where you cloned the repo). Install Caddy, then use a Caddyfile
   like this:

   ```
   haven.yourdomain.com {
       handle /api/* {
           reverse_proxy 127.0.0.1:8000
       }
       handle /relay {
           reverse_proxy 127.0.0.1:8444
       }
       handle {
           root * /opt/haven/webapp/static
           file_server
       }
   }
   ```

3. Copy the service files into place and enable them:
   ```bash
   sudo cp deploy/haven-accounts.service deploy/haven-relay.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now haven-accounts haven-relay
   ```
4. Your friend now just visits `https://haven.yourdomain.com` — no ports,
   no IP address to remember. In the login screen's URL fields they'd
   enter `https://haven.yourdomain.com/api` and
   `wss://haven.yourdomain.com/relay` (matching the Caddy paths above).

## Option C: no domain, always-on on your own Mac (launchd)

Options A and B assume a server. If you'd rather run everything on your own
Mac and just need it to survive reboots and crashes without you manually
restarting three terminal windows every time, use `launchd` (macOS's
service manager) to keep the three Haven processes running, plus one of
the two tunnel approaches below to actually expose them to the internet.

### C1 (recommended): Tailscale Funnel — free, and the URL never changes

[Tailscale](https://tailscale.com) is free for personal use and its
Funnel feature gives your Mac a permanent public hostname tied to your
device's name — `https://<device>.<your-tailnet>.ts.net` — instead of a
randomly-generated one that changes every time a tunnel process restarts.
No domain purchase, no NS record changes, nothing to renew.

1. Install Tailscale (the [standalone macOS package](https://pkgs.tailscale.com/stable/#macos)
   doesn't require an Apple ID) and sign in with any free SSO provider
   (Google/GitHub/Microsoft) — this part needs a human in a browser, it
   can't be scripted.
2. Optionally rename the device to something nicer than your Mac's
   default name — this becomes part of the permanent URL:
   ```bash
   tailscale set --hostname=haven
   ```
3. The first time you expose anything, Tailscale will print a one-time
   approval link (`https://login.tailscale.com/f/funnel?node=...`) —
   visit it and approve Funnel for your account.
4. Expose each of Haven's three services on one of Funnel's three
   allowed ports (443, 8443, 10000 — this restriction is on Tailscale's
   side, not Haven's):
   ```bash
   tailscale funnel --bg --https=443   8899  # static files
   tailscale funnel --bg --https=8443  8000  # accounts API
   tailscale funnel --bg --https=10000 8444  # relay (WebSocket)
   ```
5. Your permanent links (see `tailscale funnel status` any time to
   re-check them):
   - Web app: `https://<device>.<tailnet>.ts.net`
   - Accounts server URL: `https://<device>.<tailnet>.ts.net:8443`
   - Relay WebSocket URL: `wss://<device>.<tailnet>.ts.net:10000`

   These only change if you rename the device or its tailnet — routine
   restarts, reboots, and crashes don't affect them. If you do rename it,
   re-run `tailscale funnel reset` then step 4 again under the new name.
6. Keep the three Haven processes themselves running via the
   `com.haven.accounts.plist` / `com.haven.relay.plist` /
   `com.haven.static.plist` templates in `deploy/`, same as below.

### C2 (alternative): Cloudflare quick tunnels — free, but the URL rotates

No account needed at all, but Cloudflare's free "quick tunnels" aren't
meant for continuous uptime: they can be evicted server-side with no
warning (observed anywhere from under a day to a couple of days), and
when that happens the URL changes. Use this only if you'd rather not
create a Tailscale account.

1. Download `cloudflared` somewhere permanent — **not** `/tmp`, which
   doesn't survive a reboot:
   ```bash
   mkdir -p ~/Developer/haven/bin
   curl -fL -o ~/Developer/haven/bin/cloudflared.tgz \
     https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz
   # use cloudflared-darwin-amd64.tgz instead if you're on an Intel Mac
   tar -xzf ~/Developer/haven/bin/cloudflared.tgz -C ~/Developer/haven/bin
   rm ~/Developer/haven/bin/cloudflared.tgz
   chmod +x ~/Developer/haven/bin/cloudflared
   ```
2. Copy the six templates from `deploy/` into `~/Library/LaunchAgents/`,
   filling in your username and paths: `com.haven.accounts.plist`,
   `com.haven.relay.plist`, `com.haven.static.plist`, and three copies of
   `com.haven.tunnel-template.plist` (one per port — see the comments
   inside it).
3. Load them all:
   ```bash
   for f in ~/Library/LaunchAgents/com.haven.*.plist; do
     launchctl bootstrap gui/$(id -u) "$f"
   done
   ```
4. Check status and get the current public URLs any time:
   ```bash
   deploy/check-tunnels.sh
   ```
5. To stop everything: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.haven.<name>.plist`
   for each job, or just delete the plist files and reboot.
6. Set up the auto-recovery watchdog: copy `com.haven.tunnel-watchdog.plist`
   into `~/Library/LaunchAgents/` too (fill in your username/paths), then
   `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.haven.tunnel-watchdog.plist`.
   It runs `deploy/watch-tunnels.sh` every 2 minutes, which checks whether
   each tunnel's current URL actually responds and force-restarts any that
   don't — see that script's own comments for exactly why this is needed.
   Check `~/Library/Logs/Haven/tunnel-watchdog.log` to see when it's fired.
7. Set up automatic link publishing, so you're not re-sending a fresh
   URL to everyone by hand every time a tunnel restarts under a new one:
   copy `com.haven.publish-urls.plist` into `~/Library/LaunchAgents/`
   (fill in your username/paths — needs this Mac to already have git
   push access to the repo) and bootstrap it the same way. Every 2
   minutes, `deploy/publish-urls.sh` checks the current URLs and, only
   when one has actually changed, commits and pushes an update to
   [CURRENT_LINKS.md](CURRENT_LINKS.md) — so that one file's GitHub page
   is always the current, correct link to send anyone.

Because the accounts database now lives outside the repo (so `git pull`
never touches it), point `HAVEN_ACCOUNTS_DB` in the accounts plist at
somewhere like `~/Library/Application Support/Haven/haven_accounts.db`,
and give the relay's `--db` flag a similar persistent path.

### Optional: live call translation

If you want the live-call-translation feature (captions when someone
speaks a non-English language), set `HAVEN_OPENAI_API_KEY` in the
accounts plist's `EnvironmentVariables` to an API key from
[platform.openai.com](https://platform.openai.com/api-keys). Leave it
out entirely to skip the feature — `webapp/static/js/translation.js`
just gets an HTTP 503 from `/api/translate` and calls otherwise work
fine with no captions.

This key is billing-linked, unlike the Giphy key elsewhere in this repo,
so it must **only** ever live in this environment variable on your own
machine/server — never in any file under `webapp/static/`, never
committed to git. `accounts_server.py`'s `/api/translate` endpoint reads
it from the environment and proxies the request; the browser never sees
it. After editing the plist, reload the service:
```bash
launchctl kickstart -k gui/$(id -u)/com.haven.accounts
```

## Keeping it running

- Both `.service` files auto-restart on crash and start on boot.
- Back up `haven_accounts.db` (the accounts service's SQLite file) if you
  want signups to survive a server rebuild — it's ciphertext + hashes,
  not sensitive in the way a plaintext password database would be, but
  losing it means everyone who signed up there loses their account
  (their recovery phrase only helps if the account record still exists
  to recover *into*).
- The relay's queue database can safely be deleted any time everyone's
  online and caught up — it only holds temporarily-undelivered messages.

## What your friend does NOT need to do

No install, no Python, no git clone — Option A/B both mean they only
ever open a URL in their own browser. The clone/install steps above are
for *you*, the person hosting it.
