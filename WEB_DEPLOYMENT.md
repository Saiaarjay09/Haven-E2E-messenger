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
service manager) plus Cloudflare quick tunnels. The tradeoff versus a real
server: it's genuinely "set and forget" for crashes and reboots, but it's
still only reachable while your Mac is on, and each tunnel's URL will
change if that tunnel process itself ever restarts (crash or reboot) —
run `deploy/check-tunnels.sh` any time to read the current URLs back out.

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

Because the accounts database now lives outside the repo (so `git pull`
never touches it), point `HAVEN_ACCOUNTS_DB` in the accounts plist at
somewhere like `~/Library/Application Support/Haven/haven_accounts.db`,
and give the relay's `--db` flag a similar persistent path.

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
