<h1>Steam Account Checker • Yashvir Gaming</h1>
<p>A fast, multi-threaded Steam account checker (CLI) that fetches profile data, wallet balance, Steam Guard and Family View status, VAC/Game bans, and games list — saved as single-line captures for easy parsing.</p>

<h2>Features</h2>
<ul>
  <li>(CLI Version). Console visible with banner and live CPM.</li>
  <li>Hardcoded file inputs: <code>combos.txt</code> and <code>proxies.txt</code>.</li>
  <li>Auto-converts <code>email:password</code> → <code>username:password</code> (username is part before <code>@</code>).</li>
  <li>Deduplicates combos automatically.</li>
  <li>Parses Wallet Balance, Steam Guard, Family View, VAC bans, Game bans, games list and last online.</li>
  <li>Single-line capture output format (OpenBullet-style) saved to <code>Success.txt</code>.</li>
</ul>

<h2>Quickstart</h2>
<pre><code>git clone YOUR_REPO
cd repo
python -m pip install -r requirements.txt
# create combos.txt and proxies.txt in same folder
# run
python steam_checker.py
# or build with Nuitka
Builder.bat
</code></pre>

<h2>Files</h2>
<ul>
  <li><strong>steam_checker.py</strong> – main checker</li>
  <li><strong>requirements.txt</strong> – pinned dependencies</li>
  <li><strong>Builder.bat</strong> – builds a single EXE using Nuitka</li>
  <li><strong>Launcher.bat</strong> – runs the EXE or falls back to Python script</li>
  <li><strong>combos.txt</strong> – one combo per line (username:password or email:password)</li>
  <li><strong>proxies.txt</strong> – one proxy per line (ip:port, ip:port:user:pass, user:pass@host:port, or with scheme)</li>
</ul>

<h2>Capture format (saved to <code>Success.txt</code>)</h2>
<pre><code>username:password | Status = Verified | Balance = S$1.08 | Country = Singapore | Online = 1193 days ago | limited = false | TotalGames = 27 | Games = [Terraria | CS2 | Bloons TD 6] | VAC = None | GameBan = None | CommunityBan = None | SteamGuard = Enabled | FamilyView = Disabled | 💪 AUTHOR Telegram: 🔥 @therealyashvirgaming 🔥 |</code></pre>

<h2>Proxy formats supported</h2>
<ul>
  <li><code>ip:port</code> → converted to <code>http://ip:port</code></li>
  <li><code>ip:port:user:pass</code> → converted to <code>http://user:pass@ip:port</code></li>
  <li><code>user:pass@host:port</code> → converted to <code>http://user:pass@host:port</code></li>
  <li>Schemes allowed: <code>http://</code>, <code>https://</code>, <code>socks4://</code>, <code>socks5://</code></li>
</ul>
