from typing import List, Optional
import re
import socket
import time
import json
import os
import textwrap
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

# Próba importu bibliotek opcjonalnych
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

import requests

# PDF – reportlab
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.utils import ImageReader
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Selenium do screenshotów
try:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.common.by import By
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

APP_VERSION = "0.4.1"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".osint_domena_config.json")


# ---------- POMOCNICZE FUNKCJE ----------

def normalize_domain(domain: str) -> str:
    """
    Usuwa protokół, ścieżki, porty i parametry z podanego ciągu
    i zostawia samą domenę.
    """
    d = domain.strip().lower()

    # Usuń protokół
    d = re.sub(r'^https?://', '', d)

    # Usuń wszystko po pierwszym ukośniku
    if '/' in d:
        d = d.split('/', 1)[0]

    # Usuń port, jeśli jest (np. example.com:8080)
    if ':' in d:
        d = d.split(':', 1)[0]

    return d


def is_valid_domain(domain: str) -> bool:
    """Bardzo prosty walidator domeny (bez IDN)."""
    pattern = r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$"
    return re.match(pattern, domain) is not None


def infer_region_from_node(node_name: str) -> str:
    """
    Bardzo uproszczona heurystyka regionu na podstawie nazwy węzła
    z check-host. To tylko orientacyjne przypisanie.
    """
    n = node_name.lower()

    if "poland" in n or ".pl" in n or "-pl" in n or "warsaw" in n:
        return "Polska"
    if "ukraine" in n or ".ua" in n or "-ua" in n or "kyiv" in n or "kiev" in n:
        return "Ukraina"
    if "belarus" in n or ".by" in n or "-by" in n or "minsk" in n:
        return "Białoruś"
    if "russia" in n or ".ru" in n or "-ru" in n or "moscow" in n:
        return "Rosja"
    if "usa" in n or ".us" in n or "-us" in n or "new-york" in n or "los-angeles" in n:
        return "USA"
    if "europe" in n or ".eu" in n or "-eu" in n:
        return "Europa"
    return "Inny/nieznany"


# ---------- ZAPYTANIA SIECIOWE / OSINT ----------

def dns_lookup(domain: str) -> dict:
    """
    Próbuje pobrać podstawowe informacje DNS.
    Zwraca słownik z listami rekordów.
    """
    result = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "errors": []
    }

    # Jeśli brak dnspython, używamy tylko socket do A/AAAA
    if dns is None:
        try:
            info = socket.getaddrinfo(domain, None)
            for item in info:
                addr = item[4][0]
                if ":" in addr:
                    if addr not in result["AAAA"]:
                        result["AAAA"].append(addr)
                else:
                    if addr not in result["A"]:
                        result["A"].append(addr)
        except Exception as e:
            result["errors"].append(f"DNS/socket error: {e}")
        return result

    # Z dnspython – bardziej rozbudowane
    resolver = dns.resolver.Resolver()

    def _query(record_type: str):
        try:
            answers = resolver.resolve(domain, record_type)
            return [r.to_text() for r in answers]
        except Exception as e:
            result["errors"].append(f"{record_type} error: {e}")
            return []

    result["A"] = _query("A")
    result["AAAA"] = _query("AAAA")
    result["MX"] = _query("MX")
    result["NS"] = _query("NS")
    result["TXT"] = _query("TXT")

    return result


def whois_lookup(domain: str) -> dict:
    """Pobiera podstawowe dane WHOIS (jeśli dostępny moduł python-whois)."""
    if whois is None:
        return {"error": "Moduł 'python-whois' nie jest zainstalowany."}

    try:
        data = whois.whois(domain)
    except Exception as e:
        return {"error": f"WHOIS error: {e}"}

    result = {
        "domain_name": data.get("domain_name"),
        "registrar": data.get("registrar"),
        "creation_date": data.get("creation_date"),
        "expiration_date": data.get("expiration_date"),
        "name_servers": data.get("name_servers"),
        "emails": data.get("emails"),
        "raw": str(data)
    }

    return result


def http_check(domain: str) -> dict:
    """
    Sprawdza, czy strona odpowiada na HTTPS/HTTP,
    zwraca status i podstawowe nagłówki.
    """
    result = {
        "url_tried": [],
        "status": None,
        "final_url": None,
        "headers": {},
        "errors": []
    }

    for scheme in ("https://", "http://"):
        url = scheme + domain
        result["url_tried"].append(url)
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True)
            result["status"] = resp.status_code
            result["final_url"] = resp.url
            result["headers"] = dict(resp.headers)
            return result
        except Exception as e:
            result["errors"].append(f"{url}: {e}")

    return result


def check_wayback_archive(domain: str) -> dict:
    """
    Sprawdza, czy strona ma kopie w Internet Archive (Wayback Machine)
    za pomocą Availability API.
    """
    url = "https://archive.org/wayback/available"
    target = "http://" + domain
    try:
        resp = requests.get(url, params={"url": target}, timeout=10)
        data = resp.json()
        archived_snapshots = data.get("archived_snapshots", {})
        closest = archived_snapshots.get("closest")
        if closest:
            return {
                "available": True,
                "archive_url": closest.get("url"),
                "timestamp": closest.get("timestamp"),
                "status": closest.get("status")
            }
        return {"available": False}
    except Exception as e:
        return {"error": f"Wayback error: {e}"}


def check_google_cache(domain: str) -> dict:
    """
    Próbuje sprawdzić, czy istnieje kopia cache Google (webcache.googleusercontent.com).
    Uwaga: Google może ograniczać dostęp / blokować automatyczne zapytania.
    """
    cache_url = f"http://webcache.googleusercontent.com/search?q=cache:http://{domain}/"
    try:
        resp = requests.get(cache_url, timeout=10)
        if resp.status_code == 200:
            return {
                "cached": True,
                "status": resp.status_code,
                "cache_url": cache_url
            }
        elif resp.status_code in (404, 410):
            return {
                "cached": False,
                "status": resp.status_code,
                "cache_url": cache_url
            }
        else:
            return {
                "cached": None,
                "status": resp.status_code,
                "cache_url": cache_url
            }
    except Exception as e:
        return {"error": f"Google cache error: {e}", "cache_url": cache_url}


def shodan_lookup(ip: str, api_key: str) -> dict:
    """
    Pyta Shodan o informacje o IP (otwarte porty itd.).
    Wymaga ważnego klucza API Shodan.
    """
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 401:
            return {"error": "Błędny klucz API Shodan (401 Unauthorized)."}
        if resp.status_code == 402:
            return {"error": "Przekroczony limit/plan konta Shodan (402 Payment Required)."}
        if resp.status_code == 404:
            return {"info": "Adres IP nie występuje w bazie Shodan (404 Not Found)."}
        if resp.status_code != 200:
            return {"error": f"Błąd Shodan HTTP {resp.status_code}: {resp.text[:200]}"}

        data = resp.json()
        return {
            "ip_str": data.get("ip_str"),
            "ports": data.get("ports", []),
            "open_ports_count": len(data.get("ports", [])),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "os": data.get("os"),
        }
    except Exception as e:
        return {"error": f"Wyjątek przy zapytaniu do Shodan: {e}"}


def check_host_request(check_type: str, host: str, max_nodes: int = 5) -> dict:
    """
    Wykonuje zdalny test przez check-host.net (ping/http/tcp/dns/udp).
    Zwraca odpowiedź z tworzenia zadania i końcowe wyniki.
    """
    base_url = f"https://check-host.net/check-{check_type}"
    headers = {"Accept": "application/json"}
    try:
        start_resp = requests.get(
            base_url,
            params={"host": host, "max_nodes": max_nodes},
            headers=headers,
            timeout=15
        )
        data = start_resp.json()
        if not data.get("ok"):
            return {"error": f"check-host: odpowiedź ok={data.get('ok')}", "raw": data}

        request_id = data.get("request_id")
        if not request_id:
            return {"error": "check-host: brak request_id", "raw": data}

        # Polling wyników – kilka prób z opóźnieniem
        result_url = f"https://check-host.net/check-result/{request_id}"
        results = None
        for _ in range(8):
            time.sleep(1.0)
            r = requests.get(result_url, headers=headers, timeout=15)
            results = r.json()
            if isinstance(results, dict) and any(v is not None for v in results.values()):
                break

        return {
            "request": data,
            "results": results
        }
    except Exception as e:
        return {"error": f"check-host wyjątek: {e}"}


def try_accept_cookies(driver, max_attempts: int = 3) -> None:
    """
    Próbuje wykryć i kliknąć przyciski akceptacji cookies / zgód.
    Heurystyka – nie zadziała wszędzie, ale często usuwa overlay.
    """
    if not SELENIUM_AVAILABLE:
        return

    keywords = [
        "akceptuj", "akceptuję", "zgadzam się", "zaakceptuj",
        "accept", "i accept", "i agree", "agree", "accept all",
        "ok", "OK", "rozumiem"
    ]

    for _ in range(max_attempts):
        try:
            candidates = []
            candidates.extend(driver.find_elements(By.TAG_NAME, "button"))
            candidates.extend(
                driver.find_elements(By.XPATH, "//input[@type='button' or @type='submit']")
            )
        except Exception:
            candidates = []

        clicked = False
        for el in candidates:
            try:
                text = " ".join([
                    el.text or "",
                    el.get_attribute("value") or "",
                    el.get_attribute("innerText") or ""
                ])
                text_low = text.lower()
                if any(kw in text_low for kw in keywords):
                    el.click()
                    clicked = True
                    time.sleep(1.0)
                    break
            except Exception:
                continue

        if clicked:
            break


def capture_screenshot(url: str, output_path: str) -> bool:
    """
    Próbuje zrobić zrzut ekranu strony za pomocą Selenium + Firefox (headless).
    Wymaga zainstalowanego geckodriver i pakietu selenium.
    """
    if not SELENIUM_AVAILABLE:
        return False

    options = FirefoxOptions()
    options.add_argument("--headless")

    driver = None
    try:
        driver = webdriver.Firefox(options=options)
        driver.set_page_load_timeout(25)
        driver.set_window_size(1280, 720)
        driver.get(url)
        time.sleep(3)

        try_accept_cookies(driver)
        time.sleep(2)

        driver.save_screenshot(output_path)
        driver.quit()
        return True
    except WebDriverException as e:
        print("Screenshot WebDriver error:", e)
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return False
    except Exception as e:
        print("Screenshot error:", e)
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        return False


# ---------- SCORING RYZYKA ----------

def compute_risk(report: dict) -> dict:
    """
    Prosty wewnętrzny scoring ryzyka (0–100).
    """
    from datetime import datetime, date, timezone

    score = 50
    reasons: List[str] = []

    # Wiek domeny
    who = report.get("whois", {})
    creation = who.get("creation_date")
    creation_dt = None

    if isinstance(creation, list) and creation:
        vals = [c for c in creation if c is not None]
        if vals:
            creation = min(vals)
        else:
            creation = None

    if isinstance(creation, datetime):
        creation_dt = creation
    elif isinstance(creation, date):
        creation_dt = datetime(creation.year, creation.month, creation.day)
    elif isinstance(creation, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y"):
            try:
                creation_dt = datetime.strptime(creation[:19], fmt)
                break
            except Exception:
                continue

    age_days = None
    if creation_dt is not None:
        if creation_dt.tzinfo is not None:
            creation_dt = creation_dt.astimezone(timezone.utc).replace(tzinfo=None)
            now = datetime.utcnow()
        else:
            now = datetime.now()
        age_days = (now - creation_dt).days

    if age_days is None:
        reasons.append("Brak wiarygodnej daty rejestracji domeny – nie można ocenić wieku.")
    else:
        if age_days < 30:
            score -= 15
            reasons.append("Domena bardzo młoda (<30 dni) – zwiększone ryzyko nadużyć.")
        elif age_days < 365:
            score -= 5
            reasons.append("Domena młoda (<1 rok).")
        elif age_days > 365 * 5:
            score += 5
            reasons.append("Domena istnieje >5 lat – mniejsze prawdopodobieństwo świeżych kampanii.")

    # HTTP / HTTPS
    http = report.get("http", {})
    status = http.get("status")
    if status is None:
        score -= 5
        reasons.append("Brak odpowiedzi HTTP – domena może być nieaktywna lub jedynie tymczasowa.")
    else:
        if 200 <= status < 300:
            score += 3
            reasons.append("Domena zwraca kod 2xx – strona działa prawidłowo.")
        elif 300 <= status < 400:
            reasons.append("Domena zwraca przekierowanie (3xx).")
        else:
            score -= 3
            reasons.append("Domena zwraca błąd HTTP (4xx/5xx).")

    final_url = http.get("final_url")
    if final_url and final_url.startswith("https://"):
        score += 2
        reasons.append("Strona używa HTTPS – lepsze praktyki ochrony komunikacji.")

    # Archiwa
    archives = report.get("archives", {})
    wayback = archives.get("wayback", {})
    google_cache = archives.get("google_cache", {})
    if wayback.get("available"):
        score += 2
        reasons.append("Domena posiada archiwa Wayback – wskazuje na dłuższą obecność w sieci.")
    if google_cache.get("cached"):
        score += 1
        reasons.append("Domena występuje w Google Cache – dodatkowa oznaka obecności w indeksie.")

    # Shodan
    shodan_data = report.get("shodan", {})
    if shodan_data:
        total_ports = 0
        suspicious_ports = 0
        suspicious_set = {21, 22, 23, 445, 3389, 5900, 3306, 5432}
        for ip, info in shodan_data.items():
            if not isinstance(info, dict) or "error" in info:
                continue
            ports = info.get("ports") or []
            total_ports += len(ports)
            for p in ports:
                if p in suspicious_set:
                    suspicious_ports += 1

        if total_ports == 0:
            reasons.append("Shodan nie raportuje otwartych portów – brak ekspozycji usług.")
            score += 1
        else:
            if suspicious_ports > 0:
                score -= 10
                reasons.append("Shodan raportuje otwarte porty usług administracyjnych (SSH/RDP/itp.).")
            elif total_ports > 10:
                score -= 5
                reasons.append("Shodan raportuje dużą liczbę otwartych portów – większa powierzchnia ataku.")
            else:
                score -= 2
                reasons.append("Shodan raportuje kilka otwartych portów – standardowa ekspozycja usług.")

    # check-host
    ch = report.get("check_host", {})
    ping_data = ch.get("ping")
    http_data = ch.get("http")
    if (ping_data and "error" in ping_data) or (http_data and "error" in http_data):
        score -= 2
        reasons.append("W testach check-host.net wystąpiły błędy – utrudniona ocena łączności.")
    elif ch:
        score += 1
        reasons.append("Zewnętrzne testy łączności (check-host.net) zostały wykonane.")

    score = max(0, min(100, score))
    if score >= 70:
        level = "Niskie"
    elif score >= 40:
        level = "Średnie"
    else:
        level = "Wysokie"

    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }


# ---------- GŁÓWNA ANALIZA ----------

def analyze_domain(domain: str,
                   shodan_api_key: Optional[str] = None,
                   use_check_host: bool = False,
                   check_host_max_nodes: int = 5) -> dict:
    """
    Główny "backend" analizy domeny – zwraca ustrukturyzowany raport.
    """
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        raise ValueError(f"Niepoprawna domena: {normalized}")

    report = {
        "input": domain,
        "normalized": normalized,
        "dns": {},
        "whois": {},
        "http": {},
        "ips": [],
        "archives": {},
        "shodan": {},
        "check_host": {},
        "summary": {},
        "risk": {}
    }

    # DNS
    report["dns"] = dns_lookup(normalized)

    # WHOIS
    report["whois"] = whois_lookup(normalized)

    # HTTP
    report["http"] = http_check(normalized)

    # IP
    ips = sorted(set(report["dns"].get("A", []) + report["dns"].get("AAAA", [])))
    report["ips"] = ips

    # Archiwa
    report["archives"]["wayback"] = check_wayback_archive(normalized)
    report["archives"]["google_cache"] = check_google_cache(normalized)

    # Shodan
    if shodan_api_key and ips:
        for ip in ips:
            report["shodan"][ip] = shodan_lookup(ip, shodan_api_key)

    # check-host
    if use_check_host:
        report["check_host"]["ping"] = check_host_request("ping", normalized, check_host_max_nodes)
        report["check_host"]["http"] = check_host_request("http", normalized, check_host_max_nodes)

    # Podsumowanie opisowe
    risk_notes: List[str] = []
    if report["http"].get("status") in (200, 301, 302):
        risk_notes.append("Strona aktywna (HTTP).")
    else:
        risk_notes.append("Brak odpowiedzi HTTP lub błąd podczas próby połączenia.")

    if report["dns"].get("A") or report["dns"].get("AAAA"):
        risk_notes.append("Domena rozwiązuje się w DNS (ma rekordy A/AAAA).")
    else:
        risk_notes.append("Brak rekordów A/AAAA (lub nie udało się ich pobrać).")

    if "error" in report["whois"]:
        risk_notes.append("Brak danych WHOIS lub błąd odczytu.")
    else:
        risk_notes.append("Dane WHOIS zostały pobrane (szczegóły w raporcie).")

    wayback = report["archives"].get("wayback", {})
    if wayback.get("available"):
        risk_notes.append("Domena posiada archiwalne kopie w Internet Archive (Wayback Machine).")

    google_cache = report["archives"].get("google_cache", {})
    if google_cache.get("cached"):
        risk_notes.append("Domena posiada kopię cache w Google (webcache.googleusercontent.com).")

    if shodan_api_key:
        if report["shodan"]:
            any_ports = any(
                isinstance(info, dict) and info.get("ports")
                for info in report["shodan"].values()
            )
            if any_ports:
                risk_notes.append("Shodan raportuje otwarte porty na części adresów IP domeny.")
            else:
                risk_notes.append("Shodan nie raportuje otwartych portów dla znanych adresów IP domeny.")
    else:
        risk_notes.append("Shodan nie został użyty (brak skonfigurowanego klucza API).")

    if use_check_host:
        ch_ping = report["check_host"].get("ping", {})
        ch_http = report["check_host"].get("http", {})
        if ("error" in ch_ping if ch_ping else False) or ("error" in ch_http if ch_http else False):
            risk_notes.append("Wystąpiły błędy podczas zdalnych testów ping/HTTP (check-host.net).")
        else:
            risk_notes.append("Wykonano zdalne testy ping/HTTP z wielu lokalizacji (check-host.net).")

    report["summary"]["notes"] = risk_notes

    # Scoring
    report["risk"] = compute_risk(report)

    return report


# ---------- FORMATOWANIE RAPORTU ----------

def format_check_host_ping(ping_data: dict) -> List[str]:
    lines: List[str] = []
    if not ping_data:
        lines.append("Brak danych z testu ping.")
        return lines
    if "error" in ping_data:
        lines.append(f"Test ping: błąd – {ping_data['error']}")
        return lines

    results = ping_data.get("results")
    nodes_meta = ping_data.get("request", {}).get("nodes", {})

    if not isinstance(results, dict):
        lines.append(f"Test ping – surowe dane: {results}")
        return lines

    lines.append("4.1. Wyniki testu ping (czasy/stany per węzeł):")
    for node, measurements in results.items():
        if measurements is None:
            lines.append(f"  - {node}: brak danych")
            continue

        meta = nodes_meta.get(node, [])
        country = city = "nieznane"
        if isinstance(meta, list):
            if len(meta) >= 3:
                country = meta[2]
            if len(meta) >= 4:
                city = meta[3]

        region = infer_region_from_node(node)
        times = []
        statuses = set()
        for m in measurements:
            if isinstance(m, list) and len(m) >= 3:
                statuses.add(str(m[1]))
                times.append(str(m[2]))
        times_str = ", ".join(times) if times else "-"
        statuses_str = ", ".join(sorted(statuses)) if statuses else "-"

        lines.append(
            f"  - {node} [region={region}, kraj={country}, miasto={city}]: "
            f"statusy={statuses_str}, czasy_ms={times_str}"
        )
    return lines


def format_check_host_http(http_data: dict) -> List[str]:
    lines: List[str] = []
    if not http_data:
        lines.append("Brak danych z testu HTTP.")
        return lines
    if "error" in http_data:
        lines.append(f"Test HTTP: błąd – {http_data['error']}")
        return lines

    results = http_data.get("results")
    nodes_meta = http_data.get("request", {}).get("nodes", {})

    if not isinstance(results, dict):
        lines.append(f"Test HTTP – surowe dane: {results}")
        return lines

    lines.append("4.2. Wyniki testu HTTP (kody/czasy per węzeł):")
    for node, measurements in results.items():
        if measurements is None:
            lines.append(f"  - {node}: brak danych")
            continue

        meta = nodes_meta.get(node, [])
        country = city = "nieznane"
        if isinstance(meta, list):
            if len(meta) >= 3:
                country = meta[2]
            if len(meta) >= 4:
                city = meta[3]

        region = infer_region_from_node(node)
        codes = set()
        times = []
        for m in measurements:
            if isinstance(m, list) and len(m) >= 3:
                codes.add(str(m[1]))
                times.append(str(m[2]))
        codes_str = ", ".join(sorted(codes)) if codes else "-"
        times_str = ", ".join(times) if times else "-"
        lines.append(
            f"  - {node} [region={region}, kraj={country}, miasto={city}]: "
            f"kody={codes_str}, czasy_ms={times_str}"
        )
    return lines


def format_report(report: dict) -> str:
    """
    Raport w układzie bardziej naukowym.
    """
    lines: List[str] = []

    domain_in = report["input"]
    domain_norm = report["normalized"]

    # 0. Nagłówek
    lines.append(f"Raport dotyczący domeny: {domain_in} (znormalizowana: {domain_norm})")
    lines.append("=" * 80)
    lines.append("")

    # 1. Dane podstawowe
    lines.append("1. Dane podstawowe")
    lines.append("-------------------")
    ips = report.get("ips", [])
    lines.append(f"1.1. Domena wejściowa: {domain_in}")
    lines.append(f"1.2. Domena po normalizacji: {domain_norm}")
    if ips:
        lines.append(f"1.3. Powiązane adresy IP (DNS A/AAAA): {', '.join(ips)}")
    else:
        lines.append("1.3. Powiązane adresy IP (DNS A/AAAA): brak / nie udało się pobrać.")
    lines.append("")

    # 2. DNS
    lines.append("2. Analiza DNS")
    lines.append("----------------")
    lines.append("2.1. Wybrane typy rekordów DNS:")
    lines.append("  - A    – adres IPv4 przypisany do domeny (hosta).")
    lines.append("  - AAAA – adres IPv6 przypisany do domeny (hosta).")
    lines.append("  - MX   – serwery pocztowe obsługujące pocztę dla domeny.")
    lines.append("  - NS   – serwery nazw (Name Server) odpowiedzialne za strefę DNS domeny.")
    lines.append("  - TXT  – rekordy tekstowe (np. SPF, DMARC, inne informacje kontrolne).")
    lines.append("")
    dns_data = report.get("dns", {})
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        vals = dns_data.get(rtype, [])
        if vals:
            lines.append(f"2.2. Rekordy {rtype}:")
            for v in vals:
                lines.append(f"     - {v}")
        else:
            lines.append(f"2.2. Rekordy {rtype}: (brak danych / nie udało się pobrać)")
    if dns_data.get("errors"):
        lines.append("2.3. Błędy DNS (podczas zapytań):")
        for e in dns_data["errors"]:
            lines.append(f"     - {e}")
    lines.append("")

    # 3. WHOIS
    lines.append("3. Dane rejestracyjne WHOIS")
    lines.append("--------------------------------")
    lines.append("WHOIS – protokół i baza danych przechowująca informacje o rejestracji domeny.")
    lines.append("")
    who = report.get("whois", {})
    if "error" in who:
        lines.append(f"3.1. WHOIS: {who['error']}")
    else:
        lines.append(f"3.1. Nazwa domeny w WHOIS: {who.get('domain_name')}")
        lines.append(f"3.2. Rejestrator: {who.get('registrar')}")
        lines.append(f"3.3. Data rejestracji: {who.get('creation_date')}")
        lines.append(f"3.4. Data wygaśnięcia: {who.get('expiration_date')}")
        lines.append(f"3.5. Serwery nazw (NS): {who.get('name_servers')}")
        lines.append(f"3.6. Adresy e-mail w WHOIS: {who.get('emails')}")
    lines.append("")

    # 4. HTTP/HTTPS i testy zewnętrzne
    lines.append("4. HTTP/HTTPS i testy zewnętrzne")
    lines.append("-----------------------------------")
    http = report.get("http", {})
    lines.append("4.0. Test lokalny HTTP/HTTPS (requests):")
    lines.append(f"  - Próbowane URL-e: {http.get('url_tried')}")
    lines.append(f"  - Kod odpowiedzi HTTP: {http.get('status')}")
    lines.append(f"  - Finalny URL (po przekierowaniach): {http.get('final_url')}")
    if http.get("headers"):
        lines.append("  - Wybrane nagłówki odpowiedzi:")
        key_subset = ["Server", "X-Powered-By", "Content-Type"]
        for k in key_subset:
            if k in http["headers"]:
                lines.append(f"      {k}: {http['headers'][k]}")
    if http.get("errors"):
        lines.append("  - Błędy HTTP (podczas łączenia):")
        for e in http["errors"]:
            lines.append(f"      - {e}")
    lines.append("")

    ch = report.get("check_host", {})
    ping_data = ch.get("ping")
    http_data = ch.get("http")
    if not ch:
        lines.append("4.x. Zewnętrzne testy z wielu lokalizacji (check-host.net) nie były wykonywane.")
    else:
        lines.extend(format_check_host_ping(ping_data))
        lines.append("")
        lines.extend(format_check_host_http(http_data))
    lines.append("")

    # 5. Infrastruktura IP i Shodan
    lines.append("5. Infrastruktura IP i dane z Shodan")
    lines.append("----------------------------------------")
    lines.append("Shodan – wyszukiwarka urządzeń i usług w Internecie.")
    lines.append("")
    shodan_data = report.get("shodan", {})
    if not shodan_data:
        lines.append("5.1. Shodan nie był użyty lub nie zwrócił danych.")
    else:
        for ip, info in shodan_data.items():
            lines.append(f"5.2. IP: {ip}")
            if not isinstance(info, dict):
                lines.append(f"     - Nieoczekiwany format danych Shodan: {info}")
                continue
            if "error" in info:
                lines.append(f"     - Błąd / informacja: {info['error']}")
                continue
            if "info" in info:
                lines.append(f"     - Informacja: {info['info']}")
            lines.append(f"     - Organizacja / ISP: {info.get('org') or info.get('isp')}")
            lines.append(f"     - System operacyjny (jeśli wykryto): {info.get('os')}")
            ports = info.get("ports") or []
            if ports:
                lines.append(f"     - Otwarte porty według Shodan: {sorted(ports)}")
            else:
                lines.append("     - Brak informacji o otwartych portach w Shodan.")
    lines.append("")

    # 6. Archiwa
    lines.append("6. Archiwa i kopie strony")
    lines.append("---------------------------")
    archives = report.get("archives", {})
    wayback = archives.get("wayback", {})
    google_cache = archives.get("google_cache", {})
    if wayback.get("available"):
        lines.append("6.1. Wayback Machine:")
        lines.append(f"     - Archiwum dostępne: TAK")
        lines.append(f"     - Ostatnia znana kopia (timestamp): {wayback.get('timestamp')}")
        lines.append(f"     - URL archiwum: {wayback.get('archive_url')}")
    elif "error" in wayback:
        lines.append(f"6.1. Wayback Machine: błąd – {wayback['error']}")
    else:
        lines.append("6.1. Wayback Machine: brak informacji o archiwalnych kopiach.")
    if google_cache.get("cached") is True:
        lines.append("6.2. Google Cache:")
        lines.append(f"     - Kopia w Google Cache: TAK (status {google_cache.get('status')})")
        lines.append(f"     - URL cache: {google_cache.get('cache_url')}")
    elif google_cache.get("cached") is False:
        lines.append("6.2. Google Cache:")
        lines.append(f"     - Kopia w Google Cache: NIE (status {google_cache.get('status')})")
    elif "error" in google_cache:
        lines.append(f"6.2. Google Cache: błąd – {google_cache['error']}")
    else:
        lines.append("6.2. Google Cache: brak jednoznacznej informacji.")
    lines.append("")

    # 7. Scoring ryzyka
    lines.append("7. Scoring ryzyka domeny")
    lines.append("---------------------------")
    risk = report.get("risk", {})
    score = risk.get("score")
    level = risk.get("level")
    lines.append(f"7.1. Wynik punktowy (0–100): {score}")
    lines.append(f"7.2. Poziom ryzyka: {level}")
    lines.append("7.3. Czynniki wpływające na scoring:")
    for r in risk.get("reasons", []):
        lines.append(f"     - {r}")
    lines.append("")

    # 8. Wnioski opisowe
    lines.append("8. Wnioski opisowe z analizy")
    lines.append("--------------------------------")
    for note in report.get("summary", {}).get("notes", []):
        lines.append(f"- {note}")
    lines.append("")

    # 9. Legenda
    lines.append("9. Legenda pojęć")
    lines.append("-----------------")
    lines.append("DNS A/AAAA – mapowanie nazwy domenowej na adres IPv4 / IPv6.")
    lines.append("DNS MX – serwery pocztowe obsługujące pocztę dla domeny.")
    lines.append("DNS NS – serwery nazw odpowiedzialne za strefę DNS domeny.")
    lines.append("DNS TXT – rekordy tekstowe (np. SPF/DMARC).")
    lines.append("WHOIS – rejestr danych o właścicielu/rejestracji domeny.")
    lines.append("HTTP 2xx – poprawna odpowiedź serwera.")
    lines.append("HTTP 3xx – przekierowanie.")
    lines.append("HTTP 4xx/5xx – błąd po stronie klienta/serwera.")
    lines.append("Shodan – wyszukiwarka urządzeń/portów widocznych z Internetu.")
    lines.append("check-host.net – zewnętrzne testy ping/HTTP/TCP/DNS z wielu lokalizacji.")
    lines.append("Scoring 0–39 – Wysokie ryzyko.")
    lines.append("Scoring 40–69 – Średnie ryzyko.")
    lines.append("Scoring 70–100 – Niskie ryzyko.")
    lines.append("")

    # 10. Źródła
    lines.append("10. Wykaz wykorzystanych źródeł OSINT i narzędzi")
    lines.append("-----------------------------------------------")
    lines.append("- Zapytania DNS (dnspython / socket).")
    lines.append("- Dane WHOIS (python-whois).")
    lines.append("- HTTP/HTTPS (requests).")
    lines.append("- Internet Archive – Wayback Machine (API availability).")
    lines.append("- Google Cache (webcache.googleusercontent.com).")
    lines.append("- Shodan API (jeśli skonfigurowano klucz API).")
    lines.append("- check-host.net (testy ping/HTTP z wielu lokalizacji).")
    lines.append("")
    lines.append("Program: OSINT Domain Analyzer, autor: pawlict, licencja MIT \"AS IS\".")
    lines.append(f"Wersja programu: {APP_VERSION}")
    lines.append("Biblioteki: requests, python-whois, dnspython, reportlab, selenium, tkinter itd.")
    lines.append("")
    lines.append(
        "Uwaga: raport ma charakter informacyjny (OSINT) i nie stanowi formalnego audytu "
        "bezpieczeństwa ani jednoznacznej atrybucji."
    )

    return "\n".join(lines)


# ---------- GENEROWANIE PDF ----------

def create_pdf_with_text_and_optional_screenshot(pdf_path: str,
                                                 text: str,
                                                 screenshot_url: Optional[str] = None) -> None:
    """
    Tworzy PDF: jeśli uda się zrobić screenshot – pierwsza strona to zrzut,
    potem tekst raportu.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("Brak biblioteki reportlab.")

    c = pdf_canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    margin = 40
    text_top = height - margin
    line_height = 12

    # Strona z screenshotem (opcjonalnie)
    if screenshot_url and SELENIUM_AVAILABLE:
        screenshot_path = os.path.splitext(pdf_path)[0] + "_screenshot.png"
        if capture_screenshot(screenshot_url, screenshot_path):
            try:
                c.setFont("Helvetica-Bold", 14)
                c.drawString(margin, height - margin - line_height, "Zrzut ekranu strony (widok główny)")
                c.setFont("Helvetica", 9)

                img = ImageReader(screenshot_path)
                iw, ih = img.getSize()
                max_w = width - 2 * margin
                max_h = height - 3 * margin - 20
                scale = min(max_w / iw, max_h / ih)
                new_w, new_h = iw * scale, ih * scale
                x = (width - new_w) / 2
                y = height - 2 * margin - new_h - 20
                c.drawImage(img, x, y, new_w, new_h)
                c.showPage()
            except Exception as e:
                print("Błąd wstawiania screenshota do PDF:", e)

    # Strony z tekstem
    c.setFont("Helvetica", 9)
    y = text_top
    for raw_line in text.splitlines():
        if not raw_line:
            y -= line_height
            if y < margin:
                c.showPage()
                c.setFont("Helvetica", 9)
                y = text_top
            continue
        wrapped = textwrap.wrap(raw_line, width=100) or [""]
        for line in wrapped:
            c.drawString(margin, y, line)
            y -= line_height
            if y < margin:
                c.showPage()
                c.setFont("Helvetica", 9)
                y = text_top

    c.save()


# ---------- GUI (tkinter) ----------

class DomainOSINTApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OSINT domeny – prosty analizator")
        self.geometry("1100x780")

        self.shodan_api_var = tk.StringVar()
        self.use_check_host_var = tk.BooleanVar(value=False)
        self.check_host_max_nodes_var = tk.IntVar(value=5)

        self.last_report = None
        self.last_report_text = None

        self.create_widgets()
        self.load_config()

    # --- konfiguracja zapisu/odczytu ---

    def load_config(self):
        """Wczytuje klucz API Shodan z pliku konfiguracyjnego."""
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                key = data.get("shodan_api_key", "")
                self.shodan_api_var.set(key)
        except Exception as e:
            print("Nie udało się odczytać konfiguracji:", e)

    def save_config(self):
        """Zapisuje aktualny klucz API Shodan do pliku konfiguracyjnego."""
        data = {
            "shodan_api_key": self.shodan_api_var.get().strip()
        }
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            messagebox.showinfo(
                "Zapisano ustawienia",
                f"Ustawienia zapisane do pliku:\n{CONFIG_PATH}\n"
                "Uwaga: klucz API jest zapisany w postaci jawnej (plaintext)."
            )
        except Exception as e:
            messagebox.showerror("Błąd zapisu konfiguracji", str(e))

    # --- tworzenie GUI ---

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)

        self.main_frame = ttk.Frame(notebook)
        notebook.add(self.main_frame, text="Analiza domeny")

        self.settings_frame = ttk.Frame(notebook)
        notebook.add(self.settings_frame, text="Ustawienia (Shodan / Check-Host)")

        self.info_frame = ttk.Frame(notebook)
        notebook.add(self.info_frame, text="Info")

        # --- zakładka Analiza ---
        top_frame = ttk.Frame(self.main_frame)
        top_frame.pack(fill="x", padx=10, pady=10)

        lbl = ttk.Label(top_frame, text="Domena:")
        lbl.pack(side="left")

        self.domain_var = tk.StringVar()
        entry = ttk.Entry(top_frame, textvariable=self.domain_var, width=50)
        entry.pack(side="left", padx=5)
        entry.bind("<Return>", lambda e: self.run_analysis())

        btn = ttk.Button(top_frame, text="Analizuj", command=self.run_analysis)
        btn.pack(side="left", padx=5)

        self.info_var = tk.StringVar(value="Wpisz domenę (np. example.com) i kliknij 'Analizuj'.")
        info_label = ttk.Label(self.main_frame, textvariable=self.info_var)
        info_label.pack(fill="x", padx=10, pady=(0, 5))

        self.text = scrolledtext.ScrolledText(self.main_frame, wrap="word")
        self.text.pack(fill="both", expand=True, padx=10, pady=10)

        bottom_frame = ttk.Frame(self.main_frame)
        bottom_frame.pack(fill="x", padx=10, pady=(0, 10))

        btn_save_txt = ttk.Button(bottom_frame, text="Zapisz raport jako TXT", command=self.save_report_txt)
        btn_save_txt.pack(side="left", padx=5)

        btn_save_pdf = ttk.Button(
            bottom_frame,
            text="Zapisz raport jako PDF (z opcjonalnym screenshotem)",
            command=self.save_report_pdf
        )
        btn_save_pdf.pack(side="left", padx=5)

        # --- zakładka Ustawienia ---
        settings_inner = ttk.Frame(self.settings_frame)
        settings_inner.pack(fill="both", expand=True, padx=10, pady=10)

        shodan_label = ttk.Label(settings_inner, text="Klucz API Shodan (opcjonalnie):")
        shodan_label.pack(anchor="w")

        shodan_entry = ttk.Entry(settings_inner, textvariable=self.shodan_api_var, width=60, show="*")
        shodan_entry.pack(anchor="w", pady=5)

        shodan_help = ttk.Label(
            settings_inner,
            text=("Jeśli klucz API Shodan zostanie podany, program spróbuje pobrać informacje "
                  "o otwartych portach na adresach IP powiązanych z domeną.\n"
                  "Uwaga: korzystanie z Shodan podlega limitom i regulaminowi usługi.")
        )
        shodan_help.pack(anchor="w", pady=(0, 5))

        save_cfg_btn = ttk.Button(settings_inner, text="Zapisz ustawienia (klucz Shodan)", command=self.save_config)
        save_cfg_btn.pack(anchor="w", pady=(5, 15))

        chk_frame = ttk.LabelFrame(settings_inner, text="check-host.net – zdalne testy")
        chk_frame.pack(fill="x", pady=5)

        use_ch = ttk.Checkbutton(
            chk_frame,
            text="Włącz testy ping/HTTP przez check-host.net",
            variable=self.use_check_host_var
        )
        use_ch.pack(anchor="w", pady=5)

        max_nodes_label = ttk.Label(chk_frame, text="Maksymalna liczba węzłów (max_nodes):")
        max_nodes_label.pack(anchor="w")

        max_nodes_spin = ttk.Spinbox(
            chk_frame,
            from_=1,
            to=10,
            textvariable=self.check_host_max_nodes_var,
            width=5
        )
        max_nodes_spin.pack(anchor="w", pady=(0, 5))

        ch_help = ttk.Label(
            chk_frame,
            text=("check-host.net umożliwia wykonywanie zewnętrznych testów ping/HTTP/TCP/DNS "
                  "z wielu lokalizacji. Program używa API w trybie tylko do odczytu wyników.")
        )
        ch_help.pack(anchor="w", pady=(0, 5))

        # --- zakładka Info ---
        info_inner = ttk.Frame(self.info_frame)
        info_inner.pack(fill="both", expand=True, padx=10, pady=10)

        title_label = ttk.Label(info_inner, text="OSINT Domain Analyzer", font=("TkDefaultFont", 14, "bold"))
        title_label.pack(anchor="w", pady=(0, 10))

        info_lines = [
            f"Autor: pawlict",
            f"Wersja: {APP_VERSION}",
            "Licencja: MIT (\"AS IS\")",
            "",
            "Opis:",
            "- Prosty kombajn OSINT do analizy domeny (DNS, WHOIS, HTTP, archiwa, Shodan, check-host).",
            "- Wyniki w formie raportu tekstowego oraz eksport do PDF/TXT.",
            "",
            "Biblioteki:",
            "- requests – zapytania HTTP",
            "- python-whois – dane WHOIS",
            "- dnspython – zapytania DNS (jeśli dostępne)",
            "- reportlab – generowanie raportu PDF",
            "- selenium (+ geckodriver) – zrzuty ekranu domeny",
            "- tkinter – interfejs graficzny (GUI)",
            "",
            "Uwaga:",
            "Narzędzie ma charakter demonstracyjno-badawczy i służy do analizy OSINT.",
            "Nie zastępuje pełnego audytu bezpieczeństwa ani komercyjnych systemów TI."
        ]
        for line in info_lines:
            ttk.Label(info_inner, text=line).pack(anchor="w")

    # --- akcje GUI ---

    def run_analysis(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showwarning("Brak domeny", "Podaj domenę do analizy.")
            return

        self.info_var.set("Analiza w toku...")
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, f"Analiza domeny: {domain}\n\n")

        api_key = self.shodan_api_var.get().strip() or None
        use_check_host = self.use_check_host_var.get()
        max_nodes = self.check_host_max_nodes_var.get()

        try:
            report = analyze_domain(
                domain,
                shodan_api_key=api_key,
                use_check_host=use_check_host,
                check_host_max_nodes=max_nodes
            )
            formatted = format_report(report)
            self.text.insert(tk.END, formatted)
            self.info_var.set("Analiza zakończona.")
            self.last_report = report
            self.last_report_text = formatted
        except ValueError as ve:
            self.info_var.set("Błąd walidacji domeny.")
            messagebox.showerror("Błąd", str(ve))
        except Exception as e:
            self.info_var.set("Wystąpił błąd podczas analizy.")
            messagebox.showerror("Błąd", str(e))

    def save_report_txt(self):
        if not self.last_report_text or not self.last_report:
            messagebox.showinfo("Brak danych", "Najpierw wykonaj analizę domeny.")
            return

        norm = self.last_report.get("normalized", "domena")
        default_name = f"raport_{norm}.txt"

        filename = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Plik tekstowy", "*.txt"), ("Wszystkie pliki", "*.*")]
        )
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.last_report_text)
            messagebox.showinfo("Zapisano", f"Raport zapisany jako: {filename}")
        except Exception as e:
            messagebox.showerror("Błąd zapisu", str(e))

    def save_report_pdf(self):
        if not self.last_report_text or not self.last_report:
            messagebox.showinfo("Brak danych", "Najpierw wykonaj analizę domeny.")
            return

        if not REPORTLAB_AVAILABLE:
            messagebox.showerror(
                "Brak biblioteki reportlab",
                "Do tworzenia PDF potrzebny jest pakiet 'reportlab'.\n"
                "Zainstaluj go poleceniem: pip install reportlab"
            )
            return

        norm = self.last_report.get("normalized", "domena")
        default_name = f"raport_{norm}.pdf"

        filename = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".pdf",
            filetypes=[("Plik PDF", "*.pdf"), ("Wszystkie pliki", "*.*")]
        )
        if not filename:
            return

        http_data = self.last_report.get("http", {})
        screenshot_url = http_data.get("final_url") or f"http://{self.last_report.get('normalized', '')}"

        if not SELENIUM_AVAILABLE:
            messagebox.showinfo(
                "Brak Selenium",
                "Pakiet 'selenium' lub geckodriver nie są dostępne, więc PDF nie będzie zawierał zrzutu ekranu.\n"
                "Możesz je doinstalować: pip install selenium + geckodriver w PATH."
            )
            screenshot_url = None

        try:
            create_pdf_with_text_and_optional_screenshot(
                filename,
                self.last_report_text,
                screenshot_url=screenshot_url
            )
            messagebox.showinfo("Zapisano", f"Raport PDF zapisany jako: {filename}")
        except Exception as e:
            messagebox.showerror("Błąd przy tworzeniu PDF", str(e))


if __name__ == "__main__":
    app = DomainOSINTApp()
    app.mainloop()
