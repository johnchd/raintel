#!/usr/bin/env python3
"""
Rockwell Automation Vulnerability Intelligence Collector
Fetches data from CISA KEV, CISA ICS advisories, NVD CVE API, and security news.
"""

import sqlite3
import requests
import feedparser
import json
import logging
import hashlib
import re
import time
from datetime import datetime, timezone
from bs4 import BeautifulSoup

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('collector')

DB_PATH = 'data/intel.db'

HEADERS = {
    'User-Agent': 'RockwellIntelHub/1.0 (Security Intelligence Aggregator; contact@example.com)'
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            source TEXT,
            type TEXT,
            title TEXT,
            cve TEXT,
            severity TEXT,
            cvss_score REAL,
            products TEXT,
            summary TEXT,
            published_date TEXT,
            refs TEXT,
            source_url TEXT,
            first_seen TEXT,
            last_seen TEXT,
            kev_alerted INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def make_id(source, key):
    raw = f"{source}:{key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def upsert_finding(conn, finding):
    """Insert finding or update last_seen if duplicate. Returns True if new."""
    existing = conn.execute(
        'SELECT id, kev_alerted FROM findings WHERE id = ?', (finding['id'],)
    ).fetchone()

    if existing:
        conn.execute(
            'UPDATE findings SET last_seen = ? WHERE id = ?',
            (now_iso(), finding['id'])
        )
        return False, existing['kev_alerted']
    else:
        conn.execute('''
            INSERT INTO findings
                (id, source, type, title, cve, severity, cvss_score, products,
                 summary, published_date, refs, source_url, first_seen, last_seen, kev_alerted)
            VALUES
                (:id, :source, :type, :title, :cve, :severity, :cvss_score, :products,
                 :summary, :published_date, :refs, :source_url, :first_seen, :last_seen, :kev_alerted)
        ''', finding)
        return True, 0

def cvss_to_severity(score):
    if score is None:
        return 'Unknown'
    score = float(score)
    if score >= 9.0:
        return 'Critical'
    elif score >= 7.0:
        return 'High'
    elif score >= 4.0:
        return 'Medium'
    elif score > 0:
        return 'Low'
    return 'Unknown'

# ─── Source 1: CISA KEV ───────────────────────────────────────────────────────

def collect_cisa_kev():
    logger.info("Collecting CISA KEV...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    new_findings = []
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        logger.info(f"CISA KEV: {len(vulns)} total entries")

        conn = get_db()
        count_new = 0
        for v in vulns:
            vendor = v.get('vendorProject', '')
            if 'rockwell' not in vendor.lower():
                continue

            cve_id = v.get('cveID', '')
            finding_id = make_id('CISA_KEV', cve_id)
            refs = json.dumps([v.get('shortDescription', '')])
            finding = {
                'id': finding_id,
                'source': 'CISA_KEV',
                'type': 'KEV',
                'title': f"{cve_id} - {v.get('product', 'Unknown')}",
                'cve': cve_id,
                'severity': 'Critical',  # KEV = known exploited = critical
                'cvss_score': None,
                'products': v.get('product', ''),
                'summary': v.get('shortDescription', ''),
                'published_date': v.get('dateAdded', ''),
                'refs': json.dumps([f"https://nvd.nist.gov/vuln/detail/{cve_id}"]),
                'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'first_seen': now_iso(),
                'last_seen': now_iso(),
                'kev_alerted': 0,
            }
            is_new, _ = upsert_finding(conn, finding)
            if is_new:
                count_new += 1
                new_findings.append(finding)

        conn.commit()
        conn.close()
        logger.info(f"CISA KEV: {count_new} new Rockwell findings")
    except Exception as e:
        logger.error(f"CISA KEV failed: {e}")

    return new_findings

# ─── Source 2: CISA ICS Advisories (via CSAF GitHub) ─────────────────────────

CSAF_INDEX_URL = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/index.txt"
CSAF_BASE_URL  = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"

def collect_cisa_ics():
    logger.info("Collecting CISA ICS advisories via CSAF GitHub...")
    new_findings = []
    try:
        # Fetch the full file index
        resp = requests.get(CSAF_INDEX_URL, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        all_paths = [l.strip() for l in resp.text.splitlines() if l.strip().endswith('.json')]
        logger.info(f"CISA ICS: {len(all_paths)} total CSAF files in index")

        # Limit to last 24 months of advisories by year prefix
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)
        cutoff_year = cutoff.year  # e.g. 2024
        recent_paths = [p for p in all_paths if any(
            p.startswith(str(y) + '/') for y in range(cutoff_year, datetime.now(timezone.utc).year + 1)
        )]
        logger.info(f"CISA ICS: {len(recent_paths)} CSAF files from {cutoff_year} onwards")

        conn = get_db()
        count_new = 0
        count_checked = 0

        for path in recent_paths:
            url = CSAF_BASE_URL + path
            try:
                r = requests.get(url, headers=HEADERS, timeout=20)
                if r.status_code != 200:
                    continue
                data = r.json()
                count_checked += 1

                # Check if Rockwell Automation is the vendor
                doc = data.get('document', {})
                product_tree = data.get('product_tree', {})
                branches = product_tree.get('branches', [])
                is_rockwell = any(
                    'rockwell' in b.get('name', '').lower()
                    for b in branches
                    if b.get('category') == 'vendor'
                )
                if not is_rockwell:
                    # Also check vulnerabilities notes
                    full_text = json.dumps(data).lower()
                    if 'rockwell' not in full_text:
                        continue

                # Extract advisory details
                tracking = doc.get('tracking', {})
                advisory_id = tracking.get('id', path.replace('.json', ''))
                title = doc.get('title', advisory_id)
                pub_date = tracking.get('initial_release_date', '')

                # CVEs
                vulns = data.get('vulnerabilities', [])
                cves = [v.get('cve', '') for v in vulns if v.get('cve')]
                cve_str = ', '.join(cves)

                # CVSS score from first vulnerability
                cvss_score = None
                for v in vulns:
                    scores = v.get('scores', [])
                    for s in scores:
                        cvss_data = s.get('cvss_v3', s.get('cvss_v4', {}))
                        if cvss_data.get('baseScore'):
                            cvss_score = float(cvss_data['baseScore'])
                            break
                    if cvss_score:
                        break

                severity = cvss_to_severity(cvss_score)

                # Products
                product_names = set()
                for b in branches:
                    if b.get('category') == 'vendor':
                        for sub in b.get('branches', []):
                            product_names.add(sub.get('name', ''))
                products_str = ', '.join(list(product_names)[:5])

                # Summary from notes
                summary = ''
                for note in doc.get('notes', []):
                    if note.get('category') in ('summary', 'description', 'general'):
                        summary = note.get('text', '')[:600]
                        break
                if not summary:
                    # Try vulnerability notes
                    for v in vulns[:1]:
                        for note in v.get('notes', []):
                            summary = note.get('text', '')[:600]
                            if summary:
                                break

                source_url = f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}"
                finding_id = make_id('CISA_ICS', advisory_id)
                finding = {
                    'id': finding_id,
                    'source': 'CISA_ICS',
                    'type': 'Advisory',
                    'title': title,
                    'cve': cve_str,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'products': products_str,
                    'summary': summary,
                    'published_date': pub_date,
                    'refs': json.dumps([source_url] + [r.get('url', '') for v in vulns for r in v.get('references', [])[:2]]),
                    'source_url': source_url,
                    'first_seen': now_iso(),
                    'last_seen': now_iso(),
                    'kev_alerted': 0,
                }
                is_new, _ = upsert_finding(conn, finding)
                if is_new:
                    count_new += 1
                    new_findings.append(finding)
                    logger.info(f"  New ICS advisory: {advisory_id}")

                # Small delay to be polite to GitHub raw
                time.sleep(0.1)

            except Exception as e:
                logger.warning(f"CISA ICS: failed to process {path}: {e}")
                continue

        conn.commit()
        conn.close()
        logger.info(f"CISA ICS: checked {count_checked} advisories, {count_new} new Rockwell findings")
    except Exception as e:
        logger.error(f"CISA ICS failed: {e}")

    return new_findings

# ─── Source 3: NVD CVE API ────────────────────────────────────────────────────

def collect_nvd():
    logger.info("Collecting NVD CVE data...")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': 'Rockwell Automation',
        'resultsPerPage': 100,
    }
    new_findings = []
    try:
        # NVD rate limits: be gentle
        time.sleep(1)
        resp = requests.get(url, headers=HEADERS, params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        logger.info(f"NVD: {len(vulns)} entries")

        conn = get_db()
        count_new = 0
        for item in vulns:
            cve = item.get('cve', {})
            cve_id = cve.get('id', '')
            if not cve_id:
                continue

            # Description
            descs = cve.get('descriptions', [])
            desc = next((d['value'] for d in descs if d.get('lang') == 'en'), '')

            # CVSS score
            cvss_score = None
            metrics = cve.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    if cvss_score:
                        break

            severity = cvss_to_severity(cvss_score)

            # Products from CPE
            products_set = set()
            confs = cve.get('configurations', [])
            for conf in confs:
                for node in conf.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe = cpe_match.get('criteria', '')
                        # cpe:2.3:a:rockwell_automation:product:...
                        parts = cpe.split(':')
                        if len(parts) > 4:
                            products_set.add(parts[4].replace('_', ' ').title())

            products_str = ', '.join(list(products_set)[:5])

            # References
            refs = [r.get('url', '') for r in cve.get('references', [])[:5]]

            finding_id = make_id('NVD', cve_id)
            finding = {
                'id': finding_id,
                'source': 'NVD',
                'type': 'CVE',
                'title': cve_id,
                'cve': cve_id,
                'severity': severity,
                'cvss_score': cvss_score,
                'products': products_str,
                'summary': desc[:600],
                'published_date': cve.get('published', ''),
                'refs': json.dumps(refs),
                'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'first_seen': now_iso(),
                'last_seen': now_iso(),
                'kev_alerted': 0,
            }
            is_new, _ = upsert_finding(conn, finding)
            if is_new:
                count_new += 1
                new_findings.append(finding)

        conn.commit()
        conn.close()
        logger.info(f"NVD: {count_new} new findings")
    except Exception as e:
        logger.error(f"NVD failed: {e}")

    return new_findings

# ─── Source 4: Rockwell Automation Security Advisories ───────────────────────

RA_ADVISORIES_URL = "https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html"

def collect_rockwell_advisories():
    logger.info("Collecting Rockwell Automation Security Advisories...")
    import re as _re
    from datetime import timedelta
    new_findings = []
    try:
        resp = requests.get(RA_ADVISORIES_URL, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')

        tiles = soup.find_all('div', class_='content-fragment-list__tile')
        logger.info(f"Rockwell Advisories: {len(tiles)} tiles found")

        # Only ingest advisories from the last 2 years
        cutoff = datetime.now(timezone.utc) - timedelta(days=730)

        conn = get_db()
        count_new = 0

        for tile in tiles:
            try:
                advisory_id = tile.get('data-doc-id', '')
                if not advisory_id:
                    continue

                pub_date_raw = tile.get('data-pub-date', '')  # e.g. "2026-01-20 02:14:00"
                try:
                    pub_dt = datetime.strptime(pub_date_raw, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except Exception:
                    pub_dt = None

                if pub_dt and pub_dt < cutoff:
                    continue

                pub_date = pub_date_raw[:10] if pub_date_raw else ''

                # Title & link
                title_tag = tile.find('a', class_='content-fragment-list__tile-title')
                title = title_tag.get_text(strip=True) if title_tag else advisory_id
                source_url = title_tag.get('href', RA_ADVISORIES_URL) if title_tag else RA_ADVISORIES_URL

                # Severity from impact dot/label
                impact_tag = tile.find('div', class_='content-fragment-list__tile-impact')
                severity_raw = impact_tag.get_text(strip=True) if impact_tag else ''

                # Parse information items into a dict
                info = {}
                for item in tile.find_all('div', class_='content-fragment-list__tile-information-item'):
                    label_tag = item.find('div', class_='content-fragment-list__tile-information-label')
                    value_tag = item.find('div', class_='content-fragment-list__tile-information-value')
                    if label_tag and value_tag:
                        label = label_tag.get_text(strip=True).rstrip(':')
                        value = value_tag.get_text(strip=True)
                        info[label] = value

                # CVEs
                cve_str_raw = info.get('CVE IDs', '')
                cves = _re.findall(r'CVE-\d{4}-\d+', cve_str_raw)
                cve_str = ', '.join(cves)

                # Products
                products_str = info.get('Products', '')

                # CVSS score — prefer v4.0, fallback v3.1
                cvss_score = None
                for key in ['CVSS Scores (v4.0)', 'CVSS Scores (v3.1)']:
                    raw = info.get(key, '')
                    try:
                        cvss_score = float(raw)
                        break
                    except (ValueError, TypeError):
                        pass

                # Severity: use explicit label if present, else derive from CVSS
                sev_map = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
                severity = sev_map.get(severity_raw.lower(), cvss_to_severity(cvss_score))

                finding_id = make_id('ROCKWELL', advisory_id)
                finding = {
                    'id': finding_id,
                    'source': 'ROCKWELL',
                    'type': 'Advisory',
                    'title': title,
                    'cve': cve_str,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'products': products_str,
                    'summary': '',
                    'published_date': pub_date,
                    'refs': json.dumps([source_url]),
                    'source_url': source_url,
                    'first_seen': now_iso(),
                    'last_seen': now_iso(),
                    'kev_alerted': 0,
                }
                is_new, _ = upsert_finding(conn, finding)
                if is_new:
                    count_new += 1
                    new_findings.append(finding)
                    logger.info(f"  New RA advisory: {advisory_id}")

            except Exception as e:
                logger.warning(f"Rockwell Advisories: failed to parse tile: {e}")
                continue

        conn.commit()
        conn.close()
        logger.info(f"Rockwell Advisories: {count_new} new findings")
    except Exception as e:
        logger.error(f"Rockwell Advisories failed: {e}")

    return new_findings

# ─── Source 5: Security News ──────────────────────────────────────────────────

def collect_news():
    logger.info("Collecting security news...")
    url = "https://news.google.com/rss/search?q=Rockwell+Automation+vulnerability+CVE+exploit&hl=en-US&gl=US&ceid=US:en"
    new_findings = []
    try:
        feed = feedparser.parse(url)
        logger.info(f"News: {len(feed.entries)} entries")

        conn = get_db()
        count_new = 0
        for entry in feed.entries:
            title = entry.get('title', '')
            link = entry.get('link', '')
            summary = BeautifulSoup(entry.get('summary', ''), 'html.parser').get_text()[:500]

            pub_date = ''
            if hasattr(entry, 'published'):
                pub_date = entry.published

            cves = re.findall(r'CVE-\d{4}-\d+', title + ' ' + summary)
            cve_str = ', '.join(list(set(cves)))

            finding_id = make_id('NEWS', link)
            finding = {
                'id': finding_id,
                'source': 'NEWS',
                'type': 'News',
                'title': title,
                'cve': cve_str,
                'severity': 'Unknown',
                'cvss_score': None,
                'products': '',
                'summary': summary,
                'published_date': pub_date,
                'refs': json.dumps([link]),
                'source_url': link,
                'first_seen': now_iso(),
                'last_seen': now_iso(),
                'kev_alerted': 0,
            }
            is_new, _ = upsert_finding(conn, finding)
            if is_new:
                count_new += 1
                new_findings.append(finding)

        conn.commit()
        conn.close()
        logger.info(f"News: {count_new} new findings")
    except Exception as e:
        logger.error(f"News failed: {e}")

    return new_findings

# ─── Main Collect ─────────────────────────────────────────────────────────────

def collect_all():
    init_db()
    all_new = []

    kev_new = collect_cisa_kev()
    all_new.extend(kev_new)

    ics_new = collect_cisa_ics()
    all_new.extend(ics_new)

    nvd_new = collect_nvd()
    all_new.extend(nvd_new)

    ra_new = collect_rockwell_advisories()
    all_new.extend(ra_new)

    news_new = collect_news()
    all_new.extend(news_new)

    logger.info(f"Collection complete. Total new findings: {len(all_new)}")
    return all_new

def get_kev_unalerted():
    """Return KEV findings that haven't been alerted yet."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM findings WHERE source='CISA_KEV' AND kev_alerted=0"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def mark_kev_alerted(finding_id):
    conn = get_db()
    conn.execute("UPDATE findings SET kev_alerted=1 WHERE id=?", (finding_id,))
    conn.commit()
    conn.close()

def get_total_count():
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    conn.close()
    return count

if __name__ == '__main__':
    collect_all()
