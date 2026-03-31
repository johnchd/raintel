#!/usr/bin/env python3
"""
Rockwell Intelligence Hub — Entry Point
Collects data, generates site, sends Slack alerts.
"""

import subprocess
import logging
import sys
from collector import collect_all, get_kev_unalerted, mark_kev_alerted, get_total_count
from generate_site import generate_all

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('run')

def send_slack(message):
    try:
        result = subprocess.run(
            ['openclaw', 'message', 'send',
             '--channel', 'slack',
             '--target', 'C0ALC45EYKX',
             '--message', message],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            logger.info("Slack alert sent")
        else:
            logger.error(f"Slack send failed: {result.stderr}")
    except Exception as e:
        logger.error(f"Slack send exception: {e}")

def main():
    logger.info("=== Rockwell Intelligence Hub — Run Starting ===")

    # Step 1: Collect
    logger.info("Step 1: Collecting data from all sources...")
    try:
        new_findings = collect_all()
    except Exception as e:
        logger.error(f"Collection error: {e}")
        new_findings = []

    # Step 2: Send KEV alerts
    logger.info("Step 2: Checking for unalerted KEV findings...")
    try:
        unalerted = get_kev_unalerted()
        for finding in unalerted:
            cve = finding.get('cve', 'Unknown')
            severity = finding.get('severity', 'Unknown')
            products = finding.get('products', 'Unknown')
            url = finding.get('source_url', '')
            msg = (
                f":rotating_light: *Rockwell vulnerability added to CISA KEV*\n\n"
                f"*CVE:* {cve}\n"
                f"*Severity:* {severity}\n"
                f"*Products:* {products}\n"
                f"*Link:* {url}"
            )
            send_slack(msg)
            mark_kev_alerted(finding['id'])
            logger.info(f"Alerted KEV: {cve}")
    except Exception as e:
        logger.error(f"KEV alert error: {e}")

    # Step 3: Generate site
    logger.info("Step 3: Generating static site...")
    try:
        generate_all()
    except Exception as e:
        logger.error(f"Site generation error: {e}")

    total = get_total_count()
    logger.info(f"=== Run complete. Total findings in DB: {total} ===")
    return total

if __name__ == '__main__':
    total = main()
    print(f"TOTAL_FINDINGS={total}")
