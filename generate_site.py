#!/usr/bin/env python3
"""
Intelligence Hub — Static Site Generator
Generates index.html, archive.html, about.html, cve/*.html, rss.xml
"""

import sqlite3
import json
import logging
import os
import html as html_module
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('generate_site')

DB_PATH  = 'data/intel.db'
SITE_DIR = 'site'
SITE_URL = 'https://intel.johncrynick.com'

# ─── Nav ──────────────────────────────────────────────────────────────────────

NAV_HTML = '''
<nav>
  <div class="nav-container">
    <div class="nav-brand">
      <a href="{root}index.html" style="color:var(--text);text-decoration:none;display:flex;align-items:center;gap:8px">
        <img src="{root}favicon.svg" alt="" style="width:22px;height:22px;flex-shrink:0">
        Intelligence Hub
      </a>
    </div>
    <div class="nav-search">
      <input type="text" id="searchBox" placeholder="Search CVEs, products, keywords..." autocomplete="off">
      <span id="searchCount" class="search-count"></span>
    </div>
    <div class="nav-links">
      <a href="{root}index.html" class="{active_index}">Latest</a>
      <a href="{root}archive.html" class="{active_archive}">Archive</a>
      <a href="{root}about.html" class="{active_about}">About</a>
      <button id="themeToggle" class="theme-toggle" aria-label="Toggle theme"></button>
    </div>
  </div>
</nav>
'''

# ─── CSS ──────────────────────────────────────────────────────────────────────

CSS = '''
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --accent: #58a6ff;
}

[data-theme="light"] {
  --bg: #ffffff;
  --surface: #f6f8fa;
  --surface2: #eaeef2;
  --border: #d0d7de;
  --text: #1f2328;
  --text-muted: #57606a;
  --accent: #0969da;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
  font-size: 14px;
  line-height: 1.6;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Nav ── */
nav {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 100;
}

.nav-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 16px;
  display: flex;
  align-items: center;
  gap: 16px;
  height: 56px;
}

.nav-brand {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  white-space: nowrap;
}

.nav-search {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 360px;
}

.nav-search input {
  flex: 1;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  font-size: 13px;
  padding: 6px 12px;
  outline: none;
  transition: border-color 0.15s;
}

.nav-search input:focus { border-color: var(--accent); }
.nav-search input::placeholder { color: var(--text-muted); }

.search-count {
  font-size: 11px;
  color: var(--text-muted);
  white-space: nowrap;
}

.nav-links { display: flex; gap: 4px; margin-left: auto; }

.nav-links a {
  padding: 6px 14px;
  border-radius: 6px;
  color: var(--text-muted);
  font-size: 13px;
  transition: all 0.15s;
}

.nav-links a:hover { color: var(--text); background: var(--surface2); text-decoration: none; }
.nav-links a.active { color: var(--accent); background: rgba(88,166,255,0.1); }

/* ── Layout ── */
main {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px 16px;
}

.page-header {
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}

.page-header h1 { font-size: 22px; font-weight: 600; color: var(--text); }
.page-header p { color: var(--text-muted); margin-top: 4px; font-size: 13px; }

/* ── Stats ── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.stat-box {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
}

.stat-box .stat-label {
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 4px;
}

.stat-box .stat-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
}

.stat-box .stat-severity {
  display: inline-block;
  margin-top: 6px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 2px 7px;
  border-radius: 4px;
}
.stat-severity.sev-critical { background: rgba(248,81,73,0.15); color: #f85149; }
.stat-severity.sev-high     { background: rgba(210,153,34,0.15); color: #d29922; }
.stat-severity.sev-medium   { background: rgba(88,166,255,0.12); color: #58a6ff; }
.stat-severity.sev-low      { background: rgba(63,185,80,0.12);  color: #3fb950; }
.stat-severity.sev-none     { display: none; }

.source-breakdown {
  font-size: 13px;
  color: var(--text-muted);
  margin-bottom: 20px;
  padding: 12px 16px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
}

.source-breakdown span { color: var(--text); }

/* ── Filter bars ── */
.filter-section { margin-bottom: 8px; }
.filter-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}

.filter-btn {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 13px;
  padding: 5px 12px;
  transition: all 0.15s;
}

.filter-btn:hover { color: var(--text); border-color: var(--accent); }
.filter-btn.active { background: rgba(88,166,255,0.1); border-color: var(--accent); color: var(--accent); }

/* ── Cards ── */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
  transition: border-color 0.15s;
}

.finding-card:hover { border-color: var(--accent); }

.card-header {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}

.card-title {
  flex: 1;
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.card-title a { color: var(--text); }
.card-title a:hover { color: var(--accent); }

.source-tag {
  flex-shrink: 0;
  font-size: 11px;
  color: var(--text-muted);
  background: var(--surface2);
  border: 1px solid var(--border);
  padding: 2px 8px;
  border-radius: 4px;
}

.new-badge {
  flex-shrink: 0;
  background: rgba(88,166,255,0.2);
  border: 1px solid rgba(88,166,255,0.5);
  color: var(--accent);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.5px;
  padding: 2px 6px;
  border-radius: 4px;
  text-transform: uppercase;
}

.card-body { padding: 12px 16px; }

.card-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 8px;
  font-size: 12px;
  color: var(--text-muted);
}

.card-summary { font-size: 13px; color: var(--text-muted); line-height: 1.5; margin-bottom: 8px; }

.card-footer {
  padding: 8px 16px;
  border-top: 1px solid var(--border);
  font-size: 12px;
  display: flex;
  gap: 12px;
}

.cve-pill {
  display: inline-block;
  background: rgba(88,166,255,0.1);
  border: 1px solid rgba(88,166,255,0.3);
  color: var(--accent);
  padding: 1px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-family: monospace;
  margin: 2px;
}

/* ── Sticky filter bar ── */
.sticky-filters {
  position: sticky;
  top: 56px;
  z-index: 99;
  background: var(--bg);
  padding: 10px 0;
  margin-bottom: 4px;
  border-bottom: 1px solid var(--border);
}

/* ── Archive grouping ── */
.month-group { margin-bottom: 24px; }
.month-group.collapsed .month-cards { display: none; }

.month-heading {
  font-size: 15px;
  font-weight: 600;
  color: var(--accent);
  margin-bottom: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  user-select: none;
}
.month-heading:hover { color: var(--text); }
.month-chevron { font-size: 11px; color: var(--text-muted); margin-left: auto; transition: transform 0.2s; }
.month-group.collapsed .month-chevron { transform: rotate(-90deg); }

.year-heading {
  font-size: 18px;
  font-weight: 700;
  color: var(--text);
  margin: 24px 0 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.year-heading::before { content: "▸"; color: var(--accent); }

/* ── Detail page ── */
.detail-section { margin-bottom: 20px; }
.detail-section h3 { font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.detail-section p { font-size: 14px; color: var(--text); line-height: 1.6; }
.detail-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.ref-link { display: block; font-size: 13px; margin-bottom: 4px; word-break: break-all; }

/* ── Empty state ── */
.empty-state {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 48px 24px;
  text-align: center;
  color: var(--text-muted);
}

.empty-state h3 { color: var(--text); margin-bottom: 8px; }

/* ── Sources ── */
.sources-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.source-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
}

.source-card h3 { font-size: 15px; color: var(--text); margin-bottom: 8px; }
.source-card p { font-size: 13px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.5; }

/* ── Footer ── */
footer {
  border-top: 1px solid var(--border);
  padding: 20px 16px;
  text-align: center;
  color: var(--text-muted);
  font-size: 12px;
  margin-top: 40px;
}

/* ── Responsive ── */
@media (max-width: 768px) {
  .nav-container { flex-wrap: wrap; height: auto; padding: 10px 16px; gap: 10px; }
  .nav-search { max-width: 100%; order: 3; width: 100%; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 480px) {
  .nav-links a { padding: 4px 10px; }
  .card-header { flex-wrap: wrap; }
}

/* ── Severity badges ── */
.severity-badge {
  flex-shrink: 0;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.5px;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid;
  text-transform: uppercase;
}
.sev-critical { background: rgba(248,81,73,0.15);  border-color: rgba(248,81,73,0.5);  color: #f85149; }
.sev-high     { background: rgba(210,153,34,0.15); border-color: rgba(210,153,34,0.5); color: #d29922; }
.sev-medium   { background: rgba(88,166,255,0.15); border-color: rgba(88,166,255,0.5); color: #58a6ff; }
.sev-low      { background: rgba(63,185,80,0.15);  border-color: rgba(63,185,80,0.5);  color: #3fb950; }
.sev-unknown  { background: rgba(139,148,158,0.15);border-color: rgba(139,148,158,0.5);color: #8b949e; }
[data-theme="light"] .sev-critical { color: #cf222e; }
[data-theme="light"] .sev-high     { color: #9a6700; }
[data-theme="light"] .sev-medium   { color: #0550ae; }
[data-theme="light"] .sev-low      { color: #1a7f37; }

.theme-toggle {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-muted);
  cursor: pointer;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: all 0.15s;
}
.theme-toggle:hover { color: var(--text); border-color: var(--accent); }

/* ── Detail panel ── */
.detail-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.45);
  z-index: 200;
}
.detail-overlay.open { display: block; }
.detail-panel {
  position: fixed;
  top: 0;
  right: 0;
  width: 520px;
  max-width: 92vw;
  height: 100vh;
  background: var(--bg);
  border-left: 1px solid var(--border);
  z-index: 201;
  transform: translateX(100%);
  transition: transform 0.25s ease;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.detail-panel.open { transform: translateX(0); }
.detail-panel-header {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  flex-shrink: 0;
}
.detail-panel-close {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 18px;
  line-height: 1;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s;
}
.detail-panel-close:hover { color: var(--text); border-color: var(--accent); }
.detail-panel-body { padding: 24px; overflow-y: auto; flex: 1; }
.detail-panel-body .page-header { margin-bottom: 16px; }
.detail-panel-body .page-header p { display: none; }

/* ── About page ── */
.about-hero { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 32px; margin-bottom: 24px; }
.about-hero h2 { font-size: 20px; color: var(--text); margin-bottom: 8px; }
.about-hero p  { color: var(--text-muted); font-size: 14px; line-height: 1.7; max-width: 680px; }
.about-section { margin-bottom: 28px; }
.about-section h2 { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
.about-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 12px; }
.about-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.about-card h3 { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 6px; }
.about-card p  { font-size: 12px; color: var(--text-muted); line-height: 1.5; }
.about-card .tag { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; border: 1px solid var(--border); color: var(--text-muted); margin-top: 8px; }
.sev-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.sev-table th { text-align: left; padding: 8px 12px; color: var(--text-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
.sev-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); color: var(--text); }
.sev-table tr:last-child td { border-bottom: none; }
.about-callout { background: rgba(88,166,255,0.07); border: 1px solid rgba(88,166,255,0.25); border-radius: 8px; padding: 16px 20px; font-size: 13px; color: var(--text-muted); line-height: 1.6; }
.about-callout strong { color: var(--text); }
'''

# ─── Search JS (shared) ────────────────────────────────────────────────────────

DETAIL_PANEL = '''
<div id="detailOverlay" class="detail-overlay"></div>
<div id="detailPanel" class="detail-panel">
  <div class="detail-panel-header">
    <button class="detail-panel-close" id="detailClose" aria-label="Close">&times;</button>
  </div>
  <div class="detail-panel-body" id="detailPanelBody"></div>
</div>
<script>
(function() {
  var panel   = document.getElementById('detailPanel');
  var overlay = document.getElementById('detailOverlay');
  var body    = document.getElementById('detailPanelBody');
  var closeBtn= document.getElementById('detailClose');
  if (!panel) return;

  function openPanel(url) {
    body.innerHTML = '<p style="color:var(--text-muted);padding:8px 0">Loading\u2026</p>';
    panel.classList.add('open');
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    fetch(url)
      .then(function(r) { return r.text(); })
      .then(function(html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var main = doc.querySelector('main');
        if (main) { body.innerHTML = main.innerHTML; }
        else { body.innerHTML = '<p style="color:var(--text-muted)">Could not load content.</p>'; }
      })
      .catch(function() {
        body.innerHTML = '<p style="color:var(--text-muted)">Failed to load.</p>';
      });
  }

  function closePanel() {
    panel.classList.remove('open');
    overlay.classList.remove('open');
    document.body.style.overflow = '';
  }

  closeBtn.addEventListener('click', closePanel);
  overlay.addEventListener('click', closePanel);
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closePanel(); });

  document.addEventListener('click', function(e) {
    var link = e.target.closest('a');
    if (!link) return;
    if (link.textContent.trim() === 'Details' && link.getAttribute('href') && link.getAttribute('href').indexOf('cve/') !== -1) {
      e.preventDefault();
      openPanel(link.href);
    }
  });
})();
</script>
'''

THEME_HEAD_JS = '<script>(function(){document.documentElement.setAttribute("data-theme",localStorage.getItem("theme")||"dark");})()</script>'

THEME_TOGGLE_JS = '''
<script>
(function() {
  var btn = document.getElementById('themeToggle');
  if (!btn) return;
  var SUN  = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  var MOON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  function apply(t) {
    document.documentElement.setAttribute('data-theme', t);
    localStorage.setItem('theme', t);
    btn.innerHTML = t === 'dark' ? SUN : MOON;
    btn.title = t === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  }
  apply(document.documentElement.getAttribute('data-theme') || 'dark');
  btn.addEventListener('click', function() {
    apply(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });
})();
</script>
'''

SEARCH_JS = '''
<script>
(function() {
  var box = document.getElementById('searchBox');
  if (!box) return;
  var countEl = document.getElementById('searchCount');
  box.addEventListener('input', function() {
    var q = box.value.toLowerCase().trim();
    var cards = document.querySelectorAll('.finding-card');
    var shown = 0;
    cards.forEach(function(c) {
      var txt = c.textContent.toLowerCase();
      var match = !q || txt.indexOf(q) !== -1;
      if (c.style.display !== 'none' || match) {
        c._searchHide = !match;
        c.style.display = (c._filterHide || !match) ? 'none' : '';
      }
      if (!c._filterHide && match) shown++;
    });
    // hide empty month groups
    document.querySelectorAll('.month-group').forEach(function(g) {
      var vis = Array.from(g.querySelectorAll('.finding-card')).some(function(c) { return c.style.display !== 'none'; });
      g.style.display = vis ? '' : 'none';
    });
    document.querySelectorAll('.year-heading').forEach(function(y) {
      var next = y.nextElementSibling;
      var has = false;
      while (next && !next.classList.contains('year-heading')) {
        if (next.classList.contains('month-group') && next.style.display !== 'none') has = true;
        next = next.nextElementSibling;
      }
      y.style.display = has ? '' : 'none';
    });
    if (countEl) countEl.textContent = q ? shown + ' result' + (shown !== 1 ? 's' : '') : '';
  });
})();
</script>
'''

# ─── New-badge JS ─────────────────────────────────────────────────────────────

NEW_BADGE_JS = '''
<script>
(function() {
  var lastVisit = localStorage.getItem('rockwellLastVisit');
  var now = Date.now();
  document.querySelectorAll('.finding-card[data-published]').forEach(function(card) {
    var pub = parseInt(card.getAttribute('data-published'), 10);
    if (lastVisit && pub > parseInt(lastVisit, 10)) {
      var badge = document.createElement('span');
      badge.className = 'new-badge';
      badge.textContent = 'NEW';
      card.querySelector('.card-header').prepend(badge);
    }
  });
  localStorage.setItem('rockwellLastVisit', now);
})();
</script>
'''

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def parse_date(date_str):
    """Parse ISO8601 or RFC2822 date string → timezone-aware datetime."""
    if not date_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    for fmt in [
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d',
        '%a, %d %b %Y %H:%M:%S %z',
        '%a, %d %b %Y %H:%M:%S %Z',
    ]:
        try:
            dt = datetime.strptime(date_str[:50], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    return datetime.min.replace(tzinfo=timezone.utc)

def fmt_date(date_str):
    """Return M-D-YYYY or 'Unknown'."""
    dt = parse_date(date_str)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return 'Unknown'
    return f'{dt.month}-{dt.day}-{dt.year}'

def html_page(title, nav_html, content, active_page, root='', extra_js=''):
    active_map = {p: '' for p in ['index', 'archive', 'about']}
    active_map[active_page] = 'active'
    nav = nav_html.format(
        active_index=active_map['index'],
        active_archive=active_map['archive'],
        active_about=active_map['about'],
        root=root,
    )
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Intelligence Hub</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg">
<style>{CSS}</style>
{THEME_HEAD_JS}
</head>
<body>
{nav}
<main>
{content}
</main>
<footer>
  Last updated: {ts} &nbsp;|&nbsp; <a href="{root}rss.xml">RSS Feed</a>
</footer>
{SEARCH_JS}
{extra_js}
{DETAIL_PANEL}
{THEME_TOGGLE_JS}
</body>
</html>'''

def render_finding_card(row, data_source=False, link_to_detail=True):
    title = row['title'] or 'Untitled'
    source_url = row['source_url'] or '#'
    detail_url = f'cve/{row["id"]}.html'

    title_link = f'<a href="{source_url}" target="_blank" rel="noopener">{html_module.escape(title)}</a>'

    # CVE pills
    cve_html = ''
    if row['cve']:
        for c in row['cve'].split(','):
            c = c.strip()
            if c:
                cve_html += f'<span class="cve-pill">{html_module.escape(c)}</span> '

    pub = fmt_date(row.get('published_date', ''))
    products = row.get('products', '') or ''
    summary = row.get('summary', '') or ''

    # data attributes
    pub_dt = parse_date(row.get('published_date', ''))
    pub_ms = int(pub_dt.timestamp() * 1000)
    extra_attrs = ''
    sev = (row.get('severity') or 'Unknown')
    if data_source:
        extra_attrs += f' data-source="{html_module.escape(row["source"])}"'
        prod_list = ','.join(p.strip() for p in products.split(',') if p.strip())
        extra_attrs += f' data-products="{html_module.escape(prod_list)}"'
        extra_attrs += f' data-severity="{html_module.escape(sev)}"'
    extra_attrs += f' data-published="{pub_ms}"'

    SOURCE_LABELS = {'CISA_KEV':'CISA KEV','CISA_ICS':'CISA ICS','NVD':'NVD','ROCKWELL':'RA Advisories','NEWS':'News'}
    source_label = SOURCE_LABELS.get(row.get('source', ''), row.get('source', ''))

    sev_cls = f'sev-{sev.lower()}'
    sev_label = 'News' if sev == 'Unknown' else sev
    # Only show badge when severity is meaningful; NEWS source already shown via source tag
    show_badge = data_source and sev != 'Unknown'
    sev_badge = f'<span class="severity-badge {sev_cls}">{html_module.escape(sev_label)}</span>' if show_badge else ''

    meta_parts = [f'<span>{pub}</span>']
    if products:
        meta_parts.append(f'<span>{html_module.escape(products[:100])}</span>')

    footer_html = ''
    if link_to_detail:
        footer_html = f'''
  <div class="card-footer">
    <a href="{detail_url}">Details</a>
    <a href="{html_module.escape(source_url)}" target="_blank" rel="noopener">Source</a>
  </div>'''

    return f'''
<div class="finding-card"{extra_attrs}>
  <div class="card-header">
    <div class="card-title">{title_link}</div>
    {sev_badge}
    <span class="source-tag">{html_module.escape(source_label)}</span>
  </div>
  <div class="card-body">
    <div class="card-meta">{''.join(meta_parts)}</div>
    {f'<div style="margin-bottom:8px">{cve_html}</div>' if cve_html else ''}
    <div class="card-summary">{html_module.escape(summary[:400])}</div>
  </div>{footer_html}
</div>'''

# ─── Page 1: index.html ───────────────────────────────────────────────────────

def generate_index():
    conn = get_db()
    all_rows = [dict(r) for r in conn.execute('SELECT * FROM findings').fetchall()]
    conn.close()

    now = datetime.now(timezone.utc)

    def count_since(days=None, hours=None):
        delta = timedelta(days=days) if days else timedelta(hours=hours)
        cutoff = now - delta
        return sum(1 for r in all_rows if parse_date(r.get('published_date', '')) >= cutoff)

    SEV_ORDER = ['critical', 'high', 'medium', 'low']

    def rows_since(days=None, hours=None):
        delta = timedelta(days=days) if days else timedelta(hours=hours)
        cutoff = now - delta
        return [r for r in all_rows if parse_date(r.get('published_date', '')) >= cutoff]

    def top_severity(rows):
        sevs = {(r.get('severity') or '').lower() for r in rows}
        for s in SEV_ORDER:
            if s in sevs:
                return s
        return None

    def sev_badge(sev):
        if not sev:
            return '<span class="stat-severity sev-none"></span>'
        return f'<span class="stat-severity sev-{sev}">{sev}</span>'

    total  = len(all_rows)
    rows72h = rows_since(hours=72)
    rows7d  = rows_since(days=7)
    rows30d = rows_since(days=30)
    c72h = len(rows72h)
    c7d  = len(rows7d)
    c30d = len(rows30d)

    sev72h = top_severity(rows72h)
    sev7d  = top_severity(rows7d)
    sev30d = top_severity(rows30d)

    # Source breakdown last 30d
    cutoff30 = now - timedelta(days=30)
    src_counts = Counter(
        r['source'] for r in all_rows
        if parse_date(r.get('published_date', '')) >= cutoff30
    )
    breakdown = ' &nbsp;|&nbsp; '.join(
        f'{lbl}: <span>{src_counts.get(src, 0)}</span>'
        for src, lbl in [('CISA_KEV','CISA KEV'),('CISA_ICS','CISA ICS'),('NVD','NVD'),('ROCKWELL','RA Advisories'),('NEWS','News')]
    )

    card72h = '' if c72h == 0 else f'''
  <div class="stat-box">
    <div class="stat-label">Last 72h</div>
    <div class="stat-value">{c72h}</div>
    {sev_badge(sev72h)}
  </div>'''

    stats_html = f'''
<div class="stats-grid">
  {card72h}
  <div class="stat-box">
    <div class="stat-label">Last 7 days</div>
    <div class="stat-value">{c7d}</div>
    {sev_badge(sev7d)}
  </div>
  <div class="stat-box">
    <div class="stat-label">Last 30 days</div>
    <div class="stat-value">{c30d}</div>
    {sev_badge(sev30d)}
  </div>
</div>
<div class="source-breakdown"><strong style="color:var(--text)">Last 30 days by source</strong> &nbsp;&nbsp; {breakdown}</div>'''

    rows72h.sort(key=lambda r: parse_date(r.get('published_date', '')), reverse=True)
    rows30d.sort(key=lambda r: parse_date(r.get('published_date', '')), reverse=True)

    if not rows72h:
        if rows30d:
            display_rows = rows30d
            fallback_note = '<p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">No new intelligence in the last 72 hours — showing last 30 days.</p>'
        else:
            display_rows = []
            fallback_note = ''
    else:
        display_rows = rows72h
        fallback_note = ''

    if display_rows:
        sources_present = sorted(set(r['source'] for r in display_rows))
        src_btns = '<button class="filter-btn active" data-filter="all">All</button>'
        for src in sources_present:
            lbl = {'CISA_KEV':'CISA KEV','CISA_ICS':'CISA ICS','NVD':'NVD','ROCKWELL':'RA Advisories','NEWS':'News'}.get(src, src)
            src_btns += f'<button class="filter-btn" data-filter="{src}">{lbl}</button>'
        showing_count = len(display_rows)
        filter_bar = f'<p style="margin-bottom:8px"><span id="latestCount">{showing_count}</span> findings</p><div class="filter-bar" id="latestFilter">{src_btns}</div>'
        cards_html = ''.join(render_finding_card(r, data_source=True) for r in display_rows)
        body = fallback_note + filter_bar + cards_html
    else:
        body = '''
<div class="empty-state">
  <h3>No new intelligence in the last 72 hours.</h3>
  <p>Check back later or view the <a href="archive.html">full archive</a>.</p>
</div>'''

    INDEX_FILTER_JS = '''
<script>
(function() {
  document.querySelectorAll('#latestFilter .filter-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#latestFilter .filter-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      var active = btn.getAttribute('data-filter');
      var cards = document.querySelectorAll('.finding-card[data-source]');
      cards.forEach(function(c) {
        c.style.display = (active === 'all' || c.getAttribute('data-source') === active) ? '' : 'none';
      });
      var visible = Array.from(cards).filter(function(c) { return c.style.display !== 'none'; }).length;
      var countEl = document.getElementById('latestCount');
      if (countEl) countEl.textContent = visible;
    });
  });
})();
</script>
'''

    content = f'''
<div class="page-header">
  <h1>Latest</h1>
  <p>Rockwell Automation vulnerability intelligence</p>
</div>
{stats_html}
{body}'''

    page = html_page('Latest', NAV_HTML, content, 'index', extra_js=NEW_BADGE_JS + INDEX_FILTER_JS)
    with open(f'{SITE_DIR}/index.html', 'w') as f:
        f.write(page)
    logger.info(f"Generated index.html ({c72h} findings in 72h, {total} total)")

# ─── Page 2: archive.html ─────────────────────────────────────────────────────

ARCHIVE_FILTER_JS = '''
<script>
(function() {
  function applyFilters() {
    var activeSrc = (document.querySelector('#sourceFilter .filter-btn.active') || {}).getAttribute('data-filter') || 'all';
    var activeSev = (document.querySelector('#severityFilter .filter-btn.active') || {}).getAttribute('data-sev') || 'all';
    var cards = document.querySelectorAll('.finding-card[data-source]');
    cards.forEach(function(c) {
      var srcMatch = activeSrc === 'all' || c.getAttribute('data-source') === activeSrc;
      var cardSev  = (c.getAttribute('data-severity') || 'Unknown');
      var sevMatch = activeSev === 'all' || cardSev.toLowerCase() === activeSev.toLowerCase();
      c._filterHide = !(srcMatch && sevMatch);
      c.style.display = c._filterHide ? 'none' : '';
    });
    document.querySelectorAll('.month-group').forEach(function(g) {
      var groupCards = Array.from(g.querySelectorAll('.finding-card'));
      var visCount = groupCards.filter(function(c) { return !c._filterHide; }).length;
      g.style.display = visCount > 0 ? '' : 'none';
      var countEl = g.querySelector('.month-count');
      if (countEl) countEl.textContent = '(' + visCount + ' findings)';
    });
    document.querySelectorAll('.year-heading').forEach(function(y) {
      var next = y.nextElementSibling; var has = false;
      while (next && !next.classList.contains('year-heading')) {
        if (next.classList.contains('month-group') && next.style.display !== 'none') has = true;
        next = next.nextElementSibling;
      }
      y.style.display = has ? '' : 'none';
    });
    var visible = Array.from(cards).filter(function(c) { return !c._filterHide; }).length;
    var countEl = document.getElementById('archiveCount');
    if (countEl) countEl.textContent = visible;
  }

  document.querySelectorAll('#sourceFilter .filter-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#sourceFilter .filter-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      applyFilters();
    });
  });

  document.querySelectorAll('#severityFilter .filter-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#severityFilter .filter-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      applyFilters();
    });
  });

  // Collapsible month groups
  document.querySelectorAll('.month-heading').forEach(function(h) {
    h.addEventListener('click', function() {
      h.closest('.month-group').classList.toggle('collapsed');
    });
  });
})();
</script>
'''

def generate_archive():
    conn = get_db()
    all_rows = [dict(r) for r in conn.execute('SELECT * FROM findings').fetchall()]
    conn.close()

    cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = [r for r in all_rows if parse_date(r.get('published_date', '') or r.get('first_seen', '')) >= cutoff]

    # Group by year → month
    grouped = defaultdict(lambda: defaultdict(list))
    for r in rows:
        dt = parse_date(r.get('published_date', '') or r.get('first_seen', ''))
        grouped[dt.strftime('%Y')][dt.strftime('%B %Y')].append(r)

    total = len(rows)

    # Source filter buttons
    sources_present = sorted(set(r['source'] for r in rows))
    src_btns = '<button class="filter-btn active" data-filter="all">All</button>'
    for src in sources_present:
        lbl = {'CISA_KEV':'CISA KEV','CISA_ICS':'CISA ICS','NVD':'NVD','ROCKWELL':'RA Advisories','NEWS':'News'}.get(src, src)
        src_btns += f'<button class="filter-btn" data-filter="{src}">{lbl}</button>'

    # Severity filter buttons
    sevs_present = sorted(set((r.get('severity') or 'Unknown') for r in rows if r.get('source') != 'NEWS'),
                          key=lambda s: ['Critical','High','Medium','Low','Unknown'].index(s) if s in ['Critical','High','Medium','Low','Unknown'] else 99)
    sev_btns = '<button class="filter-btn active" data-sev="all">All</button>'
    for sev in sevs_present:
        if sev != 'Unknown':
            sev_btns += f'<button class="filter-btn" data-sev="{sev}">{sev}</button>'

    if not rows:
        body = '<div class="empty-state"><h3>No archived findings yet.</h3></div>'
        filters_html = ''
    else:
        body = ''
        is_first_month = True
        for year in sorted(grouped.keys(), reverse=True):
            body += f'<div class="year-heading">{year}</div>'
            for month in sorted(grouped[year].keys(), key=lambda m: datetime.strptime(m, '%B %Y'), reverse=True):
                month_rows = sorted(grouped[year][month], key=lambda r: parse_date(r.get('published_date', '') or r.get('first_seen', '')), reverse=True)
                cards_html = ''.join(render_finding_card(r, data_source=True) for r in month_rows)
                collapsed_cls = '' if is_first_month else ' collapsed'
                is_first_month = False
                body += f'''
<div class="month-group{collapsed_cls}">
  <div class="month-heading">{month} <span class="month-count" style="color:var(--text-muted);font-weight:400;font-size:13px">({len(month_rows)} findings)</span><span class="month-chevron">▼</span></div>
  <div class="month-cards">{cards_html}</div>
</div>'''

    filters_html = f'''
<div class="sticky-filters">
  <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
    <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;width:60px">Source</span>
    <div class="filter-bar" id="sourceFilter" style="margin-bottom:0">{src_btns}</div>
  </div>
  <div style="display:flex;align-items:center;gap:6px">
    <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;width:60px">Severity</span>
    <div class="filter-bar" id="severityFilter" style="margin-bottom:0">{sev_btns}</div>
  </div>
</div>'''

    content = f'''
<div class="page-header">
  <h1>Archive</h1>
  <p>All findings from 2025 onward</p>
</div>
<div style="margin-bottom:8px">
  <span style="font-size:13px;color:var(--text-muted)">Showing </span>
  <span id="archiveCount" style="font-size:13px;color:var(--text);font-weight:600">{total}</span>
  <span style="font-size:13px;color:var(--text-muted)"> findings</span>
</div>
{filters_html}
{body}'''

    extra_js = ARCHIVE_FILTER_JS + NEW_BADGE_JS
    page = html_page('Archive', NAV_HTML, content, 'archive', extra_js=extra_js)
    with open(f'{SITE_DIR}/archive.html', 'w') as f:
        f.write(page)
    logger.info(f"Generated archive.html ({total} findings)")

# ─── Page 3: archive.html (continued) ────────────────────────────────────────

# ─── CVE Detail Pages ─────────────────────────────────────────────────────────

def generate_detail_pages():
    os.makedirs(f'{SITE_DIR}/cve', exist_ok=True)
    conn = get_db()
    all_rows = [dict(r) for r in conn.execute('SELECT * FROM findings').fetchall()]
    conn.close()
    # Only generate detail pages for findings from 2025 onward
    cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = [r for r in all_rows if parse_date(r.get('published_date', '') or r.get('first_seen', '')) >= cutoff]

    count = 0
    for row in rows:
        title = row['title'] or 'Untitled'
        pub = fmt_date(row.get('published_date', ''))
        summary = row.get('summary', '') or ''
        products = row.get('products', '') or ''
        source_url = row.get('source_url', '') or '#'
        cve_ids = [c.strip() for c in (row.get('cve', '') or '').split(',') if c.strip()]

        # References
        refs = []
        try:
            refs = json.loads(row.get('refs', '[]') or '[]')
        except Exception:
            pass
        if source_url and source_url not in refs:
            refs = [source_url] + refs

        cve_html = ''.join(f'<span class="cve-pill">{html_module.escape(c)}</span> ' for c in cve_ids)
        refs_html = ''.join(
            f'<a class="ref-link" href="{html_module.escape(r)}" target="_blank" rel="noopener">{html_module.escape(r)}</a>'
            for r in refs if r
        )

        content = f'''
<div class="page-header">
  <h1>{html_module.escape(title)}</h1>
  <p><a href="../archive.html">Back to Archive</a></p>
</div>
<div class="detail-box">
  <div class="detail-section">
    <h3>Source</h3>
    <p>{html_module.escape(row["source"])}</p>
  </div>
  <div class="detail-section">
    <h3>Published</h3>
    <p>{pub}</p>
  </div>
  {f'<div class="detail-section"><h3>CVE IDs</h3><p>{cve_html}</p></div>' if cve_ids else ''}
  {f'<div class="detail-section"><h3>Affected Products</h3><p>{html_module.escape(products)}</p></div>' if products else ''}
  <div class="detail-section">
    <h3>Summary</h3>
    <p>{html_module.escape(summary)}</p>
  </div>
  {f'<div class="detail-section"><h3>References</h3>{refs_html}</div>' if refs_html else ''}
</div>'''

        # Nav for detail pages uses ../ prefix
        nav = NAV_HTML.format(
            active_index='', active_archive='', active_about='', root='../'
        )
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        page = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html_module.escape(title)} — Intelligence Hub</title>
<link rel="icon" type="image/svg+xml" href="favicon.svg">
<style>{CSS}</style>
{THEME_HEAD_JS}
</head>
<body>
{nav}
<main>{content}</main>
<footer>
  Last updated: {ts} &nbsp;|&nbsp; <a href="../rss.xml">RSS Feed</a>
</footer>
{SEARCH_JS}
{THEME_TOGGLE_JS}
</body>
</html>'''

        out_path = f'{SITE_DIR}/cve/{row["id"]}.html'
        with open(out_path, 'w') as f:
            f.write(page)
        count += 1

    logger.info(f"Generated {count} CVE detail pages")
    return count

# ─── Page 4: about.html ───────────────────────────────────────────────────────

def generate_about():
    content = '''
<div class="page-header">
  <h1>About</h1>
  <p>How this hub works and what it tracks</p>
</div>

<div class="about-section">
  <h2>What It Monitors</h2>
  <div class="about-grid">
    <div class="about-card">
      <h3>CISA Known Exploited Vulnerabilities</h3>
      <p>CISA&rsquo;s authoritative catalog of vulnerabilities confirmed to be exploited in the wild, filtered to Rockwell Automation entries. Every new KEV addition triggers an immediate Slack alert.</p>
      <span class="tag">JSON Feed &nbsp;&middot;&nbsp; Daily</span><br>
      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener" style="font-size:12px;margin-top:8px;display:inline-block">View Source &rarr;</a>
    </div>
    <div class="about-card">
      <h3>CISA ICS Advisories</h3>
      <p>Industrial Control System security advisories published by CISA, collected via CSAF JSON files on GitHub. Covers the last 24 months of advisories mentioning Rockwell Automation.</p>
      <span class="tag">CSAF / GitHub &nbsp;&middot;&nbsp; As published</span><br>
      <a href="https://www.cisa.gov/news-events/ics-advisories" target="_blank" rel="noopener" style="font-size:12px;margin-top:8px;display:inline-block">View Source &rarr;</a>
    </div>
    <div class="about-card">
      <h3>NVD CVE Database</h3>
      <p>The National Vulnerability Database CVE API, searched for &ldquo;Rockwell Automation&rdquo;. Includes CVSS scores, affected products from CPE data, and reference links.</p>
      <span class="tag">REST API &nbsp;&middot;&nbsp; Every 6 hours</span><br>
      <a href="https://nvd.nist.gov/" target="_blank" rel="noopener" style="font-size:12px;margin-top:8px;display:inline-block">View Source &rarr;</a>
    </div>
    <div class="about-card">
      <h3>Rockwell Automation Advisories</h3>
      <p>Security advisories published directly by Rockwell Automation on their Trust Center. Covers advisories from the last 24 months, including CVSS scores, affected products, CVE IDs, and KEV status.</p>
      <span class="tag">HTML Scrape &nbsp;&middot;&nbsp; Every 6 hours</span><br>
      <a href="https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html" target="_blank" rel="noopener" style="font-size:12px;margin-top:8px;display:inline-block">View Source &rarr;</a>
    </div>
    <div class="about-card">
      <h3>Security News</h3>
      <p>Recent news articles about Rockwell Automation vulnerabilities, CVEs, and exploits via Google News RSS. CVE IDs are extracted automatically from headlines and summaries.</p>
      <span class="tag">RSS Feed &nbsp;&middot;&nbsp; Continuous</span><br>
      <a href="https://news.google.com/rss/search?q=Rockwell+Automation+vulnerability+CVE+exploit" target="_blank" rel="noopener" style="font-size:12px;margin-top:8px;display:inline-block">View Source &rarr;</a>
    </div>
  </div>
</div>

<div class="about-section">
  <h2>Severity Levels</h2>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden">
    <table class="sev-table">
      <thead>
        <tr>
          <th>Level</th>
          <th>CVSS Range</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><span class="severity-badge sev-critical">Critical</span></td>
          <td style="color:var(--text-muted)">9.0 &ndash; 10.0</td>
          <td>Maximum impact or confirmed exploited in the wild (all KEV entries are Critical)</td>
        </tr>
        <tr>
          <td><span class="severity-badge sev-high">High</span></td>
          <td style="color:var(--text-muted)">7.0 &ndash; 8.9</td>
          <td>Significant risk — network-exploitable, low complexity, or high impact</td>
        </tr>
        <tr>
          <td><span class="severity-badge sev-medium">Medium</span></td>
          <td style="color:var(--text-muted)">4.0 &ndash; 6.9</td>
          <td>Moderate risk — may require authentication, adjacent access, or user interaction</td>
        </tr>
        <tr>
          <td><span class="severity-badge sev-low">Low</span></td>
          <td style="color:var(--text-muted)">0.1 &ndash; 3.9</td>
          <td>Limited impact — typically requires local access or significant preconditions</td>
        </tr>
        <tr>
          <td><span class="severity-badge sev-unknown">News</span></td>
          <td style="color:var(--text-muted)">N/A</td>
          <td>No CVSS data available — typical for news articles and some early advisories</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<div class="about-section">
  <h2>Data &amp; Freshness</h2>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;font-size:13px;color:var(--text-muted);line-height:1.7">
    <p style="margin-bottom:8px">
      <strong style="color:var(--text)">Collection schedule:</strong>
      Every 6 hours via cron. The full pipeline runs <code style="background:var(--surface2);padding:1px 5px;border-radius:3px;font-size:12px">collector.py → generate_site.py</code>,
      fetching from all four sources, deduplicating against the local SQLite database, and rebuilding the entire static site.
    </p>
    <p style="margin-bottom:8px">
      <strong style="color:var(--text)">Storage:</strong>
      All findings are stored in a local SQLite database. The site itself is fully static HTML — no server-side logic at request time.
    </p>
    <p>
      <strong style="color:var(--text)">Pages:</strong>
      <strong style="color:var(--text)">Latest</strong> shows the most recent findings (72h, falling back to 30 days if quiet).
      <strong style="color:var(--text)">Feed</strong> shows all findings with full filtering.
      <strong style="color:var(--text)">Archive</strong> shows all findings from 2025 onward, grouped by month.
      An <strong style="color:var(--text)">RSS feed</strong> is available at <a href="rss.xml">rss.xml</a>.
    </p>
  </div>
</div>
'''

    page = html_page('About', NAV_HTML, content, 'about')
    with open(f'{SITE_DIR}/about.html', 'w') as f:
        f.write(page)
    logger.info("Generated about.html")


# ─── RSS Feed ─────────────────────────────────────────────────────────────────

def generate_rss():
    conn = get_db()
    rows = [dict(r) for r in conn.execute('SELECT * FROM findings').fetchall()]
    conn.close()

    rows.sort(key=lambda r: parse_date(r.get('published_date', '')), reverse=True)
    rows = rows[:50]

    def rss_date(date_str):
        dt = parse_date(date_str)
        if dt == datetime.min.replace(tzinfo=timezone.utc):
            return datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
        return dt.strftime('%a, %d %b %Y %H:%M:%S +0000')

    items = ''
    for r in rows:
        title = html_module.escape(r['title'] or 'Untitled')
        link = f'{SITE_URL}/cve/{r["id"]}.html'
        desc = html_module.escape((r.get('summary', '') or '')[:500])
        pub_date = rss_date(r.get('published_date', ''))
        cat = html_module.escape(r['source'])
        items += f'''  <item>
    <title>{title}</title>
    <link>{link}</link>
    <description>{desc}</description>
    <pubDate>{pub_date}</pubDate>
    <category>{cat}</category>
    <guid isPermaLink="true">{link}</guid>
  </item>
'''

    now_rfc = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
    rss = f'''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Rockwell Automation Vulnerability Intelligence</title>
    <link>{SITE_URL}</link>
    <description>Latest Rockwell Automation vulnerability intelligence from CISA, NVD, and security news</description>
    <language>en-us</language>
    <lastBuildDate>{now_rfc}</lastBuildDate>
{items}  </channel>
</rss>'''

    with open(f'{SITE_DIR}/rss.xml', 'w') as f:
        f.write(rss)
    logger.info(f"Generated rss.xml ({len(rows)} items)")

# ─── Main ─────────────────────────────────────────────────────────────────────

def generate_all():
    os.makedirs(f'{SITE_DIR}/cve', exist_ok=True)
    generate_index()
    generate_archive()
    generate_about()
    detail_count = generate_detail_pages()
    generate_rss()
    logger.info(f"Site generation complete — {detail_count} detail pages, rss.xml")

if __name__ == '__main__':
    generate_all()
