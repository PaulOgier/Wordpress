#!/usr/bin/env python3
"""
WordPress External Exposure Audit
=============================================================================
Copyright (c) 2026 Paul Ogier, Outsource House (South Africa)
Website: https://osh.co.za | Email: support@osh.co.za
Training provided by Taming.Tech (https://taming.tech)

Google Workspace GAM7 Course on Udemy   https://taming.tech/GAMCourse
Google Workspace Admin Course on Udemy  https://www.taming.tech/GoogleWorkspaceAdmin
Google Workspace End-User Course on Udemy  https://www.taming.tech/TheCompleteWorkspaceCourse

Licence: Apache License 2.0 (full text in LICENSE at the repository root)

In plain English:
  - Free to use, including for commercial purposes.
  - Modify and redistribute freely; closed-source derivatives are allowed.
  - PLEASE KEEP THE ATTRIBUTION above intact. If you redistribute this
    file (modified or not), the copyright, contact, and course-link block
    at the top must stay in place. This is the one real obligation the
    licence puts on you (Apache 2.0 clause 4(c)) and it is what lets
    users find the original author and the training resources. Removing
    or replacing it is a licence violation.
  - No warranty: the disclaimer below is part of the licence terms.
  - "OSH", "Outsource House", and "Taming.Tech" are trademarks and are
    not licensed for use in your own product or marketing names
    (Apache 2.0 clause 6).

DISCLAIMER & LIMITATION OF LIABILITY:
This software is provided "AS IS", without warranty of any kind, express or
implied. The authors (Paul Ogier, Outsource House) and training providers
(Taming.Tech) accept NO RESPONSIBILITY for any damages, data loss, or system
issues that may arise from its use.

YOU ASSUME ALL RISK ASSOCIATED WITH THE USE OF THIS SOFTWARE.

AUTHORISATION:
Run this only against a site you own or have written permission to test.
Unauthorised scanning of third-party systems is illegal in most
jurisdictions. See "Safety posture" below for what this does and does not do.
=============================================================================

Author:       Paul Ogier
Created:      2026-09-03
Updated:      2026-09-03
Version:      1.2.0
Status:       Production
Python:       3.9+
Dependencies: Stdlib only. `dig` is used for DNS when present, with a
              DNS-over-HTTPS fallback, so nothing needs installing.

What it does
------------
A READ-ONLY external audit of a WordPress site. Three stages, each
restartable:

  collect -> check -> render

  collect : fetches the site's public surface (headers, a calibrated set of
            paths, the REST index, the four author-disclosure routes, the
            whole media library, plugin versions across the sitemap, the
            currency and vulnerability record of every component it
            identified, TLS and mail DNS), writing one JSON file per module
            into a timestamped
            run directory. manifest.json records completed modules so a
            re-run resumes instead of restarting.
  check   : a findings engine reads ONLY the collected JSON and produces
            findings (severity, plain-English title, what it means,
            remediation, evidence rows).
  render  : a single self-contained HTML report with a sticky contents rail
            and a print stylesheet. Modules that could not run are always
            listed - nothing is silently absent.

Safety posture
--------------
Every request is a GET or a HEAD. There is no POST, no form submission, no
password guessing, no injection payload, no load testing, and nothing behind
a login. A full run is a few hundred ordinary page fetches, which is safe
against production and inside the terms of hosts that forbid load testing.

This is NOT a penetration test. It cannot find injection flaws, broken
access control behind a login, or anything that needs a request this tool
will not send. A clean report is not a clean bill of health, and the report
says so in its own words.

The verified traps this encodes
-------------------------------
Each of these produced a wrong report before it was fixed. They are the
reason this tool exists rather than a `curl` loop.

  1. A cached page lies about a plugin version. Asset URLs carry the version,
     but an edge cache serves whatever was cached when the page was built.
     Every version read here is cache-busted and the cache header is recorded
     beside the number, so a stale reading is visible rather than assumed.
  2. A plugin's assets do not appear on every page. Reading one page and
     concluding "this plugin is only used here" is wrong: on one live site a
     single-page reading missed 40 of the 41 pages carrying the plugin. The
     asset module sweeps the sitemap.
  3. A short REST page is not the last page. WordPress filters items out of a
     page AFTER slicing it, so page 1 of a 1,250-item library can return 69
     rows while later pages are full. Only an empty list or the HTTP 400
     WordPress returns past the last page marks the end.
  4. The walk does not necessarily reach the whole library. On one live site
     X-WP-Total said 1,250 and the complete walk returned 875. Absence from
     the walk is therefore NOT absence from the library, and the report
     states the gap instead of quietly reporting the smaller number.
  5. The media library is not the filesystem. Files uploaded by an older
     install, or deleted from the library while the file stayed on disk, are
     invisible to the REST API and to wp-admin, and stay downloadable. The
     authoritative inventory is a directory walk over SSH, which this tool
     deliberately does not do; the report names the command.
  6. An installer answering is not a finding. /wp-admin/install.php responds
     on every WordPress site. It matters only if it still offers to install.
  7. A themed 404 can return 200, and some sites 301 every unknown path to
     the homepage. Without calibration a redirect-following client reports
     /backup.sql as a downloadable database. One uncalibrated run produced
     five CRITICAL findings that were all false.
  8. urllib follows redirects, and that hides two findings: a plain-HTTP
     check reads as "this site does not redirect" when it does, and ?author=N
     looks blocked because you never see where it pointed.
  9. Cloudflare and similar edges serve a challenge page with a 403 to the
     default User-Agent of curl and python, which reads as "the file is not
     public" when it is. Every request here carries a browser UA.
 10. An http:// site argument silently zeroes the report on a site that
     redirects to HTTPS: every real file 301s, matches the calibration, and
     is discarded, so the run exits 0 saying nothing is reachable. The scheme
     is normalised at startup and the report says it happened.
 11. A vulnerability database answers the same way for a plugin it has
     cleared and for a plugin it has never heard of: HTTP 200 with a null
     vulnerability list. Only the record's name field separates them. Read
     naively, every premium, custom-built and renamed plugin comes back
     clean, and so does every typo. Coverage is tracked per component and the
     report names what it could not check rather than implying it passed.
 12. A version comparison done on strings puts 1.10 below 1.9 and clears a
     plugin that is inside the affected range. Ranges are compared on numeric
     tuples, a prerelease sorts below the release it precedes so a "< 6.6.0"
     range still catches 6.6.0-beta1, and a range this tool cannot interpret
     is counted and disclosed rather than dropped.
 13. wordpress.org's release list for a plugin is not always complete. It
     returned 11 versions topping out at 1.7 for a plugin then shipping
     8.0.4, so counting releases against it reported a plugin two majors
     behind as perfectly current. A count is given only when the list
     demonstrably reaches the current release.
 14. wordpress.org serves a WITHDRAWN plugin as HTTP 404 with a body saying
     error: "closed", which is the same status as a plugin that never
     existed. Reading only 200 responses discards the most useful signal the
     API has and reports a plugin pulled from the directory for a security
     issue as merely "not in the directory". The body decides, not the
     status.
 15. The REST index is bigger than a page: 523 KB to 2.2 MB on four large
     sites. Read with the page-size cap it truncates, fails to parse, and was
     reported as "empty, the safer state" on every site with many plugins.
     It has its own cap, and a truncated body is flagged rather than absent.
 16. A hostname whose every path redirects to another site is not that site.
     One run described the other site's homepage as this host's wp-cron.php.
     A www/bare pair is adopted; any other host is refused with the address
     to use instead.
 17. A bundled library's version is not the core version. jquery.min.js
     carries ?ver=3.7.1, and read as core that became "WordPress 3.7.1 with
     450 published vulnerabilities". Only files WordPress enqueues with
     $wp_version count, and only to corroborate the generator tag or feed.
 18. A 429 is a request to slow down, not a closed door. A CDN rate-limited
     the path sweep at three requests a second and the run reported the REST
     index as "not readable, the safer state". The tool now pauses, retries
     once, slows the rest of the run, and labels anything still refused as
     rate limited.
 19. A 200 with the wrong content is not the file. A WAF page at
     /wp-admin/install.php contains neither "Already Installed" nor the
     install form; requiring the form is what keeps it out of the HIGH table.
 20. A site that is not WordPress must be told apart from a hardened one.
     Without platform detection, six modules reported "empty, the safer
     state" on a static site. They are marked not applicable instead, and the
     report's first line says so.

Example usage:

  # The ordinary run.
  python3 wp_audit.py --site https://www.example.com

  # Skip the media walk (large libraries) and the sitemap sweep.
  python3 wp_audit.py --site https://www.example.com --skip media,assets

  # Re-render an existing run without re-fetching anything.
  python3 wp_audit.py --run-dir wp_audit_runs/example_com_20260903_1900 \\
      --render-only

  # Logic tests, no network.
  python3 wp_audit.py --selftest
"""

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Dict, List, Optional, Tuple

###############################################################################
# CONFIGURATION
###############################################################################

SCRIPT_VERSION = "1.2.0"

# [OPTIONAL] Startup check against the remote VERSION file. Fail-silent.
CHECK_FOR_UPDATES = True
UPDATE_CHECK_URL = (
    "https://raw.githubusercontent.com/PaulOgier/Wordpress/main/VERSION"
)

# [IMPORTANT] A browser User-Agent on every request. Cloudflare and similar
# edges serve a challenge page with a 403 to curl's and python's defaults,
# which reads as "the file is not public" when it is.
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/128.0.0.0 Safari/537.36")

# [IMPORTANT] Root directory for audit runs. Each run gets its own
# wp_audit_<host>_<timestamp> subfolder. Override with --output-dir.
OUTPUT_DIRECTORY = Path("./wp_audit_runs")

# [OPTIONAL] Politeness. A run is a few hundred requests; this keeps it from
# looking like a burst to a rate limiter.
REQUEST_DELAY = 0.15         # seconds between requests
REQUEST_TIMEOUT = 25         # seconds per request
MAX_BODY_BYTES = 400_000     # per response; enough to fingerprint any page
# The REST index is the one response that is routinely larger than a page.
# Measured on four large sites: 523 KB, 585 KB, 781 KB and 2.2 MB. Reading it
# with the page cap truncated the JSON, which parsed as nothing and was
# reported as "empty, the safer state" on every one of them.
REST_INDEX_MAX_BYTES = 8_000_000

# [OPTIONAL] Limits.
EVIDENCE_ROWS = 12           # evidence rows shown per finding in the report
MEDIA_MAX_PAGES = 200        # pages of 100 media items before giving up
ASSET_MAX_PAGES = 80         # sitemap URLs fetched for the version sweep
CALIBRATION_PROBES = 3       # nonsense paths requested to learn the 404 shape

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLOURS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
                    "MEDIUM": "#d4a017", "LOW": "#3f7fbf", "INFO": "#5a6b7b"}

# Paths that should not be readable from outside, with the severity a real
# hit earns. "why" is client-facing copy and appears verbatim in the report.
PROBE_PATHS: List[Tuple[str, str, str]] = [
    # Backup and migration leftovers. The archive holds wp-config.php and the
    # whole database, so a hit here is a full compromise for one request.
    ("/backup.zip", "CRITICAL", "a site backup archive, which contains wp-config.php and the whole database"),
    ("/backup.sql", "CRITICAL", "a database dump"),
    ("/backup.tar.gz", "CRITICAL", "a site backup archive"),
    ("/db.sql", "CRITICAL", "a database dump"),
    ("/database.sql", "CRITICAL", "a database dump"),
    ("/dump.sql", "CRITICAL", "a database dump"),
    ("/site.zip", "CRITICAL", "a site backup archive"),
    ("/wordpress.zip", "CRITICAL", "a site backup archive"),
    ("/installer.php", "CRITICAL", "the Duplicator installer, which can rebuild or overwrite the site"),
    ("/installer-backup.php", "CRITICAL", "a Duplicator installer left behind after a migration"),
    ("/dup-installer/", "CRITICAL", "the Duplicator installer directory"),
    ("/wp-content/ai1wm-backups/", "CRITICAL", "All-in-One WP Migration archives, which contain the whole database"),
    ("/wp-content/updraft/", "CRITICAL", "UpdraftPlus backup archives"),
    ("/wp-content/backups-dup-lite/", "CRITICAL", "Duplicator backup archives"),
    ("/wp-content/backupwordpress/", "CRITICAL", "BackUpWordPress archives"),
    ("/wp-content/wpvividbackups/", "CRITICAL", "WPvivid backup archives"),
    ("/wp-content/uploads/backupbuddy_backups/", "CRITICAL", "BackupBuddy archives"),
    ("/wp-content/plugins/wp-staging/", "HIGH", "a WP Staging working directory"),
    # Credentials and configuration.
    ("/wp-config.php.bak", "CRITICAL", "the WordPress configuration file, which contains the database password"),
    ("/wp-config.php~", "CRITICAL", "an editor backup of the WordPress configuration file"),
    ("/wp-config.php.save", "CRITICAL", "an editor backup of the WordPress configuration file"),
    ("/wp-config.txt", "CRITICAL", "the WordPress configuration file as plain text"),
    ("/.env", "CRITICAL", "an environment file, which usually holds API keys and database credentials"),
    ("/.git/config", "CRITICAL", "a Git repository, from which the whole source tree can be reconstructed"),
    ("/.git/HEAD", "CRITICAL", "a Git repository, from which the whole source tree can be reconstructed"),
    ("/.svn/entries", "HIGH", "a Subversion working copy"),
    ("/.htpasswd", "CRITICAL", "an HTTP authentication password file"),
    ("/.aws/credentials", "CRITICAL", "Amazon Web Services credentials"),
    ("/id_rsa", "CRITICAL", "a private SSH key"),
    ("/.user.ini", "MEDIUM", "a per-directory PHP configuration file, which names paths and settings"),
    # Logs and diagnostics.
    ("/wp-content/debug.log", "HIGH", "the WordPress debug log, which leaks file paths and sometimes credentials"),
    ("/error_log", "MEDIUM", "the server error log"),
    ("/phpinfo.php", "HIGH", "a phpinfo() page, which lists the full server configuration"),
    ("/info.php", "HIGH", "a phpinfo() page"),
    ("/adminer.php", "CRITICAL", "Adminer, a web database client"),
    ("/phpmyadmin/", "HIGH", "phpMyAdmin, a web database client"),
    ("/server-status", "MEDIUM", "the Apache status page, which lists live requests and visitor addresses"),
    # Developer artefacts. Not a way in, but they name every library and its
    # version, which is the shortlist of exploits worth trying.
    ("/composer.json", "LOW", "the Composer manifest, which lists the PHP packages installed and their versions"),
    ("/package.json", "LOW", "the Node manifest, which lists the JavaScript packages used to build the site"),
    ("/.DS_Store", "LOW", "a macOS folder index, which lists the names of every file in the directory including ones nothing links to"),
    # Directory listings.
    ("/wp-content/uploads/", "MEDIUM", "a browsable list of every uploaded file"),
    ("/wp-content/plugins/", "MEDIUM", "a browsable list of every installed plugin"),
    ("/wp-content/themes/", "LOW", "a browsable list of every installed theme"),
    ("/wp-includes/", "LOW", "a browsable WordPress core directory"),
    ("/vendor/", "LOW", "a browsable Composer vendor directory"),
    ("/node_modules/", "LOW", "a browsable Node modules directory"),
    # Form and commerce upload directories. This is where client personal
    # information actually leaks: attachments visitors uploaded through a
    # form, order logs, file-manager backups. Only a browsable listing
    # counts; the directory existing is normal on any site with the plugin.
    ("/wp-content/uploads/wpforms/", "HIGH", "a browsable list of files visitors uploaded through WPForms"),
    ("/wp-content/uploads/formidable/", "HIGH", "a browsable list of files visitors uploaded through Formidable Forms"),
    ("/wp-content/uploads/gravity_forms/", "HIGH", "a browsable list of files visitors uploaded through Gravity Forms"),
    ("/wp-content/uploads/wc-logs/", "HIGH", "WooCommerce log files, which contain order and customer details"),
    ("/wp-content/uploads/wp-file-manager-pro/fm_backup/", "CRITICAL", "File Manager backups, which contain the whole site"),
    # Version and platform disclosure.
    ("/readme.html", "LOW", "the WordPress readme, which confirms the platform and the PHP floor"),
    ("/license.txt", "LOW", "the WordPress licence file, which confirms the platform and often narrows the version"),
    ("/wp-admin/install.php", "HIGH", "the WordPress installer, which can take over an unconfigured site"),
    ("/wp-admin/setup-config.php", "HIGH", "the WordPress setup wizard"),
    # Miscellaneous. The REST users and media endpoints and xmlrpc.php are
    # deliberately absent: check_users(), check_media() and check_transport()
    # cover them with better evidence, and probing them here too reported the
    # same endpoint twice in one report.
]

# Paths where a 200 is normal and only the CONTENT decides whether it is a
# finding. Checked by name in path_is_exposed().
INSTALLER_PATHS = ("/wp-admin/install.php", "/wp-admin/setup-config.php")

# What a live installer page actually contains. The finding needs one of these
# present, not merely "Already Installed" absent: a WAF that answers wp-admin
# requests with a 200 challenge page contains neither, and reading that as an
# open installer would put a false HIGH in front of a client.
INSTALLER_MARKERS = ("weblog_title", "language-chooser", "information needed",
                     "welcome to wordpress", "setup-config", "site title",
                     "create a configuration file", "wp-config.php")

# Content a real file at this path must contain, matched case-insensitively
# anywhere in the body. A 200 whose body has none of them is recorded as
# "answered, unexpected content" rather than as readable: a themed not-found
# page or a WAF block page served with a 200 has no business in a CRITICAL
# table. Archives are checked by their first bytes in content_matches().
# Paths not listed here keep the plain 200 rule.
CONTENT_MARKERS: Dict[str, Tuple[str, ...]] = {
    "/.env": ("=",),
    "/.git/config": ("[core]", "repositoryformatversion"),
    "/.git/HEAD": ("ref:", "refs/"),
    "/.htpasswd": (":",),
    "/.aws/credentials": ("aws_access_key_id", "aws_secret_access_key"),
    "/id_rsa": ("private key",),
    "/.user.ini": ("=",),
    "/wp-config.php.bak": ("db_name", "db_password", "<?php"),
    "/wp-config.php~": ("db_name", "db_password", "<?php"),
    "/wp-config.php.save": ("db_name", "db_password", "<?php"),
    "/wp-config.txt": ("db_name", "db_password", "<?php"),
    "/wp-content/debug.log": ("php ", "[", "warning", "notice", "error"),
    "/error_log": ("php ", "[", "warning", "notice", "error"),
    "/phpinfo.php": ("phpinfo()", "php version"),
    "/info.php": ("phpinfo()", "php version"),
    "/adminer.php": ("adminer",),
    "/phpmyadmin/": ("phpmyadmin",),
    "/server-status": ("server status", "server version"),
    "/composer.json": ('"require"', '"name"'),
    "/package.json": ('"name"', '"dependencies"'),
    "/.DS_Store": ("bud1",),
    "/installer.php": ("duplicator",),
    "/installer-backup.php": ("duplicator",),
    "/dup-installer/": ("index of /", "duplicator"),
}
SQL_MARKERS = ("insert into", "create table", "-- mysql dump", "-- phpmyadmin",
               "drop table", "/*!40101")

# Security response headers, with what their absence costs. Severity is the
# author's rating; see "Severity" in the README for how these were set.
SECURITY_HEADERS: List[Tuple[str, str, str]] = [
    ("strict-transport-security", "MEDIUM",
     "browsers will try plain HTTP first, so a visitor's first request on a "
     "hostile network can be intercepted before the redirect to HTTPS "
     "happens. Exploiting it needs an attacker already on the path, which is "
     "why this is rated medium rather than high on a site that already "
     "redirects."),
    ("content-security-policy", "MEDIUM",
     "there is no restriction on where scripts may load from, which is what "
     "turns one injected tag into a working attack."),
    ("x-frame-options", "LOW",
     "the site can be framed by another, which allows clickjacking. On a "
     "site with no logged-in state-changing screens this is largely "
     "theoretical, and a Content-Security-Policy frame-ancestors rule is the "
     "modern control."),
    ("referrer-policy", "LOW",
     "full URLs leak to third-party sites in the Referer header."),
    ("permissions-policy", "LOW",
     "there is no restriction on camera, microphone and geolocation for "
     "embedded content."),
    ("x-content-type-options", "LOW",
     "browsers may guess a response's type and execute something that was "
     "meant to be downloaded."),
]

# Headers that give away software versions. Not a vulnerability on their own,
# but they tell an attacker which exploits are worth trying.
LEAKY_HEADERS = ["x-powered-by", "x-generator", "x-redirect-by", "server"]

# Filenames worth a human opening, in the media and document inventory. These
# are substring matches against the URL, case-insensitive.
SENSITIVE_WORDS = [
    "patient", "medical", "clinical", "phi", "hipaa", "diagnos",
    "payroll", "salary", "compensation", "benefit", "401k",
    "pension", "invoice", "statement", "remittance", "banking",
    "contract", "agreement", "nondisclosure", "confidential", "internal",
    "private", "proprietary", "password", "credential", "licencekey",
    "employee", "staff", "personnel", "disciplinary",
    "feeschedule", "pricing", "ratecard", "disclosure",
    "tax", "vat", "audit", "board", "minutes", "strategy",
    "idcopy", "passport", "insurance", "claim",
]

# Extensions treated as documents rather than images in the media inventory.
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
           ".csv", ".txt", ".rtf", ".odt", ".ods", ".zip", ".rar", ".7z",
           ".tar", ".gz", ".sql", ".json", ".xml"}

# WordPress core REST namespaces, excluded when counting third-party plugins.
CORE_NAMESPACES = {"oembed/1.0", "wp/v2", "wp-site-health/v1",
                   "wp-block-editor/v1", "wp/v2/", "wp-abilities/v1"}

# Namespace prefix -> (human name, plugin directory slug), so the report reads
# as a plugin inventory rather than a list of slugs, and so a plugin known only
# from its namespace can have its readme.txt read for a version. The slug is
# None where the directory name is not known with confidence; guessing one
# would be probing for plugins the site never advertised, which this tool does
# not do. Unknown namespaces are shown as-is.
NAMESPACE_PLUGINS: Dict[str, Tuple[str, Optional[str]]] = {
    "acf/v3": ("Advanced Custom Fields", "advanced-custom-fields"),
    "aioseo/v1": ("All in One SEO", "all-in-one-seo-pack"),
    "akismet/v1": ("Akismet", "akismet"),
    "apple-news/v1": ("Publish to Apple News", "publish-to-apple-news"),
    "bctt/v1": ("Better Click To Tweet", "better-click-to-tweet"),
    "buddypress/v1": ("BuddyPress", "buddypress"),
    "carbon-fields/v1": ("Carbon Fields", "carbon-fields"),
    "coauthors/v1": ("Co-Authors Plus", "co-authors-plus"),
    "code-snippets/v1": ("Code Snippets", "code-snippets"),
    "complianz/v1": ("Complianz", "complianz-gdpr"),
    "contact-form-7/v1": ("Contact Form 7", "contact-form-7"),
    "duplicator/v1": ("Duplicator", "duplicator"),
    "elasticpress/v1": ("ElasticPress", "elasticpress"),
    "elementor/v1": ("Elementor", "elementor"),
    "fluent-smtp": ("FluentSMTP", "fluent-smtp"),
    "gf/v2": ("Gravity Forms", "gravityforms"),
    "google-site-kit/v1": ("Site Kit by Google", "google-site-kit"),
    "health-check/v1": ("Health Check", "health-check"),
    "hostinger-ai-assistant/v1": ("Hostinger AI Assistant", None),
    "hostinger-tools-plugin/v1": ("Hostinger Tools", None),
    "ithemes-security/v1": ("Solid Security", "better-wp-security"),
    "jetpack/v4": ("Jetpack", "jetpack"),
    "jetpack-boost/v1": ("Jetpack Boost", "jetpack-boost"),
    "kadence-blocks/v1": ("Kadence Blocks", "kadence-blocks"),
    "litespeed/v1": ("LiteSpeed Cache", "litespeed-cache"),
    "litespeed/v3": ("LiteSpeed Cache", "litespeed-cache"),
    "mainwp/v1": ("MainWP Dashboard", "mainwp"),
    "mainwp/v2": ("MainWP Dashboard", "mainwp"),
    "mcp": ("MCP adapter", None),
    "monsterinsights/v1": ("MonsterInsights", "google-analytics-for-wordpress"),
    "rankmath/v1": ("Rank Math SEO", "seo-by-rank-math"),
    "redirection/v1": ("Redirection", "redirection"),
    "regenerate-thumbnails/v1": ("Regenerate Thumbnails", "regenerate-thumbnails"),
    "seopress/v1": ("SEOPress", "wp-seopress"),
    "sg-security/v1": ("SiteGround Security", "sg-security"),
    "simple-page-ordering/v1": ("Simple Page Ordering", "simple-page-ordering"),
    "siteground-settings/v1": ("SiteGround Optimizer", "sg-cachepress"),
    "squirrly/v1": ("Squirrly SEO", "squirrly-seo"),
    "tribe/events/v1": ("The Events Calendar", "the-events-calendar"),
    "two-factor/1.0": ("Two-Factor", "two-factor"),
    "wc/v3": ("WooCommerce", "woocommerce"),
    "wordfence/v1": ("Wordfence", "wordfence"),
    "wp-mail-smtp/v1": ("WP Mail SMTP", "wp-mail-smtp"),
    "wp-parsely/v2": ("Parse.ly", "wp-parsely"),
    "wp-rocket/v1": ("WP Rocket", "wp-rocket"),
    "wpforms/v1": ("WPForms", "wpforms-lite"),
    "yoast/v1": ("Yoast SEO", "wordpress-seo"),
}
NAMESPACE_NAMES = {ns: name for ns, (name, _) in NAMESPACE_PLUGINS.items()}

# Response headers that identify a CDN, WAF or managed host in front of the
# site. What sits in front changes what every probe means: a 403 may be the
# edge rather than the file, and a version read through a cache may be stale.
# Each entry is (label, header, substring-or-None). None means presence alone.
EDGE_SIGNS: List[Tuple[str, str, Optional[str]]] = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "server", "cloudflare"),
    ("Sucuri", "x-sucuri-id", None),
    ("Sucuri", "x-sucuri-cache", None),
    ("Akamai", "server", "akamai"),
    ("Akamai", "x-akamai-transformed", None),
    ("CloudFront", "via", "cloudfront"),
    ("CloudFront", "server", "cloudfront"),
    ("Fastly", "via", "varnish"),
    ("Fastly", "x-served-by", "cache-"),
    ("Kinsta", "x-kinsta-cache", None),
    ("WP Engine", "x-powered-by", "wp engine"),
    ("Hostinger", "server", "hcdn"),
    ("LiteSpeed", "server", "litespeed"),
    ("LiteSpeed", "x-litespeed-cache", None),
    ("Nginx", "server", "nginx"),
    ("Apache", "server", "apache"),
]

# Body text that means the response is a WAF block or bot challenge, not the
# page asked for. Checked on the homepage; if the homepage itself is one of
# these, every later module is reading the edge and not the site.
CHALLENGE_MARKERS = ("just a moment", "cf-chl", "challenge-platform",
                     "attention required", "sucuri website firewall",
                     "generated by wordfence", "access denied",
                     "your access to this site has been limited",
                     "enable javascript and cookies to continue")

# Namespaces that accept a write method anonymously and deserve their own
# finding rather than a line in the inventory.
RPC_NAMESPACE_HINTS = ("mcp", "ai-assistant", "graphql")

# ---------------------------------------------------------------------------
# Vulnerability and currency lookups. Two sources, deliberately different in
# what they are trusted for.
#
# api.wordpress.org is first-party and authoritative for what the plugin
# directory currently ships: the current release, the release history, the
# last release date, the core version the author declares tested, and whether
# the plugin has been CLOSED (pulled from the directory, which is frequently a
# security removal and is one of the strongest signals available from outside).
# No key, no registration.
#
# wpvulnerability.net is a third-party aggregate of CVE, EUVD, JVN, Patchstack,
# Wordfence and WPScan, re-derived rather than mirrored. No key. It carries
# CVSS vectors and scores, which is what lets a finding be ranked. Its limits
# are encoded in collect_vulns() and stated in the report: an unknown slug and
# a clean plugin return almost the same JSON, so "no record" is reported as NOT
# COVERED and never as clean.
WPORG_PLUGIN_API = ("https://api.wordpress.org/plugins/info/1.2/"
                    "?action=plugin_information&request[slug]={slug}")
WPORG_THEME_API = ("https://api.wordpress.org/themes/info/1.2/"
                   "?action=theme_information&request[slug]={slug}")
WPORG_STABLE_CHECK = "https://api.wordpress.org/core/stable-check/1.0/"
WPVULN_API = "https://www.wpvulnerability.net/{kind}/{slug}/"

# A plugin with no release in this long is treated as unmaintained. Two years
# is deliberately generous: a small, finished plugin can sit untouched and be
# fine, which is why this is MEDIUM and phrased as "worth reviewing".
ABANDONED_DAYS = 730

# How far behind the current core release a plugin's "Tested up to" may fall
# before it is worth saying so. One major is normal in the weeks after a core
# release; two means nobody has looked.
TESTED_MAJORS_BEHIND = 2

# CVSS base score -> the severity this report gives the finding.
CVSS_BANDS = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM")]

def sensitive_hits(url_path: str) -> List[str]:
    """Flagged words in a filename, matched on token boundaries.

    A plain substring match is unusable in a client report: "nda" fires on
    "Agenda" and "RecommendationLetter", and a reviewer handed five false hits
    stops reading the list. Short words must match a whole token. Long ones may
    match inside one, because a filename writes "feeschedule" without a
    separator as often as with.
    """
    name = url_path.lower()
    spaced = re.sub(r"[^a-z0-9]+", " ", name)
    squashed = spaced.replace(" ", "")
    hits = []
    for word in SENSITIVE_WORDS:
        w = re.sub(r"[^a-z0-9]+", "", word.lower())
        if not w:
            continue
        if len(w) >= 6:
            if w in squashed:
                hits.append(word)
        elif re.search(r"\b" + re.escape(w) + r"\b", spaced):
            hits.append(word)
    return sorted(set(hits))


DOH_URL = "https://dns.google/resolve"

shutdown_requested = False

###############################################################################
# COLOURS / CONSOLE
###############################################################################


class Colours:
    """ANSI colour codes; bright variants for dark-background readability."""
    RED = '\033[1;91m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[1;93m'
    BLUE = '\033[1;94m'
    CYAN = '\033[1;96m'
    RESET = '\033[0m'

    @staticmethod
    def strip_colours():
        Colours.RED = Colours.GREEN = Colours.YELLOW = ''
        Colours.BLUE = Colours.CYAN = Colours.RESET = ''


def _enable_windows_ansi() -> bool:
    """Enable ANSI escape processing on the Windows console (Windows 10+)."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # 7 is STD_OUTPUT_HANDLE; 0x0004 is ENABLE_VIRTUAL_TERMINAL_PROCESSING.
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _force_utf8_console():
    """Windows consoles default to cp1252 and raise on the box-drawing and
    arrow characters used below. Reconfigure where the runtime allows it."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def signal_handler(_signum, _frame):
    """Ctrl-C stops after the current request rather than mid-write, so the
    manifest stays consistent and the run can be resumed."""
    global shutdown_requested
    if shutdown_requested:                       # second Ctrl-C: go now
        sys.exit(130)
    shutdown_requested = True
    print_warning("Stop requested; finishing the current module. "
                  "Press Ctrl-C again to abort immediately.")


class _PlainFormatter(logging.Formatter):
    """Strip ANSI codes so the log file is readable in any editor."""

    _ANSI = re.compile(r"\033\[[0-9;]*m")

    def format(self, record):
        return self._ANSI.sub("", super().format(record))


def setup_logging(run_dir: Path):
    """Console output is mirrored to run.log in the run directory."""
    handler = logging.FileHandler(run_dir / "run.log", encoding="utf-8")
    handler.setFormatter(_PlainFormatter("%(asctime)s  %(message)s",
                                         "%Y-%m-%d %H:%M:%S"))
    root = logging.getLogger("wp_audit")
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def _emit(level: str, text: str):
    print(text)
    logging.getLogger("wp_audit").log(
        logging.WARNING if level in ("warn", "error") else logging.INFO, text)


def print_header(title: str):
    _emit("info", f"\n{Colours.CYAN}{'=' * 70}\n  {title}\n"
                  f"{'=' * 70}{Colours.RESET}")


def print_success(msg: str):
    _emit("info", f"{Colours.GREEN}  [OK]{Colours.RESET} {msg}")


def print_warning(msg: str):
    _emit("warn", f"{Colours.YELLOW}  [!] {Colours.RESET} {msg}")


def print_error(msg: str):
    _emit("error", f"{Colours.RED}  [X] {Colours.RESET} {msg}")


def print_info(msg: str):
    _emit("info", f"{Colours.BLUE}  [-] {Colours.RESET} {msg}")


def check_for_updates():
    """Compare SCRIPT_VERSION against the repository's VERSION file.

    Fail-silent by design: an audit must not stop because GitHub is down or
    the machine is offline.
    """
    if not CHECK_FOR_UPDATES:
        return
    try:
        req = urllib.request.Request(UPDATE_CHECK_URL,
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=5) as resp:
            latest = resp.read(32).decode("utf-8", "replace").strip()
    except Exception:
        return
    if latest and latest != SCRIPT_VERSION:
        print_warning(f"Version {latest} is available "
                      f"(this is {SCRIPT_VERSION}): "
                      "https://github.com/PaulOgier/Wordpress")


###############################################################################
# HTTP LAYER
###############################################################################

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report the redirect itself rather than where it lands."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _headers(msg) -> Dict[str, str]:
    """Lowercased header dict that keeps every Set-Cookie.

    A dict comprehension over headers.items() keeps only the LAST Set-Cookie
    when a response sets several, so a cookie without Secure that was set
    first vanished from the cookie check. Multiple cookies are joined with a
    newline, which cannot appear inside a header value; the caller splits on
    it. Splitting on commas is wrong because Expires carries one.
    """
    out = {k.lower(): v for k, v in msg.items()}
    try:
        cookies = msg.get_all("Set-Cookie") or []
    except AttributeError:
        cookies = []
    if len(cookies) > 1:
        out["set-cookie"] = "\n".join(cookies)
    return out


def fetch(url: str, method: str = "GET", timeout: int = REQUEST_TIMEOUT,
          max_bytes: int = MAX_BODY_BYTES) -> Tuple[int, Dict[str, str], str]:
    """One request with a browser UA, redirects followed.

    Returns (status, lowercased headers, body text). Status 0 means the
    request never completed, and headers carries "_error" with the reason.
    A body cut off at max_bytes sets "_truncated", so a caller parsing JSON
    can tell a truncated document from a non-JSON one.
    """
    time.sleep(_delay())
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT})
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(max_bytes) if method == "GET" else b""
                hdrs = _headers(r.headers)
                if len(body) >= max_bytes:
                    hdrs["_truncated"] = str(max_bytes)
                return r.status, hdrs, body.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 1 and _back_off(e.headers):
                continue
            try:
                body = e.read(max_bytes).decode("utf-8", "replace")
            except Exception:
                body = ""
            return e.code, _headers(e.headers or {}), body
        except Exception as e:
            return 0, {"_error": f"{type(e).__name__}: {e}"}, ""
    return 0, {"_error": "unreachable"}, ""


# Rate limiting. One live run got HTTP 429 on 21 probes and both REST index
# requests after the path sweep ran at seven requests a second through
# Cloudflare. A 429 is a request to slow down, so the tool does: it waits
# (Retry-After when given, otherwise a few seconds), retries once, and slows
# every later request for the rest of the run. Anything still refused is
# recorded as "rate limited", never as "not readable".
RATE_LIMIT_PAUSE = 8          # seconds to wait after a 429 with no Retry-After
RATE_LIMIT_MAX_PAUSE = 30
_slowdown = 1.0


def _delay() -> float:
    return REQUEST_DELAY * _slowdown


def _back_off(headers) -> bool:
    """Wait as the server asked, and slow the rest of the run. Always True."""
    global _slowdown
    try:
        pause = float((headers or {}).get("Retry-After", RATE_LIMIT_PAUSE))
    except (TypeError, ValueError):
        pause = RATE_LIMIT_PAUSE
    pause = min(max(pause, 1.0), RATE_LIMIT_MAX_PAUSE)
    _slowdown = min(_slowdown * 2, 16.0)
    print_warning(f"HTTP 429: pausing {pause:.0f}s and slowing the run "
                  f"({_delay():.2f}s between requests)")
    time.sleep(pause)
    return True


def fetch_no_redirect(url: str,
                      timeout: int = REQUEST_TIMEOUT) -> Tuple[int, Dict[str, str]]:
    """One request with redirects NOT followed. Returns (status, headers).

    urllib follows redirects by default, and that hides two findings. A
    plain-HTTP check through fetch() reports the final HTTPS 200 with no
    Location header, which reads as "this site does not redirect" when it
    does; and ?author=N looks blocked because you never see where it pointed.
    """
    time.sleep(_delay())
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in (1, 2):
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, _headers(r.headers)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt == 1 and _back_off(e.headers):
                continue
            return e.code, _headers(e.headers or {})
        except Exception as e:
            return 0, {"_error": f"{type(e).__name__}: {e}"}
    return 0, {"_error": "unreachable"}


def fetch_json(url: str, max_bytes: int = MAX_BODY_BYTES):
    """GET a URL and parse JSON. Returns (status, headers, object-or-None).

    A host serving a challenge page returns valid HTTP and invalid JSON, so
    the caller needs to tell "no data" from "not JSON". A truncated body is a
    third case and the most misleading: it is valid JSON that was cut off,
    and headers["_truncated"] is how the caller finds out.
    """
    status, hdrs, body = fetch(url, max_bytes=max_bytes)
    if status != 200:
        return status, hdrs, None
    try:
        return status, hdrs, json.loads(body)
    except json.JSONDecodeError:
        return status, hdrs, None


def edge_identity(hdrs: Dict[str, str], body: str = "") -> Dict:
    """Name what is in front of the site, and whether this response is a
    block or challenge page rather than the page asked for."""
    seen: List[str] = []
    for label, header, needle in EDGE_SIGNS:
        value = hdrs.get(header, "")
        if header in hdrs and (needle is None or needle in value.lower()):
            if label not in seen:
                seen.append(label)
    low = body.lower()[:20000]
    challenged = any(marker in low for marker in CHALLENGE_MARKERS)
    return {"edge": seen, "challenged": challenged}


###############################################################################
# VERSION COMPARISON
###############################################################################

_VERSION_RE = re.compile(r"^[vV]?(\d[\d.]*)(.*)$")


def version_key(version: str) -> Tuple[Tuple[int, ...], int]:
    """A comparable key for a WordPress-style version string.

    Splitting on dots and comparing numerically is the whole job, but two
    details decide whether a vulnerability range matches correctly:

      - 1.10 is ABOVE 1.9. A string comparison puts it below, which would
        clear a vulnerable plugin.
      - 6.6.0-beta1 is BELOW 6.6.0, so a "< 6.6.0" range must still catch it.
        The suffix therefore sorts the version down, never up.

    Anything that does not start with a digit is unorderable and returns a
    key that sorts below everything; callers treat that as undecidable rather
    than as a match.
    """
    match = _VERSION_RE.match(str(version or "").strip())
    if not match:
        return ((-1,), 0)
    numbers = tuple(int(part) for part in match.group(1).strip(".").split(".")
                    if part.isdigit())
    if not numbers:
        return ((-1,), 0)
    numbers = (numbers + (0, 0, 0, 0))[:4]
    return (numbers, -1 if match.group(2).strip() else 0)


def version_ordered(version: str) -> bool:
    """Whether version_key() could actually place this string."""
    return version_key(version)[0] != (-1,)


def vuln_applies(version: str, operator: Dict) -> Optional[bool]:
    """Does a vulnerability's version range cover the version we detected?

    Returns True, False, or None when the record cannot be decided - an
    operator this code does not implement, an unparseable version, or a range
    with no bound at all. None is NOT False: an undecidable record is counted
    and disclosed in the report, because silently dropping it turns an unknown
    into a clean result.
    """
    if not version_ordered(version):
        return None
    detected = version_key(version)
    max_version = operator.get("max_version")
    max_operator = (operator.get("max_operator") or "").lower()
    min_version = operator.get("min_version")
    min_operator = (operator.get("min_operator") or "").lower()
    if not max_version and not min_version:
        return None
    if max_version:
        if not version_ordered(max_version):
            return None
        bound = version_key(max_version)
        if max_operator == "lt":
            if not detected < bound:
                return False
        elif max_operator == "le":
            if not detected <= bound:
                return False
        elif max_operator == "eq":
            if detected != bound:
                return False
        else:
            return None
    if min_version:
        if not version_ordered(min_version):
            return None
        bound = version_key(min_version)
        if min_operator == "ge":
            if not detected >= bound:
                return False
        elif min_operator == "gt":
            if not detected > bound:
                return False
        else:
            return None
    return True


def cvss_severity(score: float) -> str:
    """Report severity for a CVSS base score.

    A record with no score is unknown, not low. It comes back as MEDIUM so
    the badge and the copy ("read unscored as unknown") say the same thing.
    """
    if not score or score <= 0:
        return "MEDIUM"
    for floor, severity in CVSS_BANDS:
        if score >= floor:
            return severity
    return "LOW"


def cap_severity(severity: str, ceiling: str) -> str:
    """The lower of two severities. A cap must never raise a finding."""
    return (ceiling if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(ceiling)
            else severity)


def _vuln_rows(record: Dict, version: str) -> Tuple[List[Dict], int]:
    """Vulnerabilities from a wpvulnerability record that cover `version`.

    Returns (matching rows, count of records that could not be decided).
    """
    matched, undecidable = [], 0
    for entry in record.get("vulnerability") or []:
        verdict = vuln_applies(version, entry.get("operator") or {})
        if verdict is None:
            undecidable += 1
            continue
        if not verdict:
            continue
        cvss = ((entry.get("impact") or {}).get("cvss") or {})
        try:
            score = float(cvss.get("score"))
        except (TypeError, ValueError):
            score = 0.0
        sources = entry.get("source") or []
        cve = next((s.get("id") for s in sources
                    if str(s.get("id", "")).startswith("CVE-")), "")
        matched.append({
            "name": entry.get("name") or "",
            "cve": cve,
            "reference": next((s.get("link") for s in sources if s.get("link")), ""),
            "score": score,
            "vector": cvss.get("vector") or "",
            "fixed_in": (entry.get("operator") or {}).get("max_version") or "",
            "unfixed": str((entry.get("operator") or {}).get("unfixed")) == "1",
        })
    matched.sort(key=lambda row: row["score"], reverse=True)
    return matched, undecidable


def _core_rows(record: Dict) -> List[Dict]:
    """Vulnerabilities from a wpvulnerability CORE record.

    Kept apart from _vuln_rows() because the two endpoints are shaped
    differently: /core/<version>/ is already scoped to the version asked for
    and its records carry no operator block, so there is no range to match.
    """
    rows = []
    for entry in record.get("vulnerability") or []:
        cvss = ((entry.get("impact") or {}).get("cvss") or {})
        try:
            score = float(cvss.get("score"))
        except (TypeError, ValueError):
            score = 0.0
        sources = entry.get("source") or []
        rows.append({
            "name": entry.get("name") or "",
            "cve": next((s.get("id") for s in sources
                         if str(s.get("id", "")).startswith("CVE-")), ""),
            "reference": next((s.get("link") for s in sources if s.get("link")), ""),
            "score": score,
            "vector": cvss.get("vector") or "",
            "fixed_in": (entry.get("operator") or {}).get("max_version") or "",
            "unfixed": False,
        })
    rows.sort(key=lambda row: row["score"], reverse=True)
    return rows


def _wporg(url: str) -> Optional[Dict]:
    """One api.wordpress.org lookup. None when it did not return usable JSON.

    The status code cannot be used to decide whether there is an answer here.
    A plugin that has been CLOSED - withdrawn from the directory, which is the
    single most useful thing this API can tell you and is frequently a
    security removal - is served as HTTP 404 with a body saying so, exactly
    like a plugin that never existed. Reading only 200 responses threw both
    away and reported two withdrawn plugins on a live site as "not in the
    directory (premium, custom, or renamed)", which is the opposite of the
    truth. The body decides, not the status.
    """
    _, _, body = fetch(url)
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _wpvuln(kind: str, slug: str) -> Dict:
    """One wpvulnerability.net lookup, normalised.

    The trap this encodes: an unknown slug and a plugin with no known
    vulnerabilities both return HTTP 200 with `vulnerability: null`. The only
    thing that separates them is `data.name`, so that is what decides
    `covered`. A truncated or non-JSON body is also NOT coverage - a record
    larger than MAX_BODY_BYTES parses as nothing, and reading that as "clean"
    would be the worst possible failure of this module.
    """
    status, _, data = fetch_json(WPVULN_API.format(kind=kind, slug=slug))
    if not isinstance(data, dict):
        return {"covered": False, "record": {},
                "error": f"HTTP {status} with no usable JSON"}
    payload = data.get("data") or {}
    # The core endpoint names itself "core"; plugins and themes use "name".
    if not (payload.get("name") or payload.get("core")):
        return {"covered": False, "record": payload,
                "error": "no record for this slug"}
    return {"covered": True, "record": payload, "error": None}


def _days_since(stamp: str) -> Optional[int]:
    """Whole days since a wordpress.org `last_updated` string, or None."""
    match = re.match(r"(\d{4}-\d{2}-\d{2})", str(stamp or ""))
    if not match:
        return None
    try:
        then = datetime.strptime(match.group(1), "%Y-%m-%d")
    except ValueError:
        return None
    return (datetime.now() - then).days


###############################################################################
# CALIBRATION
###############################################################################

_TOKEN_RE = re.compile(r"[0-9a-f]{8,}|\d+", re.I)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def body_fingerprint(body: str, probe_token: str = "") -> str:
    """A stable hash of a page's shape, ignoring the things that vary.

    Two soft-404 pages for different paths differ in three ways that say
    nothing about whether a file exists: the requested path echoed into the
    body, embedded nonces and counters, and whitespace. Strip all three and
    the same 404 template hashes identically no matter what was asked for.

    Comparing raw byte length instead - the obvious approach - fails twice.
    A 404 page carrying a nonce never matches itself, and a 404 page that
    echoes the requested path never matches a probe of a different length.
    Both failures were seen on live sites.
    """
    text = body
    if probe_token:
        text = text.replace(probe_token, "")
    text = _TAG_RE.sub(" ", text)
    text = _TOKEN_RE.sub("#", text)
    text = _WS_RE.sub(" ", text).strip().lower()
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def calibrate_missing(site: str) -> Dict:
    """Learn what this site does with a path that definitely does not exist.

    Sites answer a missing path in at least three ways, and two of them look
    like success. Some serve a themed 404 with status 200. Some 301-redirect
    everything unknown to the homepage, which a redirect-following client
    then reports as a 200 with the homepage in it. Without this, /backup.sql
    on such a site is reported as a downloadable database dump. One
    uncalibrated run produced five CRITICAL findings that were all false.

    Returns a signature dict. `stable` is the field that matters: when the
    probes disagree even after fingerprinting, the site cannot be calibrated
    and every ambiguous path finding is downgraded to UNVERIFIED rather than
    reported or silently dropped.
    """
    probes = []
    for _ in range(CALIBRATION_PROBES):
        token = "zz-does-not-exist-" + uuid.uuid4().hex[:16]
        no_redirect_status, no_redirect_hdrs = fetch_no_redirect(
            f"{site}/{token}.zip")
        status, _, body = fetch(f"{site}/{token}.zip")
        probes.append({
            "status": status,
            "no_redirect_status": no_redirect_status,
            "location": no_redirect_hdrs.get("location", ""),
            "length": len(body),
            "fingerprint": body_fingerprint(body, f"{token}.zip"),
        })
    fingerprints = {p["fingerprint"] for p in probes}
    statuses = {p["status"] for p in probes}
    redirect_statuses = {p["no_redirect_status"] for p in probes}
    stable = len(fingerprints) == 1 and len(statuses) == 1

    signature = {
        "status": probes[0]["status"],
        "no_redirect_status": probes[0]["no_redirect_status"],
        "redirects_unknown_paths": 300 <= probes[0]["no_redirect_status"] < 400
                                   and len(redirect_statuses) == 1,
        "location": probes[0]["location"],
        "fingerprint": probes[0]["fingerprint"] if stable else "",
        "lengths": [p["length"] for p in probes],
        "stable": stable,
        "probes": len(probes),
    }
    return signature


CONTROL_PATHS = ("/robots.txt", "/wp-includes/js/jquery/jquery.min.js",
                 "/wp-login.php")


def verify_calibration(site: str, missing: Dict) -> Dict:
    """Positive control: a path that DOES exist must not match the 404 shape.

    Calibration can only be trusted if it still lets a real file through.
    This requests /robots.txt, which is present on essentially every site,
    and confirms it is classified as present. If it is not, the calibration
    is suppressing real findings and the run says so instead of reporting a
    clean site.

    This is the check that catches an http:// site argument on a host that
    redirects to HTTPS: there, every real file 301s exactly like a missing
    one, robots.txt is classified absent, and the whole report would
    otherwise come back empty with exit code 0.

    A site with no robots.txt cannot prove anything with it, so two more
    files that exist on every WordPress install are tried before the control
    is recorded as not run. "Not run" is its own state: an earlier version
    recorded a 404 on robots.txt as trustworthy and said nothing, which is
    a control that silently did not happen.
    """
    result = {"control_path": "", "status": 0, "no_redirect_status": 0,
              "classified_present": False, "trustworthy": True,
              "ran": False, "note": "", "robots_disallow": []}
    for path in CONTROL_PATHS:
        status, _, body = fetch(f"{site}{path}")
        no_redirect_status, _ = fetch_no_redirect(f"{site}{path}")
        if path == "/robots.txt" and status == 200:
            result["robots_disallow"] = re.findall(
                r"(?im)^disallow:\s*(\S+)", body)[:40]
        if status != 200:
            continue
        exposed = path_is_exposed(path, status, body, missing,
                                  no_redirect_status)
        result.update({
            "control_path": path, "status": status, "ran": True,
            "no_redirect_status": no_redirect_status,
            "classified_present": bool(exposed),
            "trustworthy": bool(exposed),
            "note": ("" if exposed else
                     f"A file known to exist ({path}) was classified as "
                     "absent, so the calibration is hiding real findings."),
        })
        return result
    result["note"] = ("No control file answered (robots.txt, core jQuery, "
                      "wp-login.php), so the calibration could not be proved "
                      "to let real files through. Path findings are reported "
                      "but unproven.")
    return result


def content_matches(path: str, body: str) -> Optional[bool]:
    """Does the body look like the file this path claims to be?

    Returns None when no rule exists for the path, True when the expected
    content is there, False when a 200 came back with something else. The
    empty body is the caller's decision, not this function's.
    """
    low = body.lower()
    if path.endswith(".zip"):
        return body.startswith("PK")
    if path.endswith(".gz") or path.endswith(".tgz"):
        return body.startswith("\x1f")
    if path.endswith(".sql"):
        return any(m in low for m in SQL_MARKERS)
    markers = CONTENT_MARKERS.get(path)
    if markers is None:
        return None
    return any(m in low for m in markers)


def path_is_exposed(path: str, status: int, body: str,
                    missing: Optional[Dict],
                    no_redirect_status: Optional[int] = None) -> bool:
    """Does this response mean the path is actually readable?

    A 200 is not enough on its own. WordPress serves its themed 404 with a
    200 on some setups, a directory with an index.php returns an empty 200
    that exposes nothing, and a site that bounces unknown paths to the
    homepage answers every probe with a real page.
    """
    # A redirect is not a file. Sites that bounce unknown paths to the
    # homepage answer every probe with a 3xx, and following it lands on a
    # real 200 full of homepage content.
    if (no_redirect_status is not None and 300 <= no_redirect_status < 400
            and missing and missing.get("redirects_unknown_paths")):
        return False
    if status != 200:
        return False

    low = body.lower()

    # The installer and setup wizard answer on every WordPress site. They are
    # only a finding if they still offer to install; "Already Installed" is
    # the safe response and reporting it sends a client a false positive. So
    # is a WAF page served with a 200, which is why a positive marker of the
    # install form is required rather than the mere absence of the refusal.
    if path in INSTALLER_PATHS:
        if "already installed" in low or "already configured" in low:
            return False
        return any(m in low for m in INSTALLER_MARKERS)

    # Same fingerprint as a path that cannot exist means this is the site's
    # 404 template, whatever status it carried.
    if missing and missing.get("stable") and missing.get("fingerprint"):
        # Strip the requested path first. A 404 template that echoes what was
        # asked for produces a different body for every probe, and comparing
        # those raw would classify the site's own not-found page as a file.
        if body_fingerprint(body, path.lstrip("/")) == missing["fingerprint"]:
            return False

    if ("page not found" in low or "nothing found" in low
            or "error 404" in low or "404 not found" in low):
        return False

    if path.endswith("/"):
        # A real directory listing names itself. An empty 200 is index.php
        # doing its job, which is the safe outcome.
        return "index of /" in low

    # An empty 200 on a file path is a real, empty file. Reporting it costs
    # one INFO line; not reporting it hides a truncated dump. check_paths()
    # keeps empties out of the severity bands for the same reason.
    if not body.strip():
        return True

    # Where the file has a known shape, the body has to have it. A 200 with
    # the wrong content is a block page or a soft 404 the fingerprint missed.
    verdict = content_matches(path, body)
    if verdict is False:
        return False
    return True


def path_verdict(path: str, status: int, body: str, exposed: bool,
                 no_redirect_status: Optional[int] = None) -> str:
    """A few words for the appendix: what happened to this probe.

    "not readable" used to cover a timeout as well, which read as "checked
    and clean" for a path that was never checked at all.
    """
    if status == 0:
        return "no answer"
    if status == 429:
        return "rate limited"
    if exposed:
        return "readable" if body.strip() else "empty"
    if no_redirect_status and 300 <= no_redirect_status < 400:
        return "redirected (not a file)"
    if (status == 200 and body.strip() and not path.endswith("/")
            and content_matches(path, body) is False):
        return "answered, unexpected content"
    return "not readable"


def _readme_stable_tag(site: str, slug: str) -> str:
    """The Stable tag from a plugin's own readme.txt, or "".

    Independent of the page cache and of asset URLs, so it cross-checks the
    version read from ?ver= and supplies one where no asset carried it. It is
    a second witness, not the authority: authors forget to bump it, and
    "trunk" is a legal value. Both are rejected here.
    """
    status, _, body = fetch(f"{site}/wp-content/plugins/{slug}/readme.txt",
                            max_bytes=65_536)
    if status != 200 or "<html" in body[:2000].lower():
        return ""
    match = re.search(r"(?im)^\s*stable tag:\s*([0-9][0-9a-zA-Z.\-]*)\s*$", body)
    return match.group(1).strip() if match else ""


def _theme_style(site: str, slug: str) -> Dict:
    """Version, name and parent theme from a theme's style.css header.

    The homepage names the theme directory but never its version, so without
    this no theme vulnerability can ever be matched.
    """
    status, _, body = fetch(f"{site}/wp-content/themes/{slug}/style.css",
                            max_bytes=65_536)
    out = {"status": status, "version": "", "name": "", "parent": ""}
    if status != 200 or "<html" in body[:2000].lower():
        return out
    head = body[:8000]
    for key, field in (("version", r"Version"), ("name", r"Theme Name"),
                       ("parent", r"Template")):
        match = re.search(rf"(?im)^\s*\*?\s*{field}:\s*(.+?)\s*$", head)
        if match:
            out[key] = match.group(1).strip()
    if not re.match(r"^\d", out["version"]):
        out["version"] = ""
    return out


def calibration_is_ambiguous(missing: Optional[Dict]) -> bool:
    """True when the site's missing-path answer could not be pinned down.

    An unstable signature means path findings cannot be trusted in either
    direction. The findings engine marks them UNVERIFIED rather than
    reporting them as real or dropping them, because both of those are ways
    of lying about what was measured.
    """
    if not missing:
        return False
    if missing.get("stable"):
        return False
    # A site that cleanly 404s does not need a stable body fingerprint: the
    # status code alone settles every probe.
    return missing.get("status") == 200


###############################################################################
# RUN CONTEXT
###############################################################################

class RunContext:
    """Everything the collect/check/render stages share for one run."""

    def __init__(self, run_dir: Path, args):
        self.run_dir = run_dir
        self.args = args
        self.manifest_path = run_dir / "manifest.json"
        self.manifest: Dict = {"modules": {}, "preflight": [], "meta": {}}
        if self.manifest_path.is_file():
            try:
                self.manifest = json.loads(
                    self.manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                print_warning("manifest.json unreadable; starting a fresh one")
        self.site: str = (args.site or "").rstrip("/") \
            or self.manifest["meta"].get("site", "")
        self._cache: Dict[str, object] = {}

    # -- persistence ------------------------------------------------------

    def save(self):
        self.manifest["meta"]["site"] = self.site
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2), encoding="utf-8")

    def module_status(self, key: str) -> str:
        return self.manifest["modules"].get(key, {}).get("status", "")

    def set_module(self, key: str, status: str, rows: int = 0, note: str = ""):
        self._cache.pop(key, None)
        self.manifest["modules"][key] = {
            "status": status, "rows": rows, "note": note,
            "completed_at": datetime.now().isoformat(timespec="seconds")}
        self.save()

    def json_path(self, key: str) -> Path:
        return self.run_dir / f"{key}.json"

    def write(self, key: str, data):
        self.json_path(key).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")

    def data(self, key: str):
        """Parsed module output, cached. Returns None when the module has no
        file, which is how a check tells "not collected" from "collected and
        empty"."""
        if key not in self._cache:
            path = self.json_path(key)
            if not path.is_file():
                self._cache[key] = None
            else:
                try:
                    self._cache[key] = json.loads(
                        path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    self._cache[key] = None
        return self._cache[key]

    def usable(self, key: str) -> bool:
        return self.module_status(key) in ("ok", "empty", "partial")

    @property
    def missing_signature(self) -> Optional[Dict]:
        data = self.data("calibration")
        return data.get("signature") if data else None

    def rest_url(self, route: str) -> str:
        """A REST route as this site serves it.

        /wp-json/ needs pretty permalinks. Without them WordPress still
        answers on /?rest_route=/, and a tool that only knows the first form
        reports an empty REST surface on exactly the sites least likely to
        have been hardened. collect_rest() records which form works.
        """
        base = self.manifest["meta"].get("rest_base", "/wp-json")
        route = route if route.startswith("/") else "/" + route
        if base == "/wp-json":
            return self.site + "/wp-json" + route
        path, _, query = route.partition("?")
        return (self.site + "/?rest_route=" + urllib.parse.quote(path, safe="/")
                + (f"&{query}" if query else ""))


###############################################################################
# COLLECT
###############################################################################

def collect_calibration(ctx: RunContext) -> Tuple[str, int, str]:
    """Learn the site's missing-path signature and prove it lets real files
    through. Everything in the paths module depends on this, so it runs
    first and its result is stated in the report rather than assumed."""
    signature = calibrate_missing(ctx.site)
    control = verify_calibration(ctx.site, signature)
    ctx.write("calibration", {"signature": signature, "control": control})
    if not control["trustworthy"]:
        return "error", 0, control["note"]
    if not control.get("ran"):
        return "partial", 1, control["note"]
    if calibration_is_ambiguous(signature):
        return ("partial", 1,
                "the site answers missing paths with a 200 whose content "
                "changes between requests, so path findings could not be "
                "confirmed and are reported as unverified")
    if signature["redirects_unknown_paths"]:
        return ("ok", 1, "site redirects unknown paths; findings calibrated "
                         "against that")
    return "ok", 1, ""


def _site_named_backups(site: str) -> List[Tuple[str, str, str]]:
    """Backup filenames derived from the site's own name.

    example.com.zip and example.sql are the commonest real backup names and
    cannot come from a static list. Content is checked by content_matches(),
    so a soft 404 cannot satisfy these.
    """
    host = urllib.parse.urlparse(site).netloc.lower().split(":")[0]
    bare = host[4:] if host.startswith("www.") else host
    stem = bare.split(".")[0]
    names = []
    for base in dict.fromkeys([bare, stem]):
        names.append((f"/{base}.zip", "CRITICAL",
                      "a site backup archive named after the site"))
        names.append((f"/{base}.sql", "CRITICAL",
                      "a database dump named after the site"))
    names.append(("/wp-content.zip", "CRITICAL",
                  "an archive of wp-content, which holds every upload and plugin"))
    names.append(("/latest.sql", "CRITICAL", "a database dump"))
    return names


def _robots_probe_rows(disallow: List[str]) -> List[Tuple[str, str, str]]:
    """robots.txt Disallow entries worth requesting.

    The owner's own list of paths they did not want indexed, and public.
    Attackers read it as a shortlist. Wildcards, the default /wp-admin/ line
    and core directories are skipped; the rest are probed at INFO severity
    with copy that says what they are.
    """
    out = []
    for raw in disallow:
        path = raw.strip()
        if (not path.startswith("/") or any(c in path for c in "*$?")
                or path in ("/", "/wp-admin/", "/wp-admin")
                or path.startswith(("/wp-admin", "/wp-includes", "/wp-login"))
                or len(path) > 120):
            continue
        out.append((path, "INFO",
                    "listed as Disallow in robots.txt, so the site owner did "
                    "not want it indexed"))
        if len(out) >= 20:
            break
    return out


def collect_paths(ctx: RunContext) -> Tuple[str, int, str]:
    """Request every path in PROBE_PATHS, redirect-aware and calibrated."""
    missing = ctx.missing_signature
    calibration = ctx.data("calibration") or {}
    disallow = (calibration.get("control") or {}).get("robots_disallow", [])
    probed = {p for p, _, _ in PROBE_PATHS}
    extra = [t for t in _site_named_backups(ctx.site) if t[0] not in probed]
    probed |= {p for p, _, _ in extra}
    extra += [t for t in _robots_probe_rows(disallow) if t[0] not in probed]
    rows = []
    for path, severity, why in PROBE_PATHS + extra:
        if shutdown_requested:
            ctx.write("paths", rows)
            return "partial", len(rows), "stopped by the operator"
        url = ctx.site + path
        no_redirect_status, _ = fetch_no_redirect(url)
        status, hdrs, body = fetch(url)
        exposed = path_is_exposed(path, status, body, missing,
                                  no_redirect_status)
        rows.append({
            "path": path,
            "url": url,
            "severity": severity,
            "why": why,
            "status": status,
            "no_redirect_status": no_redirect_status,
            "bytes": len(body),
            "content_type": hdrs.get("content-type", ""),
            "exposed": exposed,
            "verdict": path_verdict(path, status, body, exposed,
                                    no_redirect_status),
            "error": hdrs.get("_error", ""),
        })
    ctx.write("paths", rows)
    unanswered = [r for r in rows if r["verdict"] in ("no answer", "rate limited")]
    if unanswered:
        # A probe that never got an answer was not checked. Saying "ok" here
        # would let the appendix read those rows as clean.
        return ("partial", len(rows),
                f"{len(unanswered)} path(s) got no answer or were rate "
                "limited, so they were not checked: "
                + ", ".join(r["path"] for r in unanswered[:8])
                + ("..." if len(unanswered) > 8 else ""))
    return "ok", len(rows), ""


def collect_headers(ctx: RunContext) -> Tuple[str, int, str]:
    """Security headers, leaky headers and cookie flags from the homepage."""
    status, hdrs, body = fetch(ctx.site + "/")
    if status == 0:
        ctx.write("headers", {})
        return "error", 0, hdrs.get("_error", "homepage unreachable")
    edge = edge_identity(hdrs, body)
    cookies = []
    # Multiple cookies arrive newline-joined from _headers(). Each one is
    # then "name=value; attr; attr".
    for chunk in hdrs.get("set-cookie", "").split("\n"):
        if "=" not in chunk:
            continue
        low = chunk.lower()
        cookies.append({
            "name": chunk.split("=", 1)[0].strip(),
            "secure": "secure" in low,
            "httponly": "httponly" in low,
            "samesite": "samesite" in low,
        })
    generators = re.findall(r'<meta name="generator" content="([^"]+)"', body)

    # Core version, from every free source, because the generator tag is the
    # first thing a hardening guide removes and the homepage may be a cached
    # copy built before the last update. Sources are kept apart so a
    # disagreement is visible rather than averaged away.
    core_versions: Dict[str, str] = {}
    for g in generators:
        if g.lower().startswith("wordpress"):
            core_versions["generator"] = re.sub(r"^wordpress\s*", "", g,
                                                flags=re.I).strip()
    # Only the core files that are enqueued with $wp_version. jQuery and the
    # other bundled libraries carry their own numbers, and the first version
    # of this read "3.4.1" off jquery-migrate and reported it as a second
    # opinion on the core version.
    includes = re.findall(
        r"/wp-includes/(?:js/wp-emoji-release\.min\.js|js/wp-embed\.min\.js"
        r"|css/dist/block-library/style\.min\.css|css/classic-themes\.min\.css"
        r")\?ver=(\d[\d.]*\d)", body)
    if includes:
        core_versions["wp-includes assets"] = max(
            set(includes), key=includes.count)
    if status == 200 and not edge["challenged"]:
        # Same page, cache-busted, generator only. If this disagrees with the
        # first reading the cached copy is stale and the report says so.
        _, _, fresh = fetch(f"{ctx.site}/?nc={uuid.uuid4().hex[:8]}")
        for g in re.findall(r'<meta name="generator" content="([^"]+)"', fresh):
            if g.lower().startswith("wordpress"):
                core_versions["generator (cache-busted)"] = re.sub(
                    r"^wordpress\s*", "", g, flags=re.I).strip()
        f_status, _, feed = fetch(ctx.site + "/feed/")
        if f_status == 200:
            match = re.search(r"<generator>[^<]*\?v=([^<\s]+)</generator>", feed)
            if match:
                core_versions["feed"] = match.group(1).strip()

    themes = sorted(set(re.findall(r"/wp-content/themes/([^/\"']+)/", body)))
    theme_info = {}
    for slug in themes:
        if shutdown_requested:
            break
        theme_info[slug] = _theme_style(ctx.site, slug)

    # Is this WordPress at all? Without this the WordPress modules on a
    # non-WordPress site all came back "empty, the safer state", which reads
    # as a hardened install. The platform-neutral checks (headers, TLS,
    # cookies, mail DNS, generic paths) still apply to any site.
    signals = []
    if "/wp-content/" in body:
        signals.append("wp-content paths")
    if "/wp-includes/" in body:
        signals.append("wp-includes paths")
    if any(g.lower().startswith("wordpress") for g in generators):
        signals.append("generator tag")
    if "api.w.org" in hdrs.get("link", "") or "api.w.org" in body:
        signals.append("REST discovery link")
    if not signals and status == 200 and not edge["challenged"]:
        # A headless front end shows none of the above. wp-login.php is the
        # one WordPress URL that survives a decoupled theme.
        l_status, _, login = fetch(ctx.site + "/wp-login.php", max_bytes=65_536)
        if l_status == 200 and "wp-login" in login.lower() and "log in" in login.lower():
            signals.append("wp-login.php")
    ctx.manifest["meta"]["platform"] = {
        "wordpress": bool(signals), "signals": signals,
        "decided": status == 200 and not edge["challenged"]}
    ctx.save()

    # Resources loaded over plain HTTP from an HTTPS page. Browsers block the
    # active ones outright and mark the page "not secure" for the rest.
    mixed = []
    if ctx.site.startswith("https://"):
        for tag, attr in re.findall(
                r"<(script|img|iframe|source|video|audio|link)\b[^>]*?\b(?:src|href)"
                r"=[\"'](http://[^\"']+)", body, flags=re.I):
            mixed.append({"tag": tag.lower(), "url": attr})
        # <link> only counts when it is a stylesheet; canonical, pingback and
        # alternate links are not fetched by the browser.
        mixed = [m for m in mixed if m["tag"] != "link"
                 or re.search(r"<link\b[^>]*rel=[\"'][^\"']*stylesheet[^\"']*[\"'][^>]*"
                              + re.escape(m["url"]), body, flags=re.I)]
        mixed = mixed[:20]

    data = {
        "platform": ctx.manifest["meta"]["platform"],
        "mixed_content": mixed,
        "status": status,
        "headers": {k: v for k, v in hdrs.items() if not k.startswith("_")},
        "missing": [h for h, _, _ in SECURITY_HEADERS if h not in hdrs],
        "leaky": {h: hdrs[h] for h in LEAKY_HEADERS if h in hdrs},
        "cookies": cookies,
        "generators": generators,
        "core_versions": core_versions,
        "theme": themes,
        "theme_info": theme_info,
        "homepage_plugins": sorted(set(re.findall(
            r"/wp-content/plugins/([^/\"']+)/", body))),
        "edge": edge["edge"],
        "challenged": edge["challenged"],
    }
    ctx.write("headers", data)
    if edge["challenged"] or status != 200:
        # Reading security headers off a block page grades the WAF, not the
        # site, and every module after this one is reading the same wall.
        return ("error", 1,
                f"the homepage answered HTTP {status} with a "
                f"{'challenge or block page' if edge['challenged'] else 'non-success response'}"
                + (f" from {', '.join(edge['edge'])}" if edge["edge"] else "")
                + "; this run is seeing the edge, not the site")
    return "ok", 1, (f"in front: {', '.join(edge['edge'])}" if edge["edge"] else "")


def collect_rest(ctx: RunContext) -> Tuple[str, int, str]:
    """The REST index is a better plugin inventory than the page HTML.

    A plugin appears in page HTML only if it loads an asset on the page you
    fetched; any plugin with an API registers a namespace regardless. On one
    live site the homepage named 4 plugins and /wp-json/ revealed 10.

    Route methods are read from the index. No route is called: finding out
    what a POST endpoint accepts means submitting, which this tool does not
    do.
    """
    attempts = []
    data = None
    for base, url in (("/wp-json", ctx.site + "/wp-json/"),
                      ("/?rest_route=", ctx.site + "/?rest_route=/")):
        status, hdrs, data = fetch_json(url, max_bytes=REST_INDEX_MAX_BYTES)
        attempts.append({"base": base, "status": status,
                         "truncated": bool(hdrs.get("_truncated")),
                         "json": isinstance(data, dict)})
        if isinstance(data, dict) and "routes" in data:
            ctx.manifest["meta"]["rest_base"] = base
            ctx.save()
            break
        data = None
    if not isinstance(data, dict):
        ctx.write("rest", {"attempts": attempts})
        first = attempts[0]
        if first["truncated"]:
            return ("error", 0,
                    f"the REST index is larger than {REST_INDEX_MAX_BYTES:,} "
                    "bytes and could not be read in full")
        if first["status"] == 200:
            # A 200 that is not JSON is a challenge page or an HTML page at
            # /wp-json/. Neither is "safer"; the API was not readable by this
            # run and may be readable by a browser.
            return ("error", 0,
                    "/wp-json/ and /?rest_route=/ both answered HTTP 200 "
                    "without JSON, so the REST API could not be read; a "
                    "challenge page or a non-WordPress front end is the "
                    "usual cause")
        if any(a["status"] in (429, 503, 0) for a in attempts):
            return ("error", 0,
                    "the REST index could not be read: HTTP "
                    + "/".join(str(a["status"]) for a in attempts)
                    + " (rate limited or unreachable). This is not the safer "
                    "state; the endpoint was not examined")
        return ("empty", 0,
                f"/wp-json/ returned HTTP {first['status']} and "
                f"/?rest_route=/ returned HTTP {attempts[-1]['status']}, so "
                "the REST index is not anonymously readable, which is the "
                "safer state")
    routes = data.get("routes", {}) or {}
    namespaces = data.get("namespaces", []) or []
    write_routes = []
    for route, spec in routes.items():
        methods = sorted({m for ep in spec.get("endpoints", [])
                          for m in ep.get("methods", [])})
        if set(methods) - {"GET", "HEAD"}:
            write_routes.append({"route": route, "methods": methods})
    third_party = [n for n in namespaces if n not in CORE_NAMESPACES]

    # A plugin known only from its namespace has no asset URL to read a
    # version from. Where the namespace maps to a known directory slug, its
    # own readme.txt supplies one. Only slugs the site itself advertised are
    # requested; nothing is guessed.
    namespace_plugins: Dict[str, Dict] = {}
    for ns in third_party:
        if shutdown_requested:
            break
        name, slug = NAMESPACE_PLUGINS.get(ns, (ns, None))
        if not slug or slug in namespace_plugins:
            continue
        tag = _readme_stable_tag(ctx.site, slug)
        namespace_plugins[slug] = {"name": name, "namespace": ns,
                                   "readme_version": tag}
    ctx.write("rest", {
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "home": data.get("home", ""),
        "base": ctx.manifest["meta"].get("rest_base", "/wp-json"),
        "attempts": attempts,
        "route_count": len(routes),
        "namespaces": namespaces,
        "third_party": third_party,
        "namespace_plugins": namespace_plugins,
        "write_routes": write_routes,
        "authentication": data.get("authentication", {}),
    })
    note = ""
    if ctx.manifest["meta"].get("rest_base") != "/wp-json":
        note = "read via /?rest_route=/ because /wp-json/ did not answer"
    return "ok", len(routes), note


def collect_users(ctx: RunContext) -> Tuple[str, int, str]:
    """Author names leak from four routes, not one.

    /wp-json/wp/v2/users is the one people close. ?author=N redirects to
    /author/<slug>/ and that slug is usually, but not always, the login name;
    the users sitemap and oEmbed's author_name publish display names. All
    four are read here, and oEmbed is reported only when author_name differs
    from provider_name, since most sites return the site name there and
    disclose nothing.
    """
    result: Dict = {"rest": [], "author_redirect": [], "sitemap": [],
                    "oembed": ""}

    status, hdrs, data = fetch_json(ctx.rest_url("/wp/v2/users?per_page=100"))
    result["rest_status"] = status
    result["rest_total"] = hdrs.get("x-wp-total", "")
    if isinstance(data, list):
        for user in data:
            result["rest"].append({
                "id": user.get("id"),
                "name": user.get("name", ""),
                # This is user_nicename, NOT user_login. WordPress seeds it
                # from the login at registration, but it is editable
                # independently and importers commonly set it from the
                # display name. Calling it a login needs a login-error
                # oracle, which is a POST, so this tool never claims it.
                "slug": user.get("slug", ""),
                "link": user.get("link", ""),
            })

    # ?author=N, redirects NOT followed, so the Location is visible.
    for n in range(1, 6):
        code, h = fetch_no_redirect(f"{ctx.site}/?author={n}")
        location = h.get("location", "")
        if 300 <= code < 400 and "/author/" in location:
            slug = location.rstrip("/").rsplit("/", 1)[-1]
            if slug:
                result["author_redirect"].append({"n": n, "slug": slug})

    status, _, body = fetch(ctx.site + "/wp-sitemap-users-1.xml")
    if status == 200 and "<loc>" in body:
        result["sitemap"] = re.findall(r"<loc>([^<]+)</loc>", body)[:100]

    status, _, data = fetch_json(ctx.rest_url(
        "/oembed/1.0/embed?url=" + urllib.parse.quote(ctx.site + "/", safe="")))
    if isinstance(data, dict):
        author = data.get("author_name", "")
        provider = data.get("provider_name", "")
        if author and author != provider:
            result["oembed"] = author

    ctx.write("users", result)
    return "ok", len(result["rest"]), ""


def collect_media(ctx: RunContext) -> Tuple[str, int, str]:
    """Walk the whole media library and compare the walk against X-WP-Total.

    Two traps live here. A short page is not the last page: WordPress filters
    items out of a page AFTER slicing it, so page 1 of a 1,250-item library
    can return 69 rows while later pages are full. Stopping on a short page
    is the obvious optimisation and it produced a report naming 2 public
    documents where there were 35.

    And the complete walk still need not reach the whole library. On one live
    site the header said 1,250 and thirteen pages returned 875. That gap is
    recorded, because "absent from the walk" is a far weaker statement than
    "absent from the library" and the difference decides whether a document
    can be found in wp-admin.
    """
    probe_status, hdrs, probe = fetch_json(
        ctx.rest_url("/wp/v2/media?per_page=1&_fields=id"))
    if probe_status != 200 or not isinstance(probe, list):
        ctx.write("media", {})
        return ("empty", 0,
                f"the media endpoint returned HTTP {probe_status}"
                + ("" if probe_status != 200 else " without JSON")
                + ", so the library is not anonymously enumerable, which is "
                "the safer state")
    try:
        reported_total = int(hdrs.get("x-wp-total", "0"))
    except ValueError:
        reported_total = 0
    header_missing = "x-wp-total" not in hdrs

    items: List[Dict] = []
    pages: List[Dict] = []
    page = 1
    stopped = ""
    while True:
        if page > MEDIA_MAX_PAGES:
            # Leaving the loop on the cap without saying so made the gap look
            # like WordPress filtering when it was this tool giving up.
            stopped = (f"stopped at the {MEDIA_MAX_PAGES}-page limit "
                       f"({MEDIA_MAX_PAGES * 100} items)")
            break
        if shutdown_requested:
            stopped = "stopped by the operator"
            break
        url = ctx.rest_url(
            f"/wp/v2/media?per_page=100&page={page}"
            "&_fields=id,date,link,source_url,mime_type,title,status")
        status, _, data = fetch_json(url)
        if status == 400:            # WordPress returns 400 past the last page
            break
        if status != 200:
            stopped = f"page {page} returned HTTP {status}"
            break
        if data is None:
            stopped = (f"page {page} did not return JSON; the host may be "
                       "serving a challenge page")
            break
        if not data:
            break
        pages.append({"page": page, "rows": len(data)})
        items.extend(data)
        page += 1

    urls = [i.get("source_url", "") for i in items]
    docs = [i for i in items
            if Path(urllib.parse.urlparse(i.get("source_url", "")).path).suffix.lower()
            in DOC_EXT]
    data = {
        "reported_total": reported_total,
        "header_missing": header_missing,
        "walked": len(items),
        "gap": max(0, reported_total - len(items)),
        "pages": pages,
        "documents": [{
            "url": d.get("source_url", ""),
            "date": (d.get("date") or "")[:10],
            "mime": d.get("mime_type", ""),
            "title": (d.get("title") or {}).get("rendered", ""),
        } for d in docs],
        "all_urls": urls,
        "stopped": stopped,
    }
    ctx.write("media", data)
    note = stopped
    if data["gap"]:
        note = (f"the walk returned {data['walked']} of the "
                f"{reported_total} items the endpoint reports; "
                f"{data['gap']} are not covered"
                + (f"; {stopped}" if stopped else
                   "; WordPress filtered them out after paging"))
    elif header_missing:
        note = ("the endpoint sent no X-WP-Total header, so the walk cannot "
                "be compared against the library size"
                + (f"; {stopped}" if stopped else ""))
    return ("partial" if stopped else "ok"), len(items), note


def collect_documents(ctx: RunContext) -> Tuple[str, int, str]:
    """Confirm each document resolves, and flag filenames worth opening.

    Also takes --url for a file found some other way, such as through a
    search engine. That is how the files an older install left behind get
    into the report at all: they are on disk, readable by URL, absent from
    the media library, and invisible in wp-admin.
    """
    media = ctx.data("media") or {}
    library = {u.split("?")[0] for u in media.get("all_urls", [])}
    candidates = [d["url"] for d in media.get("documents", [])]
    # --url is a command-line flag, so a resumed run would otherwise drop the
    # extras and quietly produce different findings from the same run
    # directory. Merge with whatever the run already recorded and persist.
    known = ctx.manifest["meta"].get("extra_urls", [])
    merged = list(dict.fromkeys(known + list(ctx.args.url or [])))
    ctx.manifest["meta"]["extra_urls"] = merged
    ctx.save()
    extra = [u if u.startswith("http") else ctx.site + u for u in merged]
    if ctx.data("media") is None and not extra:
        # Nothing to confirm. "ok, 0 rows" here read as "no documents" when
        # the media module had been skipped and no document was ever listed.
        ctx.write("documents", [])
        return ("skipped", 0, "depends on the media module, which did not "
                              "run, and no --url was given")
    rows = []
    for url in candidates + [u for u in extra if u not in candidates]:
        if shutdown_requested:
            break
        status, hdrs, _ = fetch(url, method="HEAD")
        if status in (405, 501):
            # Some hosts refuse HEAD. A GET capped at one byte of body is
            # the same question asked politely.
            status, hdrs, _ = fetch(url, max_bytes=1)
        name = urllib.parse.urlparse(url).path.lower()
        rows.append({
            "url": url,
            "status": status,
            "bytes": hdrs.get("content-length", ""),
            "content_type": hdrs.get("content-type", ""),
            "in_library": url.split("?")[0] in library,
            "sensitive": sensitive_hits(name),
        })
    ctx.write("documents", rows)
    return "ok", len(rows), ""


def collect_assets(ctx: RunContext) -> Tuple[str, int, str]:
    """Read plugin versions from asset query strings, across the sitemap.

    Two traps, both of which have produced a wrong version reading.

    A cached page lies. Asset URLs carry the version, but an edge cache
    serves whatever was cached when the page was built, so every request
    here carries a throwaway query string and the cache header is recorded
    beside the number.

    And one page is not the site. A plugin's assets load only on pages that
    use it. Reading /contact-us/ alone and concluding a form plugin runs on
    one page understated the public surface of a vulnerable plugin by a
    factor of forty on a live site.
    """
    urls = _sitemap_urls(ctx.site)[:ASSET_MAX_PAGES]
    if not urls:
        urls = [ctx.site + "/"]
    plugins: Dict[str, Dict] = {}
    page_rows = []
    failed: Dict[int, int] = {}
    for url in urls:
        if shutdown_requested:
            break
        bust = f"{'&' if '?' in url else '?'}nc={uuid.uuid4().hex[:8]}"
        status, hdrs, body = fetch(url + bust)
        if status != 200:
            # Skipping silently hid a WAF that started answering 429 thirty
            # pages in; the sweep then covered half the site and said so
            # nowhere.
            failed[status] = failed.get(status, 0) + 1
            continue
        cache = (hdrs.get("x-kinsta-cache") or hdrs.get("x-cache")
                 or hdrs.get("cf-cache-status") or hdrs.get("x-litespeed-cache")
                 or "")
        found = re.findall(
            r"/wp-content/plugins/([^/\"']+)/[^\"']*?\?ver=([0-9][0-9a-zA-Z.\-]*)",
            body)
        seen_here = set()
        # A plugin whose only version string was rejected above is still
        # installed. Recording the slug with no version keeps it in the
        # inventory and keeps it eligible for the currency and withdrawal
        # checks, which need no version at all.
        for slug, _version in found:
            plugins.setdefault(slug, {"versions": {}, "pages": 0})
        for slug, version in found:
            # A hash-shaped "version" is a cache-buster, not a release. So is
            # a bare Unix timestamp: Complianz served ?ver=1781763570 on a
            # live site, which passed every check here and was then compared
            # against real release numbers as though it were one.
            if (len(version) > 20 or re.fullmatch(r"[0-9a-f]{16,}", version)
                    or re.fullmatch(r"1[0-9]{9}", version)):
                continue
            seen_here.add((slug, version))
            entry = plugins.setdefault(slug, {"versions": {}, "pages": 0})
            entry["versions"].setdefault(version, 0)
            entry["versions"][version] += 1
        for slug in {s for s, _ in found}:
            plugins[slug]["pages"] += 1
        page_rows.append({
            "url": url,
            "cache": cache,
            "plugins": sorted({f"{s} {v}" for s, v in seen_here}),
        })
    # readme.txt as a second witness. It is independent of the page cache and
    # of the ?ver= string, and it is the only version source for a plugin
    # whose assets carry a cache-buster instead of a release number.
    for slug, entry in plugins.items():
        if shutdown_requested:
            break
        tag = _readme_stable_tag(ctx.site, slug)
        entry["readme_version"] = tag
        if tag and not entry["versions"]:
            entry["versions"][tag] = 0
    data = {
        "pages_checked": len(page_rows),
        "pages_in_sitemap": len(urls),
        "pages_failed": failed,
        "cache_states": sorted({r["cache"] for r in page_rows if r["cache"]}),
        "plugins": {slug: {
            "versions": sorted(v["versions"]),
            "readme_version": v.get("readme_version", ""),
            "pages": v["pages"],
        } for slug, v in sorted(plugins.items())},
        "pages": page_rows,
    }
    ctx.write("assets", data)
    cached = [r for r in page_rows
              if r["cache"].upper() in ("HIT", "CACHED")]
    notes = []
    if cached:
        notes.append(f"{len(cached)} page(s) were served from cache despite "
                     "the cache-busting parameter, so their version numbers "
                     "may be stale")
    if failed:
        notes.append(f"{sum(failed.values())} of {len(urls)} page(s) did not "
                     "answer 200 and were not read ("
                     + ", ".join(f"HTTP {s} x{n}" for s, n in sorted(failed.items()))
                     + ")")
    status = "partial" if failed and sum(failed.values()) * 4 > len(urls) else "ok"
    return status, len(page_rows), "; ".join(notes)


def _sitemap_urls(site: str) -> List[str]:
    """Every page URL the site publishes, from either sitemap convention."""
    out: List[str] = []
    for name in ("/sitemap_index.xml", "/wp-sitemap.xml", "/sitemap.xml"):
        status, _, body = fetch(site + name)
        if status != 200 or "<loc>" not in body:
            continue
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)
        if "sitemapindex" in body[:2000].lower():
            # Prefer page sitemaps: they are where forms and plugin assets
            # live. Post archives add hundreds of URLs and little signal.
            children = sorted(locs, key=lambda u: (0 if "page" in u else 1, u))
            for child in children[:6]:
                s2, _, b2 = fetch(child)
                if s2 == 200:
                    out.extend(re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", b2))
        else:
            out.extend(locs)
        if out:
            break
    seen = set()
    unique = []
    for u in out:
        if u not in seen and not u.endswith((".xml", ".jpg", ".png")):
            seen.add(u)
            unique.append(u)
    return unique


def collect_vulns(ctx: RunContext) -> Tuple[str, int, str]:
    """Look up every detected component against two public APIs.

    Reads only what earlier modules already collected - no new fingerprinting
    happens here - and asks two questions per component: what does
    wordpress.org currently ship, and does wpvulnerability.net know of a
    vulnerability covering the version we saw.

    Three limits are recorded rather than papered over:

      1. Only components with a VERSION can be matched against a
         vulnerability range. A plugin known from its REST namespace but
         carrying no asset URL gets a currency lookup and nothing more.
      2. The asset sweep can see more than one version for a plugin across
         the site. Every version seen is tested, and the report names which
         one matched, because "it is patched on the pages we happened to
         read" is not a clean result.
      3. A slug that wpvulnerability does not recognise is recorded as NOT
         COVERED. Its response for an unknown plugin is nearly identical to
         its response for a clean one, so treating absence as safety would
         hand a client a green tick nobody earned.
    """
    assets = ctx.data("assets") or {}
    headers = ctx.data("headers") or {}
    rest = ctx.data("rest") or {}
    plugins: Dict[str, Dict] = {
        slug: dict(info, source="assets")
        for slug, info in assets.get("plugins", {}).items()}
    # Plugins known only from a REST namespace, with the version their own
    # readme.txt gave. This is where the security and caching plugins live:
    # they load nothing on the front end and never appear in asset URLs.
    for slug, info in (rest.get("namespace_plugins") or {}).items():
        if slug in plugins:
            continue
        tag = info.get("readme_version", "")
        plugins[slug] = {"versions": [tag] if tag else [], "pages": 0,
                         "readme_version": tag, "source": "rest namespace"}
    theme_slugs = headers.get("theme", []) or []
    theme_info = headers.get("theme_info", {}) or {}

    data: Dict = {
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "sources": {
            "currency": "api.wordpress.org (first-party plugin/theme/core directory)",
            "vulnerabilities": "wpvulnerability.net (aggregate of CVE, EUVD, JVN, "
                               "Patchstack, Wordfence, WPScan)",
        },
        "core": {}, "plugins": {}, "themes": {},
    }

    # Core. Every source the headers module found is kept; the generator tag
    # is preferred when present, and a disagreement between sources is
    # recorded because it means one of them is a cached copy.
    releases = _wporg(WPORG_STABLE_CHECK) or {}
    latest_core = next((v for v, state in releases.items() if state == "latest"), "")
    sources: Dict[str, str] = dict(headers.get("core_versions") or {})
    if not sources:
        generator = next((g for g in headers.get("generators", [])
                          if g.lower().startswith("wordpress")), "")
        if generator:
            sources["generator"] = re.sub(r"^wordpress\s*", "", generator,
                                          flags=re.I).strip()
    # The asset reading only corroborates; it never stands alone. On its own it
    # once produced "WordPress 3.7.1 has 450 published vulnerabilities" for a
    # site on 7.x, because 3.7.1 was jQuery's version. The generator tag and
    # the feed are written by WordPress itself.
    detected_core = ""
    for key in ("generator (cache-busted)", "generator", "feed"):
        if sources.get(key):
            detected_core = sources[key]
            break
    distinct = sorted({v for v in sources.values() if v})
    core: Dict = {"detected": detected_core, "latest": latest_core,
                  "sources": sources,
                  "sources_disagree": len(distinct) > 1,
                  "releases_listed": len(releases),
                  "majors": sorted({".".join(v.split(".")[:2])
                                    for v in releases if version_ordered(v)},
                                   key=version_key)}
    if detected_core and latest_core and version_ordered(detected_core):
        floor = version_key(detected_core)
        core["releases_behind"] = sum(
            1 for v in releases if version_ordered(v) and version_key(v) > floor)
        lookup = _wpvuln("core", detected_core)
        core["covered"] = lookup["covered"]
        core["lookup_error"] = lookup["error"]
        # No range matching here: /core/<version>/ returns the vulnerabilities
        # affecting THAT version, and its records carry no operator block.
        # Running them through the plugin matcher marked all 32 undecidable
        # and reported a vulnerable core as clean.
        core["vulnerabilities"] = _core_rows(lookup["record"])
        core["undecidable"] = 0
    data["core"] = core

    # Plugins. Sorted so a resumed run and a fresh run produce the same file.
    for slug, info in sorted(plugins.items()):
        if shutdown_requested:
            break
        versions = [v for v in info.get("versions", []) if version_ordered(v)]
        entry: Dict = {"detected_versions": info.get("versions", []),
                       "readme_version": info.get("readme_version", ""),
                       "source": info.get("source", "assets"),
                       "pages": info.get("pages", 0)}
        # readme.txt disagreeing with the asset URLs means one of them is
        # stale. Both are tested, and the report names the disagreement.
        readme = entry["readme_version"]
        if readme and version_ordered(readme) and readme not in versions:
            entry["version_conflict"] = True
            versions.append(readme)
        entry["wporg"] = _currency(WPORG_PLUGIN_API.format(slug=slug), versions)
        lookup = _wpvuln("plugin", slug)
        entry["covered"] = lookup["covered"]
        entry["lookup_error"] = lookup["error"]
        entry["total_records"] = len(lookup["record"].get("vulnerability") or [])
        matched: List[Dict] = []
        undecidable = 0
        for version in versions:
            rows, skipped = _vuln_rows(lookup["record"], version)
            undecidable = max(undecidable, skipped)
            for row in rows:
                row = dict(row, affected_version=version)
                matched.append(row)
        # One vulnerability seen on two detected versions is one vulnerability.
        seen = set()
        entry["vulnerabilities"] = [
            row for row in sorted(matched, key=lambda r: r["score"], reverse=True)
            if not (row["name"] in seen or seen.add(row["name"]))]
        entry["undecidable"] = undecidable
        data["plugins"][slug] = entry

    # Themes. The homepage names the theme directory; style.css, read by the
    # headers module, supplies the version. Without it this is a currency and
    # coverage check only and the report says so.
    for slug in theme_slugs:
        if shutdown_requested:
            break
        style = theme_info.get(slug) or {}
        version = style.get("version", "")
        versions = [version] if version and version_ordered(version) else []
        entry = {"detected_versions": versions,
                 "theme_name": style.get("name", ""),
                 "parent": style.get("parent", ""),
                 "pages": 0,
                 "wporg": _currency(WPORG_THEME_API.format(slug=slug), versions)}
        lookup = _wpvuln("theme", slug)
        entry["covered"] = lookup["covered"]
        entry["lookup_error"] = lookup["error"]
        entry["total_records"] = len(lookup["record"].get("vulnerability") or [])
        rows: List[Dict] = []
        undecidable = 0
        if versions:
            rows, undecidable = _vuln_rows(lookup["record"], versions[0])
            rows = [dict(r, affected_version=versions[0]) for r in rows]
        entry["vulnerabilities"] = rows
        entry["undecidable"] = undecidable
        data["themes"][slug] = entry

    ctx.write("vulns", data)
    rows = len(data["plugins"]) + len(data["themes"])
    uncovered = [s for s, e in data["plugins"].items() if not e["covered"]]
    note = ""
    if uncovered:
        note = (f"{len(uncovered)} plugin(s) have no vulnerability record, "
                "which is not the same as having no vulnerabilities")
    if not rows:
        return "empty", 0, ("nothing to look up: no plugin or theme was "
                            "identified, usually because the assets module "
                            "was skipped")
    return "ok", rows, note


def _currency(url: str, versions: List[str]) -> Dict:
    """What wordpress.org currently ships for one plugin or theme.

    This is the half that needs no vulnerability database at all. A plugin
    CLOSED in the directory, or two years without a release, is a finding on
    its own, and both come from a single unauthenticated request.
    """
    payload = _wporg(url)
    if not isinstance(payload, dict) or not payload.get("slug"):
        return {"found": False,
                "note": "not in the wordpress.org directory (premium, custom, "
                        "or renamed)"}
    current = {
        "found": True,
        "name": payload.get("name") or "",
        "current_version": payload.get("version") or "",
        "last_updated": payload.get("last_updated") or "",
        "days_since_release": _days_since(payload.get("last_updated")),
        "added": payload.get("added") or "",
        "tested": payload.get("tested") or "",
        "requires_php": payload.get("requires_php") or "",
        "active_installs": payload.get("active_installs") or 0,
        # A closed plugin answers with error:"closed" and carries no version
        # or release date at all, so nothing below this line can be relied on
        # for it. reason_text is the directory's own words for the closure.
        "closed": bool(payload.get("closed")) or payload.get("error") == "closed",
        "closed_reason": (payload.get("reason_text") or payload.get("reason")
                          or payload.get("closed_reason") or ""),
        "closed_date": payload.get("closed_date") or "",
    }
    all_versions = [v for v in (payload.get("versions") or {}) if version_ordered(v)]
    current["releases_published"] = len(all_versions)
    if versions and current["current_version"]:
        oldest = min(versions, key=version_key)
        current["outdated"] = version_key(oldest) < version_key(current["current_version"])
        # Only count releases when the list demonstrably reaches the current
        # release. wordpress.org returned 11 versions topping out at 1.7 for a
        # plugin then shipping 8.0.4, and counting against that list reported
        # a plugin two majors behind as perfectly current.
        if current["current_version"] in all_versions:
            floor = version_key(oldest)
            current["releases_behind"] = sum(
                1 for v in all_versions if version_key(v) > floor)
    return current


def collect_transport(ctx: RunContext) -> Tuple[str, int, str]:
    """HTTP-to-HTTPS behaviour, TLS, CORS, XML-RPC and security.txt."""
    host = urllib.parse.urlparse(ctx.site).netloc
    data: Dict = {"host": host}

    http_status, http_hdrs = fetch_no_redirect("http://" + host + "/")
    data["http"] = {"status": http_status,
                    "location": http_hdrs.get("location", "")}

    data["tls"] = _tls_info(host)

    _, cors_hdrs, _ = fetch(ctx.site + "/wp-json/")
    data["cors"] = cors_hdrs.get("access-control-allow-origin", "")

    # XML-RPC without a POST: GET returns a one-line refusal when the
    # endpoint is live and a 403/404 when it is blocked. Listing the
    # available methods would need system.listMethods, which is a POST.
    status, _, body = fetch(ctx.site + "/xmlrpc.php")
    data["xmlrpc"] = {
        "status": status,
        "answering": status == 200 and "xml-rpc server accepts" in body.lower(),
    }

    status, _, body = fetch(ctx.site + "/.well-known/security.txt")
    data["security_txt"] = {"status": status,
                            "present": status == 200 and "contact" in body.lower()}

    # wp-cron.php answers on every WordPress site and returns an empty body,
    # so a 200 here discloses nothing. What matters is that anyone can trigger
    # it, repeatedly, for free. Reported as context, never as a readable file:
    # it sat in the "paths readable that should not be" table for one report
    # and read as though PHP source had been served. "Answering" means a
    # direct 200 with nothing in it; a 200 reached through a redirect, or one
    # carrying a page, is the host's block page or the homepage, and one run
    # reported a 275 KB homepage as wp-cron "returning an empty response".
    cron_direct, _ = fetch_no_redirect(ctx.site + "/wp-cron.php")
    status, _, body = fetch(ctx.site + "/wp-cron.php")
    data["wp_cron"] = {"status": status, "direct_status": cron_direct,
                       "bytes": len(body),
                       "answering": (status == 200 and cron_direct == 200
                                     and not body.strip())}

    status, _, body = fetch(ctx.site + "/robots.txt")
    data["robots"] = {"status": status,
                      "disallow": re.findall(r"(?im)^disallow:\s*(\S+)", body)[:40]}

    ctx.write("transport", data)
    return "ok", 1, ""


def _tls_info(host: str) -> Dict:
    """Certificate issuer, expiry and negotiated protocol. Read-only
    handshake, no data sent beyond the TLS ClientHello."""
    out: Dict = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                out["protocol"] = tls.version()
                cert = tls.getpeercert() or {}
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        out["issuer"] = issuer.get("organizationName", "?")
        out["expires"] = cert.get("notAfter", "")
        if out["expires"]:
            expiry = datetime.strptime(out["expires"], "%b %d %H:%M:%S %Y %Z")
            out["days_left"] = (expiry - datetime.now()).days
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def collect_dns(ctx: RunContext) -> Tuple[str, int, str]:
    """SPF and DMARC for the website domain.

    A domain that never sends mail still needs both, or anyone can send as
    it. Where the website domain differs from the mail domain this is the
    half nobody owns. Uses `dig` when present and DNS-over-HTTPS otherwise,
    and reports a _dmarc CNAME pointing at a monitoring provider as
    delegated rather than missing.
    """
    host = urllib.parse.urlparse(ctx.site).netloc.split(":")[0]
    domain = host[4:] if host.startswith("www.") else host
    data = {"domain": domain, "via": "dig" if shutil.which("dig") else "doh"}

    spf = [r for r in _dns_txt(domain) if r.lower().startswith("v=spf1")]
    dmarc_txt = _dns_txt("_dmarc." + domain)
    dmarc = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
    cname = _dns_cname("_dmarc." + domain)

    data["spf"] = spf[0] if spf else ""
    data["dmarc"] = dmarc[0] if dmarc else ""
    data["dmarc_delegated_to"] = cname if cname and not dmarc else ""
    # DMARC is inherited. A subdomain with no _dmarc record of its own is
    # covered by the organisational domain's policy (sp= if present, else
    # p=), so "blogs.example.com publishes no DMARC record" is wrong when
    # example.com does. Walk up until a record is found or two labels remain.
    data["dmarc_parent"] = ""
    data["dmarc_parent_record"] = ""
    if not dmarc and not cname:
        labels = domain.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            found = [r for r in _dns_txt("_dmarc." + parent)
                     if r.lower().startswith("v=dmarc1")]
            if found:
                data["dmarc_parent"] = parent
                data["dmarc_parent_record"] = found[0]
                break
    data["mx"] = _dns_mx(domain)
    ctx.write("dns", data)
    return "ok", 1, ""


def _dig(name: str, rtype: str) -> List[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.run(["dig", "+short", rtype, name],
                             capture_output=True, text=True, timeout=15)
    except Exception:
        return []
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def _doh(name: str, rtype: str) -> List[str]:
    try:
        url = (f"{DOH_URL}?name={urllib.parse.quote(name)}"
               f"&type={urllib.parse.quote(rtype)}")
        status, _, data = fetch_json(url)
        if not isinstance(data, dict):
            return []
        return [a.get("data", "") for a in data.get("Answer", [])]
    except Exception:
        return []


def _dns_txt(name: str) -> List[str]:
    raw = _dig(name, "TXT") or _doh(name, "TXT")
    return [r.strip('"').replace('" "', "") for r in raw]


def _dns_cname(name: str) -> str:
    raw = _dig(name, "CNAME") or _doh(name, "CNAME")
    return raw[0].rstrip(".") if raw else ""


def _dns_mx(name: str) -> List[str]:
    return (_dig(name, "MX") or _doh(name, "MX"))[:10]


# The module registry. `key` names the JSON file and the manifest entry.
MODULES: List[Dict] = [
    {"key": "calibration", "title": "Missing-path calibration",
     "fn": collect_calibration, "required": True,
     "about": "Learns how the site answers a path that cannot exist, and "
              "proves the result still lets a real file through."},
    {"key": "headers", "title": "Security headers and site identity",
     "fn": collect_headers, "required": True,
     "about": "Reads the homepage for security response headers, version "
              "disclosure, cookie flags and the theme."},
    {"key": "rest", "title": "REST API index",
     "fn": collect_rest, "required": False,
     "about": "Reads /wp-json/ for the plugin inventory and any route that "
              "accepts a write method. No route is called."},
    {"key": "users", "title": "Author and user disclosure",
     "fn": collect_users, "required": False,
     "about": "Reads the four routes that publish account names: the REST "
              "users endpoint, ?author=N, the users sitemap and oEmbed."},
    {"key": "media", "title": "Media library walk",
     "fn": collect_media, "required": False,
     "about": "Pages through the whole media library and compares the walk "
              "against the total the endpoint reports."},
    {"key": "documents", "title": "Public documents",
     "fn": collect_documents, "required": False,
     "about": "Confirms each document resolves and flags filenames worth "
              "opening."},
    {"key": "assets", "title": "Plugin versions across the sitemap",
     "fn": collect_assets, "required": False,
     "about": "Reads plugin versions from cache-busted asset URLs on every "
              "page in the sitemap, not just one."},
    {"key": "vulns", "title": "Known vulnerabilities and currency",
     "fn": collect_vulns, "required": False,
     "about": "Looks every detected plugin, theme and core version up "
              "against api.wordpress.org for currency and withdrawal, and "
              "wpvulnerability.net for published CVEs. Components with no "
              "record are reported as unchecked, never as clean."},
    # The path sweep is the one burst in a run (fifty-odd paths, two requests
    # each) and it is what trips rate limiters. It runs after the modules
    # whose data the vulnerability lookups depend on, so a WAF that starts
    # refusing halfway through costs path coverage rather than the inventory.
    {"key": "paths", "title": "Readable paths",
     "fn": collect_paths, "required": False,
     "about": "Requests backup archives, database dumps, credential files, "
              "logs, developer artefacts, form-upload directories and "
              "directory listings that should not be readable, plus backup "
              "names derived from the domain and the paths robots.txt hides."},
    {"key": "transport", "title": "Transport and TLS",
     "fn": collect_transport, "required": False,
     "about": "HTTP-to-HTTPS behaviour, the certificate, CORS, XML-RPC and "
              "security.txt."},
    {"key": "dns", "title": "Mail spoofing posture",
     "fn": collect_dns, "required": False,
     "about": "SPF and DMARC for the website domain, which is the half "
              "nobody owns when it differs from the mail domain."},
]

MODULE_BY_KEY = {m["key"]: m for m in MODULES}

# Modules that only mean something on WordPress. On any other site they are
# marked "not applicable" rather than run, because "empty" would read as
# hardened. The paths module stays: half its list applies to any site.
WORDPRESS_ONLY_MODULES = {"rest", "users", "media", "documents", "assets", "vulns"}


def selected_modules(args) -> List[Dict]:
    only = {k.strip() for k in (args.only or "").split(",") if k.strip()}
    skip = {k.strip() for k in (args.skip or "").split(",") if k.strip()}
    out = []
    for mod in MODULES:
        if only and mod["key"] not in only and not mod["required"]:
            continue
        if mod["key"] in skip and not mod["required"]:
            continue
        out.append(mod)
    return out


def collect(ctx: RunContext, modules: List[Dict]):
    print_header("STAGE 1 - COLLECT")
    for mod in modules:
        key = mod["key"]
        if ctx.module_status(key) == "ok" and not ctx.args.force:
            print_info(f"{key}: already collected, skipping "
                       "(use --force to redo)")
            continue
        if shutdown_requested:
            ctx.set_module(key, "skipped", 0, "stopped by the operator")
            continue
        # Calibration is load-bearing: without a trustworthy signature the
        # path module reports either fiction or nothing. An earlier version
        # marked paths "skipped" here and then ran it anyway two iterations
        # later, because the loop only honoured "ok". Found on a live run.
        if key == "paths" and ctx.module_status("calibration") == "error":
            ctx.set_module("paths", "skipped", 0,
                           "calibration failed, so a path result could not "
                           "be told apart from a 404")
            print_warning("paths: skipped, calibration could not be trusted")
            continue
        platform = ctx.manifest["meta"].get("platform", {})
        if (key in WORDPRESS_ONLY_MODULES and platform.get("decided")
                and not platform.get("wordpress")):
            ctx.set_module(key, "not applicable", 0,
                           "no WordPress markers were found on this site "
                           "(wp-content, wp-includes, generator tag, REST "
                           "discovery link, wp-login.php), so this "
                           "WordPress-specific check does not apply")
            print_info(f"{key}: not applicable, this is not a WordPress site")
            continue
        started = time.time()
        try:
            status, rows, note = mod["fn"](ctx)
        except Exception as exc:                 # one module must not end a run
            ctx.set_module(key, "error", 0, f"{type(exc).__name__}: {exc}")
            print_error(f"{key}: {type(exc).__name__}: {exc}")
            continue
        ctx.set_module(key, status, rows, note)
        elapsed = time.time() - started
        line = f"{key}: {status}, {rows} row(s) in {elapsed:.1f}s"
        if status == "ok":
            print_success(line + (f" - {note}" if note else ""))
        elif status == "error":
            print_error(f"{line} - {note}")
        else:
            print_warning(f"{line} - {note}" if note else line)
        if key == "calibration" and status == "error":
            print_error("Calibration could not be trusted; the paths module "
                        "will not run. See the report's Methodology section.")


###############################################################################
# CHECK
###############################################################################

class Finding:
    """One report finding: fixed client-facing copy plus evidence rows."""

    def __init__(self, fid: str, severity: str, title: str, meaning: str,
                 remediation: str, evidence: List[Dict[str, str]],
                 source: str, count: Optional[int] = None):
        self.fid = fid
        self.severity = severity
        self.title = title
        self.meaning = meaning
        self.remediation = remediation
        self.evidence = evidence[:EVIDENCE_ROWS]
        self.count = count if count is not None else len(evidence)
        self.source = source


def check_paths(ctx: RunContext) -> List[Finding]:
    """One finding per severity band, so a report with eleven readable
    paths does not become eleven sections the reader scrolls past."""
    rows = ctx.data("paths")
    if not rows:
        return []
    ambiguous = calibration_is_ambiguous(ctx.missing_signature)
    findings = []
    by_severity: Dict[str, List[Dict]] = {}
    empties: List[Dict] = []
    for row in rows:
        if not row["exposed"]:
            continue
        if not row["bytes"] and not row["path"].endswith("/"):
            # A 0-byte 200 is a real file with nothing in it, or a server
            # rule that answers 200 for a blocked path. Neither supports the
            # severity the path would earn with content, so these get their
            # own INFO finding rather than a seat in the CRITICAL table.
            empties.append(row)
            continue
        by_severity.setdefault(row["severity"], []).append(row)

    if empties:
        findings.append(Finding(
            "paths-empty", "INFO",
            f"{len(empties)} path(s) answered HTTP 200 with an empty body",
            "The server answered as though the file exists but sent nothing. "
            "That is either an empty file or a web-server rule that returns "
            "200 for a path it blocks. Nothing was read, so this is not an "
            "exposure; it is a prompt to look, because an empty backup file "
            "or an empty .env in the web root means one was there at some "
            "point.",
            "Check each path on the server. If a file exists, delete it and "
            "ask how it got there; if a rule is answering, consider returning "
            "404 instead so the path does not confirm anything.",
            [{"Path": r["path"], "Status": r["status"],
              "What it would be": r["why"]} for r in empties],
            "paths.json", len(empties)))

    for severity, hits in by_severity.items():
        evidence = [{"Path": h["path"], "Status": h["status"],
                     "Bytes": h["bytes"], "Type": h["content_type"],
                     "What it gives away": h["why"]} for h in hits]
        if severity == "INFO":
            findings.append(Finding(
                "paths-robots", "INFO",
                f"{len(hits)} path(s) the site's own robots.txt hides from "
                "search engines are readable",
                "robots.txt is public, and its Disallow lines are the site "
                "owner's own list of things they did not want indexed. "
                "Attackers read it as a shortlist. Each listed path was "
                "requested; these answered with content. A page that is "
                "public but unindexed is normal. A directory, an export or an "
                "admin screen in this list is not.",
                "Look at what each path serves. Anything that should not be "
                "public needs a login or removal, not a robots.txt line, "
                "which only asks well-behaved crawlers to look away.",
                evidence, "paths.json", len(hits)))
            continue
        if ambiguous:
            findings.append(Finding(
                f"paths-{severity.lower()}", "INFO",
                f"{len(hits)} path(s) answered, but could not be confirmed "
                f"({severity} if real)",
                "This site answers a path that cannot exist with a page whose "
                "content changes between requests, so a real file cannot be "
                "told apart from the site's own not-found page. These paths "
                "answered with content; whether the file exists is unknown.",
                "Open two or three of these URLs in a browser and compare "
                "them with a deliberately nonsensical filename on the same "
                "site. If they differ, the file is real and this becomes a "
                f"{severity} finding.",
                evidence, "paths.json", len(hits)))
            continue
        if severity == "CRITICAL":
            meaning = ("These paths are readable by anyone. A backup archive "
                       "or a database dump contains wp-config.php and the "
                       "whole database, which is every password hash, every "
                       "customer record and the keys needed to sign in as an "
                       "administrator. Treat a confirmed hit here as a "
                       "compromise that has already happened.")
            remediation = ("Delete the file from the server today, then "
                           "change the database password, the WordPress "
                           "salts in wp-config.php and every administrator "
                           "password. Move backups out of the web root "
                           "entirely; a backup plugin that writes into "
                           "wp-content is one directory listing away from "
                           "handing over the site.")
        elif severity == "HIGH":
            meaning = ("These paths give an attacker material help: account "
                       "names to guess passwords against, server "
                       "configuration, or an installer that can take over a "
                       "site whose database is unreachable.")
            remediation = ("Block each path at the web server or CDN, or "
                           "remove the file. For the REST users endpoint, "
                           "filter it for logged-out callers with a small "
                           "snippet in a code-snippets plugin.")
        else:
            meaning = ("These paths confirm the platform and its version, or "
                       "let the site be enumerated in bulk. None of them is "
                       "an entry on its own; together they tell an attacker "
                       "which exploits are worth trying.")
            remediation = ("Delete readme.html and license.txt after each "
                           "core update - both are restored by every update - "
                           "and turn off directory indexing for any listing "
                           "above.")
        findings.append(Finding(
            f"paths-{severity.lower()}", severity,
            f"{len(hits)} path(s) readable that should not be",
            meaning, remediation, evidence, "paths.json", len(hits)))
    return findings


def check_headers(ctx: RunContext) -> List[Finding]:
    data = ctx.data("headers")
    if not data:
        return []
    findings = []
    if data.get("status") != 200 or data.get("challenged"):
        # The headers of a block page describe the WAF, not the site.
        return findings
    missing = data.get("missing", [])
    by_sev = {}
    for header, severity, cost in SECURITY_HEADERS:
        if header in missing:
            by_sev.setdefault(severity, []).append(
                {"Header": header, "Without it": cost})
    for severity, rows in by_sev.items():
        findings.append(Finding(
            f"headers-{severity.lower()}", severity,
            f"{len(rows)} security header(s) not sent",
            "These headers are sent by the web server or a plugin on every "
            "response, so adding them is a configuration change and not a "
            "code change. Each one closes a class of attack that the site "
            "is otherwise open to.",
            "Add them at the CDN or web server rather than in the theme, so "
            "they survive a theme change. Add Strict-Transport-Security "
            "last and with a short max-age at first: it is difficult to "
            "reverse quickly if something on the site still needs HTTP.",
            rows, "headers.json", len(rows)))

    leaky = data.get("leaky", {})
    # A value with no number in it names a product, not a version, and the
    # finding below is about versions. "x-powered-by: WP Engine" and
    # "x-redirect-by: WordPress" were both reported as version disclosure.
    interesting = {k: v for k, v in leaky.items() if re.search(r"\d", v or "")}
    if interesting:
        findings.append(Finding(
            "headers-leaky", "LOW",
            "The server names its own software version on every response",
            "This is not a way in on its own. It removes the attacker's "
            "guesswork: knowing the exact PHP or server build tells them "
            "which published exploits are worth trying against this site.",
            "Suppress the header at the web server. In PHP set "
            "expose_php = Off; in nginx or Apache remove the version from "
            "the Server token.",
            [{"Header": k, "Value": v} for k, v in interesting.items()],
            "headers.json"))

    insecure = [c for c in data.get("cookies", [])
                if not c["secure"] or not c["httponly"]]
    if insecure:
        findings.append(Finding(
            "headers-cookies", "LOW",
            f"{len(insecure)} cookie(s) set without Secure or HttpOnly",
            "A cookie without Secure can be sent over plain HTTP; one "
            "without HttpOnly can be read by any script running on the "
            "page, which is what turns a script injection into a stolen "
            "session.",
            "Set both flags on every cookie the site issues. Cookies set by "
            "a plugin need the plugin updated or its settings changed.",
            [{"Cookie": c["name"],
              "Secure": "yes" if c["secure"] else "NO",
              "HttpOnly": "yes" if c["httponly"] else "NO",
              "SameSite": "yes" if c["samesite"] else "no"}
             for c in insecure], "headers.json"))

    mixed = data.get("mixed_content", [])
    if mixed:
        active = [m for m in mixed if m["tag"] in ("script", "iframe", "link")]
        findings.append(Finding(
            "headers-mixed", "MEDIUM" if active else "LOW",
            f"{len(mixed)} resource(s) on the homepage load over plain HTTP",
            "The page is served over HTTPS but asks the browser to fetch "
            + ("scripts or stylesheets" if active else "images or media")
            + " over plain HTTP. Browsers block scripts and stylesheets "
            "loaded this way, so part of the page is broken for every "
            "visitor; images and media still load but the address bar loses "
            "its padlock. Either way anyone on the network path can read or "
            "swap what is fetched.",
            "Change each URL to https:// or to a scheme-relative //host/path. "
            "For a WordPress site, run a search-and-replace on the database "
            "for http://<your domain> after confirming the Site Address in "
            "Settings > General starts with https.",
            [{"Tag": m["tag"], "URL": m["url"]} for m in mixed],
            "headers.json", len(mixed)))

    generators = data.get("generators", [])
    wp_version = next((g for g in generators if g.lower().startswith("wordpress")), "")
    if wp_version:
        findings.append(Finding(
            "headers-generator", "INFO",
            f"The site publishes its WordPress version: {wp_version}",
            "WordPress adds a generator meta tag to every page unless it is "
            "removed. It saves an attacker the trouble of working out which "
            "core version they are looking at.",
            "Remove it with a one-line filter "
            "(remove_action('wp_head', 'wp_generator')). Keeping the site "
            "patched matters far more than hiding the number.",
            [{"Generator": g} for g in generators], "headers.json"))
    return findings


def check_users(ctx: RunContext) -> List[Finding]:
    data = ctx.data("users")
    if not data:
        return []
    rest = data.get("rest", [])
    findings = []
    if rest:
        named = [u for u in rest if u.get("slug")]
        evidence = [{"ID": u["id"], "Display name": u["name"],
                     "Author slug": u["slug"] or "(none)"} for u in rest]
        findings.append(Finding(
            "users-rest", "HIGH",
            f"The REST API hands out all {len(rest)} account(s) to anyone",
            "/wp-json/wp/v2/users returns every account with its display "
            "name and its author slug to a caller who is not signed in. The "
            "slug is WordPress's user_nicename field. It is often the same "
            "as the login name, but not always, so treat it as a strong "
            "starting point for password guessing rather than a confirmed "
            "username. Where a site has deliberately obfuscated its logins, "
            "this endpoint publishes the obfuscated name next to the real "
            "person, which undoes the obfuscation.",
            "Filter the endpoint for logged-out callers with a snippet in a "
            "code-snippets plugin, hooking rest_authentication_errors or "
            "the users endpoint specifically. Test it on staging first: "
            "some page builders and themes fetch users through the REST API "
            "on the front end. Closing this does not replace two-factor "
            "authentication on the accounts themselves.",
            evidence, "users.json", len(rest)))
        if len(named) != len(rest):
            findings.append(Finding(
                "users-count", "INFO",
                f"{len(rest)} account(s) are published but only "
                f"{len(named)} carry a slug",
                "An account with an empty slug is usually a legacy or "
                "system account. It is worth knowing it exists.",
                "Review the accounts with no slug and remove any that are "
                "no longer used.",
                [{"ID": u["id"], "Display name": u["name"]}
                 for u in rest if not u.get("slug")], "users.json"))

    redirects = data.get("author_redirect", [])
    sitemap = data.get("sitemap", [])
    if redirects or sitemap:
        # One finding for both routes: they publish the same slug, and two
        # sections saying so would be the same disclosure counted twice. The
        # users sitemap was collected and never reported for one release;
        # on one live site that was 61 author URLs the report knew about and
        # said nothing.
        routes = []
        if redirects:
            routes.append("?author=N")
        if sitemap:
            routes.append("the users sitemap")
        evidence = [{"Route": f"?author={r['n']}", "Author slug": r["slug"]}
                    for r in redirects]
        evidence += [{"Route": "wp-sitemap-users-1.xml",
                      "Author slug": u.rstrip("/").rsplit("/", 1)[-1]}
                     for u in sitemap]
        findings.append(Finding(
            "users-author", "MEDIUM",
            f"Author slugs are published through {' and '.join(routes)}",
            "These are the older enumeration routes and they outlive the "
            "REST endpoint. /?author=1 redirects to /author/<slug>/, and the "
            "users sitemap lists every author archive URL; both carry the "
            "same user_nicename the REST endpoint publishes. Closing only the "
            "REST endpoint leaves these open. On a publication with many "
            "named authors this is expected; the point is that the slug, "
            "which is often the login name, travels with the name.",
            "Block the author query string at the web server, or return a "
            "404 for author archives if the site does not use them. Remove "
            "the users sitemap with the wp_sitemaps_add_provider filter if "
            "author archives are not meant to be discovered.",
            evidence, "users.json", len(evidence)))

    if data.get("oembed"):
        findings.append(Finding(
            "users-oembed", "LOW",
            "oEmbed publishes an author's display name",
            "The oEmbed endpoint returns author_name for any page on the "
            "site. It gives a real name rather than a slug, which is a "
            "smaller disclosure but survives closing the other routes.",
            "Filter the oembed_response_data hook to drop author_name if "
            "the site does not need oEmbed previews elsewhere.",
            [{"author_name": data["oembed"]}], "users.json"))
    return findings


def check_media(ctx: RunContext) -> List[Finding]:
    data = ctx.data("media")
    if not data:
        return []
    findings = []
    total = data.get("reported_total", 0)
    walked = data.get("walked", 0)
    if total or walked:
        # A host that strips X-WP-Total leaves total at 0. The library was
        # still walked, and a finding gated on the header alone vanished.
        findings.append(Finding(
            "media-open", "MEDIUM",
            f"The media library is enumerable without a login "
            f"({total or walked} items"
            f"{'' if total else ', counted by walking; no total was sent'})",
            "Anyone can page through every file ever uploaded, including "
            "files no page links to. Closing this stops bulk enumeration and "
            "protects no individual file, because an upload is readable by "
            "its URL either way.",
            "Restrict the media endpoint for logged-out callers, the same "
            "way as the users endpoint. Then deal with the files "
            "themselves: anything that should not be public has to move "
            "behind a login or off the server.",
            [{"Reported by the endpoint": total,
              "Returned by a full walk": walked,
              "Pages walked": len(data.get("pages", []))}],
            "media.json"))
    gap = data.get("gap", 0)
    if gap:
        findings.append(Finding(
            "media-gap", "INFO",
            f"{gap} library item(s) could not be listed and are not covered "
            "by this report",
            f"The endpoint reports {total} items. A complete walk of every "
            f"page returned {walked}. WordPress filters items out of a page "
            "after slicing it, so the shortfall is normal, but it means "
            "'not in the library listing' is a weaker statement than it "
            "looks: some of the missing items may be documents nobody has "
            "reviewed.",
            "The authoritative inventory is a directory walk on the server, "
            "which this tool deliberately does not do. Over SSH or SFTP: "
            "find wp-content/uploads -type f ! -iname '*.jpg' ! -iname "
            "'*.png' ! -iname '*.webp' -printf '%TY-%Tm-%Td %10s %p\\n' | "
            "sort",
            [{"Reported total": total, "Walked": walked, "Not listed": gap}],
            "media.json"))
    return findings


def check_documents(ctx: RunContext) -> List[Finding]:
    rows = ctx.data("documents")
    if not rows:
        return []
    findings = []
    live = [r for r in rows if r["status"] == 200]

    orphans = [r for r in live if not r["in_library"]]
    if orphans:
        findings.append(Finding(
            "docs-orphan", "MEDIUM",
            f"{len(orphans)} document(s) are downloadable but do not appear "
            "in the media library",
            "A file uploaded by an older install, or deleted from the "
            "library while the file stayed on disk, does not appear in the "
            "REST response and is not visible in wp-admin either. The Media "
            "screen therefore cannot delete it. It stays downloadable and "
            "search engines keep it indexed. These are the files nobody "
            "knows they still have.",
            "Removing these needs SFTP or SSH; there is no way to do it "
            "from the WordPress admin. Get a directory listing of "
            "wp-content/uploads first, decide what should still be public, "
            "and delete the rest. Anything already indexed also needs a "
            "removal request in Google Search Console.",
            [{"URL": r["url"], "Bytes": r["bytes"], "Type": r["content_type"],
              "Flagged words": ", ".join(r["sensitive"]) or "-"}
             for r in orphans], "documents.json", len(orphans)))

    sensitive = [r for r in live if r["sensitive"]]
    hidden_sensitive = [r for r in sensitive if not r["in_library"]]
    if hidden_sensitive:
        findings.append(Finding(
            "docs-hidden-sensitive", "HIGH",
            f"{len(hidden_sensitive)} document(s) are invisible to the admin "
            "screens AND named like something worth protecting",
            "These are the intersection of the two problems below: nobody can "
            "see them from inside WordPress, and the filename suggests "
            "contents that were probably never meant to be public. A file in "
            "this list has been downloadable for as long as it has existed, "
            "with nothing in the admin interface to prompt anyone to review "
            "it. Search engines index these the same as any other page.",
            "Open each one first and decide what it is. Then remove it over "
            "SFTP or SSH, because the Media screen cannot. If the contents "
            "should never have been public, assume they were taken: the "
            "access logs will not go back far enough to prove otherwise. "
            "Follow up with a removal request in Google Search Console for "
            "anything already indexed.",
            [{"URL": r["url"], "Flagged words": ", ".join(r["sensitive"]),
              "Bytes": r["bytes"]} for r in hidden_sensitive],
            "documents.json", len(hidden_sensitive)))
    if sensitive:
        findings.append(Finding(
            "docs-sensitive", "MEDIUM",
            f"{len(sensitive)} public document(s) have filenames worth "
            "opening",
            "These matched on the filename alone, which is a prompt to look "
            "rather than a finding. A name is not evidence of what is inside "
            "it: a 'sample' template with blank fields is harmless, and a "
            "neutrally named PDF can hold a fee schedule. Expect some of "
            "this list to be marketing material that is public on purpose. "
            "Someone still has to open each one, because no filename rule "
            "can tell the difference.",
            "Open each file and decide: leave it public, move it behind a "
            "login, or delete it. Record the decision, so the next audit "
            "does not re-litigate the same list. For anything that should "
            "never have been public, assume it was downloaded and treat the "
            "contents accordingly.",
            [{"URL": r["url"], "Flagged words": ", ".join(r["sensitive"]),
              "In library": "yes" if r["in_library"] else "NO",
              "Bytes": r["bytes"]} for r in sensitive],
            "documents.json", len(sensitive)))

    dead = [r for r in rows if r["status"] not in (200, 0)]
    if dead:
        findings.append(Finding(
            "docs-dead", "INFO",
            f"{len(dead)} listed document(s) no longer resolve",
            "The media library lists them but the file is gone. Harmless in "
            "itself; it usually means a broken download link somewhere on "
            "the site.",
            "Clean up the library entries, and check whether any page still "
            "links to them.",
            [{"URL": r["url"], "Status": r["status"]} for r in dead],
            "documents.json", len(dead)))
    return findings


def check_rest(ctx: RunContext) -> List[Finding]:
    data = ctx.data("rest")
    if not data:
        return []
    findings = []
    third_party = data.get("third_party", [])
    if third_party:
        findings.append(Finding(
            "rest-inventory", "INFO",
            f"The REST index lists {data.get('route_count', 0)} routes "
            f"across {len(third_party)} non-core namespaces",
            "This is a fuller plugin inventory than the page HTML, because "
            "a plugin appears in the HTML only if it loads an asset on the "
            "page you happened to fetch, while any plugin with an API "
            "registers a namespace regardless. Anyone can read it. It is "
            "listed here so the plugin inventory in this report is honest "
            "about how it was built.",
            "Nothing to fix directly. Use the list to check that every "
            "plugin here is one you meant to install and is still "
            "maintained. Two plugins doing the same job, or a previous "
            "host's control-panel plugin left behind after a migration, is "
            "attack surface with no owner.",
            [{"Namespace": ns, "Plugin": NAMESPACE_NAMES.get(ns, "unknown")}
             for ns in third_party], "rest.json", len(third_party)))

    rpc = [r for r in data.get("write_routes", [])
           if any(hint in r["route"].lower() for hint in RPC_NAMESPACE_HINTS)]
    if rpc:
        # MEDIUM, not HIGH. The evidence is a route name and an advertised
        # write method; WordPress routes almost always require authentication
        # for writes and the index does not say. A Jetpack settings route
        # earned HIGH on the word "mcp" alone before this was lowered.
        findings.append(Finding(
            "rest-rpc", "MEDIUM",
            f"{len(rpc)} route(s) accept write methods and look like a "
            "remote-control interface",
            "These routes advertise POST, PUT or DELETE and sit in a "
            "namespace that exists to drive the site programmatically. "
            "Whether they accept an anonymous call is UNKNOWN and was "
            "deliberately not tested, because finding out means sending a "
            "POST, which is submitting rather than observing. Most WordPress "
            "routes require authentication for writes, which is why this is "
            "rated medium on the evidence of a name; an unauthenticated route "
            "of this shape would be a way to change the site, so resolve it "
            "rather than filing it.",
            "Determine from the plugin's own documentation or its source "
            "what authentication these routes require. If the plugin is not "
            "in use, remove it rather than deactivating it. If it is, "
            "restrict the routes to authenticated callers and confirm from "
            "the plugin's settings that no long-lived token is issued.",
            [{"Route": r["route"], "Methods": ", ".join(r["methods"])}
             for r in rpc], "rest.json", len(rpc)))
    return findings


def check_assets(ctx: RunContext) -> List[Finding]:
    data = ctx.data("assets")
    if not data:
        return []
    findings = []
    plugins = data.get("plugins", {})
    if plugins:
        findings.append(Finding(
            "assets-versions", "INFO",
            f"{len(plugins)} plugin version(s) readable from the page source",
            "WordPress appends each plugin's version to its script and "
            "stylesheet URLs, so anyone can read which release is running "
            "and look it up against published vulnerabilities. Every page "
            "here was requested with a throwaway query string to defeat the "
            "cache, so these numbers are what the site is serving now "
            "rather than what it served when a cached copy was built. The "
            "page count matters: it is the size of the public surface for "
            "any vulnerability in that plugin.",
            "Check each version against the plugin's changelog and the "
            "WordPress vulnerability databases, and update anything behind. "
            "Hiding the version numbers is cosmetic; a scanner fingerprints "
            "the plugin from its assets either way.",
            [{"Plugin": slug,
              "Version(s) seen": ", ".join(info["versions"]),
              "Pages carrying it": info["pages"]}
             for slug, info in plugins.items()], "assets.json", len(plugins)))

    # More than one version string for a plugin means one of two things, and
    # only one is a finding. If a single page carries both, the plugin
    # versions its own assets independently (a bundled library under its own
    # number) and nothing is stale. Only pages that disagree with EACH OTHER,
    # each carrying one version, point at a cache or a half-applied update.
    # The first version of this check reported a plugin with three asset
    # versions on every one of 26 pages as a cache problem.
    per_page: Dict[str, List[set]] = {}
    for page in data.get("pages", []):
        seen: Dict[str, set] = {}
        for item in page.get("plugins", []):
            slug, _, version = item.rpartition(" ")
            seen.setdefault(slug, set()).add(version)
        for slug, versions in seen.items():
            per_page.setdefault(slug, []).append(versions)
    mixed = {}
    for slug, info in plugins.items():
        if len(info["versions"]) < 2:
            continue
        page_sets = per_page.get(slug, [])
        if any(len(s) > 1 for s in page_sets):
            continue                       # same page, several versions: by design
        singles = {next(iter(s)) for s in page_sets if len(s) == 1}
        if len(singles) > 1:
            mixed[slug] = sorted(singles, key=version_key)
    if mixed:
        findings.append(Finding(
            "assets-mixed", "MEDIUM",
            f"{len(mixed)} plugin(s) are served at different versions on "
            "different pages",
            "Each page carries one version of the plugin, and the pages "
            "disagree. That usually means some pages are still being served "
            "from a cache built before an update, but it can also mean a "
            "half-applied update. Either way a version read from one page "
            "cannot be trusted for the whole site.",
            "Clear the site and CDN caches, then re-run this check. If the "
            "versions still disagree, look at wp-content/upgrade/ on the "
            "server for a partly applied update.",
            [{"Plugin": s, "Versions": ", ".join(v)}
             for s, v in mixed.items()], "assets.json", len(mixed)))

    conflicts = {s: i for s, i in plugins.items()
                 if i.get("readme_version") and i["versions"]
                 and i["readme_version"] not in i["versions"]}
    if conflicts:
        findings.append(Finding(
            "assets-readme", "INFO",
            f"{len(conflicts)} plugin(s) report a different version in "
            "readme.txt than in their asset URLs",
            "The plugin's own readme.txt names a Stable tag that differs "
            "from the version appended to its scripts and styles. Authors do "
            "forget to bump one or the other, so this is not itself a "
            "problem. It is listed because the vulnerability check below "
            "tested both numbers, and the reader should know why two appear.",
            "Check the version shown in Plugins > Installed Plugins, which is "
            "the authoritative one.",
            [{"Plugin": s, "Asset URLs say": ", ".join(i["versions"]),
              "readme.txt says": i["readme_version"]}
             for s, i in conflicts.items()], "assets.json", len(conflicts)))
    return findings


def check_vulns(ctx: RunContext) -> List[Finding]:
    """Findings from the two lookup APIs.

    The order matters to a reader: what is known to be vulnerable, then what
    has been withdrawn from the directory, then what is merely behind, then
    an honest statement of what could not be checked. The last one is not
    optional. A report that lists three vulnerable plugins and stays silent
    about the four it could not look up reads as though seven were cleared.
    """
    data = ctx.data("vulns")
    if not data:
        return []
    findings: List[Finding] = []
    plugins = data.get("plugins", {})
    themes = data.get("themes", {})
    core = data.get("core", {})

    # 1. Plugins and themes with a vulnerability whose range covers a version
    #    we saw. Themes are here since v1.2.0, when style.css started
    #    supplying their version.
    vulnerable = {slug: entry for slug, entry in {**plugins, **themes}.items()
                  if entry.get("vulnerabilities")}
    if vulnerable:
        rows = []
        worst = "INFO"
        for slug, entry in sorted(
                vulnerable.items(),
                key=lambda kv: -max(r["score"] for r in kv[1]["vulnerabilities"])):
            top = entry["vulnerabilities"][0]
            severity = cvss_severity(max(r["score"] for r in entry["vulnerabilities"]))
            matched = top.get("affected_version", "")
            readme = entry.get("readme_version", "")
            version_text = matched
            if entry.get("source") == "rest namespace":
                version_text = f"{matched} (from the plugin's readme.txt)"
            elif entry.get("version_conflict"):
                # Two witnesses that disagree. The match holds for one of them
                # and the other may be current, so the component cannot carry
                # more than MEDIUM until someone reads the Plugins screen.
                other = readme if matched != readme else ", ".join(
                    v for v in entry.get("detected_versions", []) if v != readme)
                version_text = (f"{matched} per {'readme.txt' if matched == readme else 'asset URLs'}; "
                                f"{'asset URLs say' if matched == readme else 'readme.txt says'} "
                                f"{other}, which does not match this range. "
                                "Confirm on the Plugins screen.")
                severity = cap_severity(severity, "MEDIUM")
            if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(worst):
                worst = severity
            rows.append({
                "Component": f"{slug} ({'theme' if slug in themes else 'plugin'})",
                "Version running": version_text,
                "Known issues": len(entry["vulnerabilities"]),
                "Worst CVSS": f"{top['score']:.1f}" if top["score"] else "unscored",
                "Reference": top["cve"] or top["name"][:60],
                "Fixed in": top["fixed_in"] or ("no fix published"
                                                if top["unfixed"] else ""),
                "Pages carrying it": entry.get("pages", 0) or "not read from pages",
            })
        findings.append(Finding(
            "vulns-plugins", worst,
            f"{len(vulnerable)} component(s) are running a version with a "
            "published vulnerability",
            "The version this site is serving falls inside the affected range "
            "of a vulnerability that has been published and given a CVE. That "
            "is not a prediction: the details, and usually a proof of "
            "concept, are already public, which is what makes an unpatched "
            "plugin different from a theoretical weakness. The page count is "
            "the size of the exposed surface. Severity here is the published "
            "CVSS base score, not this tool's opinion; an unscored entry is "
            "one the database lists without a score, and it should be read "
            "as unknown rather than as low.",
            "Update each component named below to the fixed version, then "
            "re-run this audit to confirm the site is serving the new version "
            "rather than a cached page. Where no fix is published, the plugin "
            "has to be deactivated and removed until one is, or replaced.",
            rows, "vulns.json", len(vulnerable)))

    # 2. Withdrawn from the directory. No vulnerability database needed, and
    #    frequently more urgent than one: a closed plugin gets no more
    #    security releases, and closure is often itself the security event.
    closed = {slug: entry for slug, entry in {**plugins, **themes}.items()
              if (entry.get("wporg") or {}).get("closed")}
    if closed:
        findings.append(Finding(
            "vulns-closed", "HIGH",
            f"{len(closed)} installed component(s) have been withdrawn from "
            "the WordPress directory",
            "WordPress.org has closed this plugin or theme, so it can no "
            "longer be downloaded or installed. Closure is most often a "
            "guideline breach or an abandonment, but it is also what happens "
            "when an unfixed security issue is reported and the author does "
            "not respond. Either way the site is running code that will never "
            "receive another update, including a security one, and WordPress "
            "will not warn the administrator about it.",
            "Find out why each was closed, then replace it with a maintained "
            "alternative or remove it. Do not leave a closed plugin installed "
            "and deactivated: its files stay on disk and stay reachable.",
            [{"Component": slug,
              "Closed on": (entry.get("wporg") or {}).get("closed_date", "") or "unstated",
              "Stated reason": (entry.get("wporg") or {}).get("closed_reason", "")
                               or "not published"}
             for slug, entry in sorted(closed.items())],
            "vulns.json", len(closed)))

    # 3. Behind, or unmaintained. Separate from 1 because "out of date" is
    #    not "vulnerable", and a report that conflates them gets ignored.
    stale = []
    for slug, entry in sorted({**plugins, **themes}.items()):
        wporg = entry.get("wporg") or {}
        if not wporg.get("found") or wporg.get("closed"):
            continue
        behind = wporg.get("releases_behind")
        days = wporg.get("days_since_release")
        reasons = []
        if behind:
            reasons.append(f"{behind} release(s) behind")
        elif wporg.get("outdated"):
            # The release list was incomplete, so say what is true - it is
            # behind - without inventing a count.
            reasons.append("behind the current release")
        if days is not None and days > ABANDONED_DAYS:
            reasons.append(f"no release in {days // 365} year(s)")
        tested = wporg.get("tested", "")
        latest_core = core.get("latest", "")
        # "Two majors behind" has to be counted against the list of releases
        # WordPress actually made. Arithmetic on the numbers themselves says
        # 6.9 is 92 behind 7.1 rather than 2, which fires on everything.
        majors = core.get("majors") or []
        if tested and majors and version_ordered(tested):
            floor = version_key(tested)[0][:2]
            behind = sum(1 for m in majors if version_key(m)[0][:2] > floor)
            if behind >= TESTED_MAJORS_BEHIND:
                reasons.append(f"declares support only up to WordPress {tested}, "
                               f"which is {behind} major releases ago")
        if not reasons:
            continue
        stale.append({
            "Component": slug,
            "Version running": ", ".join(entry.get("detected_versions", [])) or "not read",
            "Current release": wporg.get("current_version", ""),
            "Last released": (wporg.get("last_updated", "") or "")[:10],
            "Why it is listed": "; ".join(reasons),
        })
    if stale:
        findings.append(Finding(
            "vulns-stale", "MEDIUM",
            f"{len(stale)} component(s) are behind the current release or "
            "look unmaintained",
            "None of these is known to be vulnerable today. They are listed "
            "because the gap between what is installed and what is published "
            "is where the next vulnerability lands: a plugin two years "
            "without a release has no one to write the fix, and one that "
            "declares support only for an old WordPress version has not been "
            "looked at since. This is the maintenance backlog, not an "
            "incident.",
            "Update everything with a newer release, on a staging copy first. "
            "For anything with no release in over a year, decide whether it is "
            "still needed at all; the cheapest security fix available is "
            "removing a plugin nobody uses.",
            stale, "vulns.json", len(stale)))

    # 4. Core.
    detected = str(core.get("detected", ""))
    sources = core.get("sources") or {}
    if core.get("vulnerabilities"):
        worst = max(row["score"] for row in core["vulnerabilities"])
        # What the evidence supports. "WordPress 7.0" IS a release: the
        # generator prints $wp_version verbatim, and /core/7.0/ answers for
        # that release alone (measured: 7.0 has 12 records, 7.0.1 has 11,
        # 7.0.2 has 5). The one real doubt is a cached page built before an
        # update, so the severity stands only when a second, cache-busted
        # reading agrees. When the sources disagree, or there is only one
        # uncorroborated reading, the finding is capped and says why.
        corroborated = (len({v for v in sources.values() if v}) == 1
                        and len([v for v in sources.values() if v]) >= 2)
        disagree = bool(core.get("sources_disagree"))
        severity = cvss_severity(worst)
        if disagree or not corroborated:
            severity = cap_severity(severity, "MEDIUM")
        if disagree:
            doubt = ("The sources this tool read do not agree on the version ("
                     + "; ".join(f"{k}: {v}" for k, v in sources.items() if v)
                     + "), which usually means one of them is a cached copy "
                     "built before an update. The list below is for the "
                     "version most sources report and is something to "
                     "confirm, not a confirmed exposure.")
        elif not corroborated:
            doubt = ("Only one source disclosed the version and nothing "
                     "corroborated it, so a cached page cannot be ruled out. "
                     "Listed as something to confirm rather than as a "
                     "confirmed exposure.")
        else:
            doubt = ("The version was read from more than one source and they "
                     "agree, so a stale cached page is unlikely. Core "
                     "auto-updates are on by default for security releases, so "
                     "a site sitting on a vulnerable version usually means "
                     "auto-updates were switched off or a failed update was "
                     "never completed.")
        findings.append(Finding(
            "vulns-core", severity,
            f"WordPress {detected} has {len(core['vulnerabilities'])} "
            "published vulnerability(ies) against it",
            "The core version this site discloses falls inside the affected "
            "range of a published WordPress vulnerability. " + doubt,
            "Check the exact version in Dashboard > Updates, then update core "
            "to " + (core.get("latest") or "the current release")
            + ". Confirm that automatic background updates for security "
            "releases are enabled while you are there.",
            [{"Reference": row["cve"] or row["name"][:60],
              "CVSS": f"{row['score']:.1f}" if row["score"] else "unscored",
              "Details": row["reference"]}
             for row in core["vulnerabilities"]], "vulns.json",
            len(core["vulnerabilities"])))
    elif core.get("detected") and core.get("releases_behind"):
        findings.append(Finding(
            "vulns-core-behind", "LOW",
            f"WordPress core is {core['releases_behind']} release(s) behind",
            f"The site discloses WordPress {core['detected']} and the current "
            f"release is {core.get('latest', 'newer')}. No vulnerability is "
            "known for this version, so this is a currency observation rather "
            "than a security finding.",
            "Apply core updates on the usual maintenance schedule. Confirm "
            "automatic background updates for security releases are enabled.",
            [{"Running": core["detected"], "Current": core.get("latest", ""),
              "Releases behind": core["releases_behind"]}],
            "vulns.json", 1))

    # 5. What could not be checked. This finding exists because its absence
    #    is a lie: a plugin the vulnerability database has never heard of
    #    produces the same empty result as a plugin it has cleared.
    gaps = []
    # Core first. A core that could not be looked up, or was never
    # identified, was absent from this list for one release, so a report on
    # a site running a development build said nothing about core at all.
    if not detected:
        gaps.append({"Component": "WordPress core",
                     "What was not checked": "no version is disclosed (generator "
                     "tag, feed and wp-includes asset URLs were all read), so "
                     "core could not be checked against the vulnerability data. "
                     "Hiding it is good practice; it also means this report "
                     "cannot say whether core is current."})
    elif core.get("covered") is False:
        gaps.append({"Component": f"WordPress core {detected}",
                     "What was not checked": core.get("lookup_error")
                     or "no vulnerability record for this version"})
    for slug, entry in sorted({**plugins, **themes}.items()):
        reasons = []
        if not entry.get("covered"):
            reasons.append(entry.get("lookup_error") or "no vulnerability record")
        if not (entry.get("wporg") or {}).get("found"):
            reasons.append("not in the wordpress.org directory")
        if not entry.get("detected_versions"):
            reasons.append("no version could be read"
                           + (" from style.css" if slug in themes else
                              " from asset URLs or readme.txt")
                           + ", so no range could be matched")
        if entry.get("undecidable"):
            reasons.append(f"{entry['undecidable']} record(s) used a version "
                           "range this tool does not interpret")
        if reasons:
            gaps.append({"Component": f"{slug} ({'theme' if slug in themes else 'plugin'})",
                         "What was not checked": "; ".join(reasons)})
    if gaps:
        findings.append(Finding(
            "vulns-coverage", "INFO",
            f"{len(gaps)} component(s) could not be fully checked against the "
            "vulnerability data",
            "These are listed so that the absence of a finding above is not "
            "read as a clean result. The vulnerability database returns "
            "almost the same answer for a plugin it has never heard of as for "
            "one with nothing against it, and premium, custom-built and "
            "renamed plugins are routinely absent from both sources. A "
            "component here has not been cleared; it has not been examined.",
            "Check each of these by hand against the vendor's own changelog "
            "and security notices. For a custom or premium plugin, ask the "
            "developer directly what release the site should be on.",
            gaps, "vulns.json", len(gaps)))
    return findings


def check_transport(ctx: RunContext) -> List[Finding]:
    data = ctx.data("transport")
    if not data:
        return []
    findings = []
    http = data.get("http", {})
    if http.get("status") == 200:
        findings.append(Finding(
            "transport-http", "HIGH",
            "The site serves content over plain HTTP without redirecting",
            "A visitor who types the address without https reaches the site "
            "over an unencrypted connection. Anything they send, including "
            "a login, is readable by anyone on the network between them and "
            "the server.",
            "Redirect all HTTP traffic to HTTPS at the web server or CDN, "
            "then add Strict-Transport-Security so browsers stop trying "
            "HTTP at all.",
            [{"URL": "http://" + data.get("host", ""),
              "Status": http.get("status")}], "transport.json"))

    if data.get("wp_cron", {}).get("answering"):
        findings.append(Finding(
            "transport-wp-cron", "INFO",
            "wp-cron.php answers to anyone, which is the WordPress default",
            "This is how WordPress runs scheduled work: a visitor's page load "
            "triggers the endpoint. It returns an empty response and discloses "
            "nothing - no file contents and no PHP source - so it is listed "
            "as context rather than as an exposure. It matters only in that "
            "anybody can trigger it as often as they like, and each call does "
            "real work on the server, so it can be used to add load cheaply.",
            "Nothing needs doing on most sites. On a busy site, or one that "
            "has been used this way, set DISABLE_WP_CRON in wp-config.php and "
            "run wp-cron.php from a real system cron instead, then restrict "
            "the URL at the CDN or web server.",
            [{"URL": ctx.site + "/wp-cron.php",
              "Status": data["wp_cron"].get("status"),
              "Body returned": f"{data['wp_cron'].get('bytes', 0)} bytes"}],
            "transport.json", 1))

    if data.get("xmlrpc", {}).get("answering"):
        findings.append(Finding(
            "transport-xmlrpc", "MEDIUM",
            "XML-RPC is answering",
            "xmlrpc.php accepts password attempts and, through "
            "system.multicall, lets an attacker try many in a single "
            "request, which defeats most login rate limits. It can also be "
            "used to bounce traffic at a third party. Most sites no longer "
            "need it; the Jetpack and WordPress mobile apps are the usual "
            "exceptions.",
            "Block xmlrpc.php at the web server or CDN. Confirm first that "
            "nothing is using it: check whether Jetpack is active or "
            "whether anyone publishes from the mobile app.",
            [{"URL": ctx.site + "/xmlrpc.php", "Status": "answering"}],
            "transport.json"))

    if data.get("cors") == "*":
        findings.append(Finding(
            "transport-cors", "MEDIUM",
            "The REST API allows requests from any origin",
            "Access-Control-Allow-Origin is set to *, so a script on any "
            "other website can read this site's API responses in a "
            "visitor's browser.",
            "Restrict the header to the origins that genuinely need it, or "
            "remove it and let the API be same-origin.",
            [{"Header": "access-control-allow-origin", "Value": "*"}],
            "transport.json"))

    tls = data.get("tls", {})
    days = tls.get("days_left")
    if isinstance(days, int) and days < 21:
        findings.append(Finding(
            "transport-tls", "MEDIUM" if days > 0 else "CRITICAL",
            f"The TLS certificate expires in {days} day(s)"
            if days > 0 else "The TLS certificate has expired",
            "An expired certificate makes every browser show a full-page "
            "security warning before the site loads. Most automatic "
            "renewals happen 30 days out, so this close to expiry usually "
            "means the renewal is failing.",
            "Check the renewal at the host or CDN today rather than waiting "
            "for it to run. If it is a Let's Encrypt certificate, look for "
            "a failing validation.",
            [{"Issuer": tls.get("issuer", "?"),
              "Expires": tls.get("expires", "?"),
              "Days left": days}], "transport.json"))

    if not data.get("security_txt", {}).get("present"):
        findings.append(Finding(
            "transport-securitytxt", "INFO",
            "There is no security.txt",
            "A researcher who finds a problem with this site has no "
            "documented way to report it, so the first you hear of it may "
            "be from someone who did not try to reach you.",
            "Publish /.well-known/security.txt with a contact address. It "
            "is four lines and it costs nothing.",
            [{"Path": "/.well-known/security.txt", "Status": "absent"}],
            "transport.json"))
    return findings


def check_dns(ctx: RunContext) -> List[Finding]:
    data = ctx.data("dns")
    if not data:
        return []
    findings = []
    domain = data.get("domain", "")
    parent = data.get("dmarc_parent", "")
    parent_record = data.get("dmarc_parent_record", "")
    parent_policy = ""
    if parent_record:
        sp = re.search(r"\bsp=(\w+)", parent_record)
        p = re.search(r"\bp=(\w+)", parent_record)
        parent_policy = (sp or p).group(1).lower() if (sp or p) else ""
    inherits_enforcing = parent_policy in ("quarantine", "reject")
    if not data.get("spf"):
        findings.append(Finding(
            "dns-spf", "LOW" if inherits_enforcing else "MEDIUM",
            f"{domain} publishes no SPF record",
            "Without SPF, anyone can send email claiming to be from this "
            "domain and many receiving servers will accept it. This "
            "applies even when the domain never sends mail; a domain used "
            "only for a website is a common target precisely because nobody "
            "is watching it.",
            "If the domain sends no mail, publish a hard-fail record: "
            "v=spf1 -all. If it does, list the senders and end with ~all "
            "until the reports are clean.",
            [{"Domain": domain, "SPF": "absent"}
             + ([{"Note": f"rated low because {parent}'s DMARC policy "
                          f"({parent_policy}) already covers this subdomain"}]
                if inherits_enforcing else [])], "dns.json"))
    if not data.get("dmarc") and not data.get("dmarc_delegated_to") and parent:
        findings.append(Finding(
            "dns-dmarc-inherited", "INFO" if inherits_enforcing else "LOW",
            f"{domain} has no DMARC record of its own and inherits "
            f"{parent}'s policy ({parent_policy or 'unstated'})",
            "DMARC is inherited: a subdomain without a _dmarc record falls "
            "under the organisational domain's policy, using sp= where set "
            "and p= otherwise. That is the normal arrangement and not a gap. "
            + ("An enforcing parent policy means spoofed mail from this "
               "subdomain is already rejected or quarantined."
               if inherits_enforcing else
               "The parent policy is p=none, so nothing is enforced for this "
               "subdomain either; that is the parent domain's decision to "
               "revisit."),
            "Nothing to do on this subdomain. Review the parent domain's "
            "DMARC policy if it is still p=none.",
            [{"Subdomain": f"_dmarc.{domain}", "Inherits from": f"_dmarc.{parent}",
              "Record": parent_record}], "dns.json"))
    elif not data.get("dmarc") and not data.get("dmarc_delegated_to"):
        findings.append(Finding(
            "dns-dmarc", "MEDIUM",
            f"{domain} publishes no DMARC record",
            "DMARC is what tells a receiving server to reject mail that "
            "fails SPF, and what sends you reports about who is trying. "
            "Without it, SPF alone is advisory.",
            "Start with v=DMARC1; p=none; rua=mailto:<your reporting "
            "address> to collect reports, read them for a few weeks, then "
            "move to p=reject.",
            [{"Domain": f"_dmarc.{domain}", "DMARC": "absent"}], "dns.json"))
    elif data.get("dmarc", "").startswith("v=DMARC1"):
        policy = re.search(r"p=(\w+)", data["dmarc"])
        if policy and policy.group(1).lower() == "none":
            findings.append(Finding(
                "dns-dmarc-none", "LOW",
                f"{domain} publishes DMARC but the policy is p=none",
                "p=none monitors and enforces nothing. Mail that fails the "
                "checks is still delivered, so a spoofed message from this "
                "domain reaches the recipient's inbox.",
                "Read the reports the record is already collecting, "
                "confirm every legitimate sender passes, then move to "
                "p=quarantine and on to p=reject.",
                [{"Record": data["dmarc"]}], "dns.json"))
    return findings


CHECKS = [check_paths, check_headers, check_users, check_media,
          check_documents, check_rest, check_assets, check_vulns,
          check_transport, check_dns]


def run_checks(ctx: RunContext) -> List[Finding]:
    print_header("STAGE 2 - CHECK")
    findings: List[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(ctx))
        except Exception as exc:                # one check must not end a run
            print_error(f"{check.__name__}: {type(exc).__name__}: {exc}")
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.fid))
    counts = {s: sum(1 for f in findings if f.severity == s)
              for s in SEVERITY_ORDER}
    print_info("Findings: " + ", ".join(f"{counts[s]} {s.lower()}"
                                        for s in SEVERITY_ORDER))
    return findings


###############################################################################
# RENDER
###############################################################################

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"


def _evidence_table(finding: Finding) -> str:
    if not finding.evidence:
        return ""
    # Union of keys, not row 0's: evidence built from different sources can
    # legitimately carry different columns.
    headers = list(dict.fromkeys(k for r in finding.evidence for k in r))
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = ""
    for row in finding.evidence:
        cells = "".join(f"<td>{escape(str(row.get(h, '')))}</td>"
                        for h in headers)
        body += f"<tr>{cells}</tr>"
    more = ""
    if finding.count > len(finding.evidence):
        more = (f"<p class='more'>Showing {len(finding.evidence)} of "
                f"{finding.count}. The full list is in "
                f"<code>{escape(finding.source)}</code> in the run "
                f"directory.</p>")
    return (f"<div class='scroll'><table><thead><tr>{head}</tr></thead>"
            f"<tbody>{body}</tbody></table></div>{more}")


def _profile_block(ctx: RunContext) -> str:
    """What the site says about itself: platform, plugins, theme, transport."""
    headers = ctx.data("headers") or {}
    rest = ctx.data("rest") or {}
    assets = ctx.data("assets") or {}
    transport = ctx.data("transport") or {}
    dns = ctx.data("dns") or {}
    tls = transport.get("tls", {})

    rows = []

    def add(label, value):
        if value:
            rows.append((label, value))

    platform = ctx.manifest["meta"].get("platform", {})
    add("WordPress detected",
        ("yes, from " + ", ".join(platform.get("signals", []))
         if platform.get("wordpress") else
         "NO. None of the WordPress markers were found; only the "
         "platform-neutral checks apply to this site.")
        if platform else "")
    add("In front of the site",
        ", ".join(headers.get("edge", [])) or "nothing identified")
    add("Platform", ", ".join(headers.get("generators", []))
        or "not published (good)")
    add("Core version by source",
        "; ".join(f"{k}: {v}" for k, v in
                  (headers.get("core_versions") or {}).items()))
    theme_info = headers.get("theme_info") or {}
    add("Theme", ", ".join(
        f"{slug}"
        + (f" {theme_info[slug]['version']}"
           if theme_info.get(slug, {}).get("version") else "")
        + (f" (child of {theme_info[slug]['parent']})"
           if theme_info.get(slug, {}).get("parent") else "")
        for slug in headers.get("theme", [])))
    add("Version-disclosing headers",
        ", ".join(f"{k}: {v}" for k, v in headers.get("leaky", {}).items()))
    add("Plugins named in the homepage HTML",
        f"{len(headers.get('homepage_plugins', []))} "
        f"({', '.join(headers.get('homepage_plugins', [])[:12])})")
    add("Plugins registering a REST namespace",
        f"{len(rest.get('third_party', []))} across "
        f"{rest.get('route_count', 0)} routes")
    add("Pages swept for plugin versions",
        f"{assets.get('pages_checked', 0)} of "
        f"{assets.get('pages_in_sitemap', 0)} in the sitemap")
    add("Cache states seen during the sweep",
        ", ".join(assets.get("cache_states", [])) or "none reported")
    add("TLS", f"{tls.get('protocol', '?')}, {tls.get('issuer', '?')}, "
               f"expires {tls.get('expires', '?')}"
        if tls and "error" not in tls else "")
    add("Plain HTTP",
        f"HTTP {transport.get('http', {}).get('status', '?')}"
        + (f" to {transport['http']['location']}"
           if transport.get("http", {}).get("location") else ""))
    add("XML-RPC", "answering"
        if transport.get("xmlrpc", {}).get("answering") else "not answering")
    add("security.txt", "present"
        if transport.get("security_txt", {}).get("present") else "absent")
    add("SPF", dns.get("spf") or "absent")
    add("DMARC", dns.get("dmarc")
        or (f"delegated to {dns['dmarc_delegated_to']}"
            if dns.get("dmarc_delegated_to") else "absent"))

    body = "".join(f"<tr><th scope='row'>{escape(k)}</th>"
                   f"<td>{escape(str(v))}</td></tr>" for k, v in rows)
    return (f"<div class='scroll'><table class='kv'><tbody>{body}"
            f"</tbody></table></div>")


def _paths_appendix(ctx: RunContext) -> str:
    """Every path probed, with its result.

    Without this a reader cannot tell "checked and clean" from "not checked",
    which is the difference between a report and a reassurance.
    """
    rows = ctx.data("paths")
    if not rows:
        return "<p>The path module did not run, so nothing here was checked.</p>"
    body = ""
    for r in sorted(rows, key=lambda r: r["path"]):
        verdict = r.get("verdict") or ("readable" if r["exposed"] else "not readable")
        verdict = verdict.upper() if r["exposed"] else verdict
        cls = ("bad" if r["exposed"] else
               "warn-cell" if verdict in ("no answer", "rate limited",
                                          "answered, unexpected content")
               else "good")
        redirect = (f" (redirect {r['no_redirect_status']})"
                    if 300 <= (r["no_redirect_status"] or 0) < 400 else "")
        body += (f"<tr><td><code>{escape(r['path'])}</code></td>"
                 f"<td>{escape(str(r['status']))}{escape(redirect)}</td>"
                 f"<td>{r['bytes']}</td>"
                 f"<td class='{cls}'>{verdict}</td></tr>")
    return (f"<p>All {len(rows)} paths requested during this run, including "
            f"the ones that came back clean. Every result below was compared "
            f"against how this site answers a path that cannot exist. "
            f"<em>No answer</em> and <em>rate limited</em> mean the path was "
            f"not checked; <em>answered, unexpected content</em> means a 200 "
            f"came back without the content that file would have.</p>"
            f"<div class='scroll'><table><thead><tr><th>Path</th>"
            f"<th>Status</th><th>Bytes</th><th>Verdict</th></tr></thead>"
            f"<tbody>{body}</tbody></table></div>")


def _methodology_block(ctx: RunContext) -> str:
    cal = ctx.data("calibration") or {}
    sig = cal.get("signature", {})
    control = cal.get("control", {})
    lines = []

    if sig.get("redirects_unknown_paths"):
        lines.append(
            "<p><strong>This site redirects unknown paths.</strong> A request "
            f"for a filename that cannot exist returns HTTP "
            f"{sig.get('no_redirect_status')} and lands on a real page. A "
            "checker that follows redirects would report every file it asked "
            "for as present, which is how an early version of this tool "
            "produced five critical findings that were all false. Path "
            "results below were each compared against that signature, and a "
            "file is reported only when it answers differently.</p>")
    elif sig.get("status") == 200:
        lines.append(
            "<p><strong>This site answers unknown paths with HTTP 200.</strong> "
            "A themed not-found page is served with a success status, so "
            "status alone proves nothing. Each result was compared against "
            "a fingerprint of that page.</p>")
    else:
        lines.append(
            f"<p>This site answers a path that cannot exist with HTTP "
            f"{sig.get('status')}, so a readable file is unambiguous.</p>")

    if not sig.get("stable") and sig.get("status") == 200:
        lines.append(
            "<p class='warn'><strong>Calibration was not conclusive.</strong> "
            "Repeated requests for different nonsense filenames returned "
            "pages that still differ after normalising, so a real file "
            "cannot be told apart from this site's not-found page by "
            "machine. Path findings are reported as unverified and need a "
            "person to open two or three of them in a browser.</p>")

    if control:
        if control.get("classified_present"):
            lines.append(
                f"<p><strong>The calibration was proved not to hide real "
                f"files.</strong> A control request for "
                f"<code>{escape(control.get('control_path', ''))}</code>, a "
                "file that exists on essentially every site, was still "
                "classified as present after the same filtering that "
                "discards false hits. Without this control, a calibration "
                "that suppressed everything would produce an empty report "
                "and read as a clean result.</p>")
        elif control.get("ran") is False:
            lines.append(f"<p class='warn'><strong>The calibration control "
                         f"could not run.</strong> {escape(control.get('note', ''))}"
                         "</p>")
        elif control.get("note"):
            lines.append(f"<p class='warn'><strong>Calibration control "
                         f"failed.</strong> {escape(control['note'])}</p>")

    headers = ctx.data("headers") or {}
    if headers.get("edge"):
        lines.append(
            f"<p><strong>Something sits in front of this site:</strong> "
            f"{escape(', '.join(headers['edge']))}. A 403 or 404 in this "
            "report may be the edge answering rather than the file being "
            "absent, and a version read through a cache may lag the origin. "
            "Findings here describe what an outsider sees, which is the "
            "point, but a clean path result behind a WAF is weaker evidence "
            "than the same result from a bare server.</p>")
    if headers.get("challenged"):
        lines.append(
            "<p class='warn'><strong>The homepage answered with a challenge "
            "or block page.</strong> Every module after that was reading the "
            "edge, not the site. Treat this report as a description of the "
            "WAF and re-run from an address the WAF trusts.</p>")

    media = ctx.data("media") or {}
    if media.get("gap"):
        lines.append(
            f"<p><strong>The media library was not fully enumerable.</strong> "
            f"The endpoint reports {media['reported_total']} items and a "
            f"complete walk returned {media['walked']}. Statements in this "
            "report about what is or is not in the library cover the "
            f"{media['walked']} items that came back, not all "
            f"{media['reported_total']}.</p>")

    lines.append(
        "<p><strong>What this run did not do.</strong> Every request was a "
        "GET or a HEAD. No form was submitted, no password was guessed, no "
        "injection payload was sent, no load test was run, and nothing "
        "behind a login was touched. That means this cannot find injection "
        "flaws, broken access control behind a login, or anything a "
        "read-only request will not reveal. A real penetration test covers "
        "those and needs written authorisation from both the site owner and "
        "the host.</p>")
    lines.append(
        "<p><strong>The media library is not the filesystem.</strong> Files "
        "an older install uploaded, or files deleted from the library while "
        "the file stayed on disk, appear in neither the REST response nor "
        "wp-admin, and stay downloadable. The authoritative inventory is a "
        "directory walk on the server, which this tool deliberately does "
        "not do.</p>")
    return "".join(lines)


def _coverage_block(ctx: RunContext) -> str:
    rows = ""
    for key, entry in sorted(ctx.manifest["modules"].items()):
        if entry["status"] in ("ok",):
            continue
        title = MODULE_BY_KEY.get(key, {}).get("title", key)
        note = entry.get("note", "")
        if entry["status"] == "partial" and entry.get("rows"):
            note = (f"{entry['rows']} row(s) collected and checked "
                    f"({key}.json); {note}")
        rows += (f"<tr><td>{escape(title)}</td>"
                 f"<td>{escape(entry['status'])}</td>"
                 f"<td>{escape(note or '-')}</td></tr>")
    if not rows:
        return ("<p class='good'>Every module ran and returned data. "
                "Nothing in the list of checks was skipped.</p>")
    return (
        "<p>These areas were not fully audited on this run, for the reason "
        "given. <strong>skipped</strong> and <strong>error</strong> mean no "
        "data at all, so absence from the findings above does not mean they "
        "are clean. <strong>empty</strong> means the endpoint answered but "
        "returned nothing, which is usually the safe state. "
        "<strong>partial</strong> means the rows that did come back were "
        "collected and checked. <strong>not applicable</strong> means the "
        "check is WordPress-specific and this is not a WordPress site.</p>"
        f"<div class='scroll'><table><thead><tr><th>Area</th><th>Status</th>"
        f"<th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div>")


def _checks_block() -> str:
    rows = "".join(
        f"<tr><td><code>{escape(m['key'])}</code></td>"
        f"<td>{escape(m['title'])}</td><td>{escape(m['about'])}</td></tr>"
        for m in MODULES)
    return (f"<p>Every module this tool runs, whether or not it produced a "
            f"finding.</p><div class='scroll'><table><thead><tr>"
            f"<th>Key</th><th>Area</th><th>What it looks at</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>")


REPORT_CSS = """
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
         Arial, sans-serif; margin: 0; color: #1d2733; background: #f5f6f8;
         line-height: 1.55; }
  header.page { background: #1a2733; color: #fff; padding: 32px 24px; }
  header.page .inner { max-width: 1180px; margin: 0 auto; }
  header.page h1 { margin: 0 0 6px; font-size: 26px; }
  header.page p { margin: 0; color: #b8c4cf; font-size: 14px; }
  header.page a { color: #9fd0ff; }
  .layout { max-width: 1180px; margin: 0 auto; padding: 24px;
            display: grid; grid-template-columns: 232px 1fr; gap: 24px;
            align-items: start; }
  nav.toc { position: sticky; top: 16px; background: #fff; border-radius: 8px;
            padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.12);
            max-height: calc(100vh - 32px); overflow-y: auto; }
  nav.toc h2 { font-size: 12px; text-transform: uppercase;
               letter-spacing: .06em; color: #667; margin: 0 0 10px; }
  nav.toc ol { list-style: none; margin: 0 0 14px; padding: 0; }
  nav.toc li { margin: 0 0 2px; }
  nav.toc a { display: block; padding: 5px 8px; border-radius: 5px;
              text-decoration: none; color: #2b3a4a; font-size: 13px; }
  nav.toc a:hover { background: #eef2f6; }
  nav.toc .pill { display: inline-block; min-width: 20px; text-align: center;
                  color: #fff; font-size: 10px; font-weight: 700;
                  border-radius: 10px; padding: 1px 6px; margin-right: 6px; }
  main { min-width: 0; }
  .tiles { display: flex; gap: 12px; margin: 0 0 20px; flex-wrap: wrap; }
  .tile { background: #fff; border-radius: 8px; padding: 14px 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,.12); min-width: 104px;
          text-align: center; flex: 1 1 104px; }
  .tile .num { font-size: 30px; font-weight: 700; line-height: 1.1; }
  .tile .lbl { color: #667; font-size: 12px; text-transform: uppercase;
               letter-spacing: .05em; }
  section.card { background: #fff; border-radius: 8px; padding: 18px 24px;
          margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.12);
          scroll-margin-top: 16px; }
  section.card h2 { font-size: 19px; margin: 0 0 12px; }
  section.card h3 { font-size: 17px; margin: 0 0 10px; line-height: 1.35; }
  section.card p { margin: 0 0 10px; }
  .sev { color: #fff; font-size: 11px; font-weight: 700; padding: 3px 8px;
         border-radius: 4px; vertical-align: middle; margin-right: 8px;
         letter-spacing: .04em; }
  .label { font-weight: 700; color: #35485c; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { text-align: left; padding: 7px 10px; vertical-align: top;
           border-bottom: 1px solid #e4e7ea; }
  th { background: #f0f2f4; font-weight: 600; }
  table.kv th { width: 34%; background: #fafbfc; }
  .scroll { overflow-x: auto; margin: 12px 0 4px; }
  .more { color: #667; font-size: 12px; }
  .good { color: #1d7a4c; }
  .bad { color: #c0392b; font-weight: 600; }
  .warn-cell { color: #9a6b00; font-weight: 600; }
  .warn { background: #fdf6e3; border-left: 4px solid #d4a017;
          padding: 10px 14px; border-radius: 0 4px 4px 0; }
  code { background: #f0f2f4; padding: 1px 5px; border-radius: 3px;
         font-size: 12px; word-break: break-all; }
  footer { color: #667; font-size: 12px; padding: 24px; text-align: center; }
  footer a { color: #35485c; }
  @media (max-width: 860px) {
    .layout { grid-template-columns: 1fr; }
    nav.toc { position: static; max-height: none; }
  }
  @media print {
    body { background: #fff; }
    nav.toc { display: none; }
    .layout { display: block; max-width: none; padding: 0; }
    section.card, .tile { box-shadow: none; border: 1px solid #ccc;
                          page-break-inside: avoid; }
    a { color: #222; text-decoration: none; }
  }
"""


def render_html(ctx: RunContext, findings: List[Finding]) -> Path:
    print_header("STAGE 3 - RENDER")
    site = ctx.site
    host = urllib.parse.urlparse(site).netloc or site
    counts = {sev: sum(1 for f in findings if f.severity == sev)
              for sev in SEVERITY_ORDER}

    tiles = "".join(
        f"<div class='tile' style='border-top:5px solid "
        f"{SEVERITY_COLOURS[sev]}'><div class='num'>{counts[sev]}</div>"
        f"<div class='lbl'>{sev.title()}</div></div>"
        for sev in SEVERITY_ORDER)

    # Findings, each its own anchored card, plus a contents entry.
    toc_findings = ""
    sections = ""
    for finding in findings:
        anchor = f"f-{_slug(finding.fid)}"
        colour = SEVERITY_COLOURS[finding.severity]
        toc_findings += (
            f"<li><a href='#{anchor}'><span class='pill' "
            f"style='background:{colour}'>{escape(finding.severity[0])}</span>"
            f"{escape(finding.title)}</a></li>")
        sections += f"""
<section class='card' id='{anchor}'>
  <h3><span class='sev' style='background:{colour}'>{escape(finding.severity)}</span>{escape(finding.title)}</h3>
  <p><span class='label'>What this means:</span> {escape(finding.meaning)}</p>
  <p><span class='label'>What to do:</span> {escape(finding.remediation)}</p>
  {_evidence_table(finding)}
</section>"""
    if not findings:
        sections = ("<section class='card' id='f-none'><h3>No findings</h3>"
                    "<p>Nothing this tool checks came back exposed. Read the "
                    "Coverage and Methodology sections before treating that "
                    "as a clean result: they say what was checked and what "
                    "this run could not see.</p></section>")
        toc_findings = "<li><a href='#f-none'>No findings</a></li>"

    appendices = [
        ("profile", "Site profile", _profile_block(ctx)),
        ("paths-appendix", "Every path checked", _paths_appendix(ctx)),
        ("coverage", "Coverage gaps", _coverage_block(ctx)),
        ("checks", "What this tool checks", _checks_block()),
        ("methodology", "Methodology and limits", _methodology_block(ctx)),
    ]
    toc_appendix = "".join(
        f"<li><a href='#{a}'>{escape(t)}</a></li>" for a, t, _ in appendices)
    appendix_html = "".join(
        f"<section class='card' id='{a}'><h2>{escape(t)}</h2>{b}</section>"
        for a, t, b in appendices)

    worst = next((f.severity for f in findings
                  if f.severity in ("CRITICAL", "HIGH")), None)
    headline = (f"{counts['CRITICAL']} critical and {counts['HIGH']} high "
                f"finding(s) need attention."
                if worst else
                "Nothing critical or high was found. Read the coverage and "
                "methodology sections before calling the site clean.")
    platform = ctx.manifest["meta"].get("platform", {})
    if platform.get("decided") and not platform.get("wordpress"):
        headline = ("This does not appear to be a WordPress site: none of "
                    "the WordPress markers were found. Only the "
                    "platform-neutral checks (security headers, TLS, cookies, "
                    "mail DNS, common exposed files) were run, and the "
                    "WordPress-specific ones are listed under Coverage gaps as "
                    "not applicable. " + headline)

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta name='robots' content='noindex,nofollow'>
<title>WordPress exposure audit - {escape(host)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<header class='page'>
  <div class='inner'>
    <h1>WordPress exposure audit</h1>
    <p><a href='{escape(site)}'>{escape(site)}</a> &middot;
       generated {escape(generated)} &middot;
       wp_audit.py v{SCRIPT_VERSION} &middot;
       read-only: GET and HEAD requests only</p>
  </div>
</header>
<div class='layout'>
<nav class='toc' aria-label='Contents'>
  <h2>Findings</h2>
  <ol>{toc_findings}</ol>
  <h2>Reference</h2>
  <ol>{toc_appendix}</ol>
</nav>
<main>
  <div class='tiles'>{tiles}</div>
  <section class='card' id='how-to-read'>
    <h2>How to read this report</h2>
    <p>{escape(headline)}</p>
    <p>Findings are ordered by severity. Each one says what was found, why it
    matters and what to do about it, with a sample of the affected items;
    the full lists are in the JSON files next to this report. Severity here
    describes what an attacker gains, not how hard the fix is.</p>
    <p><strong>Critical</strong> means someone can take the site over today.
    <strong>High</strong> means they get material help towards that.
    <strong>Medium</strong> and <strong>low</strong> are hardening: worth
    doing, not worth an evening. <strong>Info</strong> is context you should
    know rather than something to fix.</p>
    <p>Before treating a quiet report as good news, read
    <a href='#coverage'>Coverage gaps</a> and
    <a href='#methodology'>Methodology and limits</a>. This is an external,
    read-only check. It is not a penetration test, and a clean result here is
    not a clean bill of health.</p>
  </section>
  {sections}
  {appendix_html}
</main>
</div>
<footer>
  Produced by wp_audit.py v{SCRIPT_VERSION} &middot;
  Paul Ogier, <a href='https://osh.co.za'>Outsource House</a> &middot;
  training at <a href='https://taming.tech'>Taming.Tech</a> &middot;
  print this page for a PDF copy.
</footer>
</body>
</html>"""

    out_path = ctx.run_dir / "exposure_report.html"
    out_path.write_text(html, encoding="utf-8")
    print_success(f"Report written: {out_path}")

    findings_json = ctx.run_dir / "findings.json"
    findings_json.write_text(json.dumps([{
        "id": f.fid, "severity": f.severity, "title": f.title,
        "meaning": f.meaning, "remediation": f.remediation,
        "count": f.count, "source": f.source, "evidence": f.evidence,
    } for f in findings], indent=2), encoding="utf-8")
    print_success(f"Findings JSON written: {findings_json}")
    return out_path


###############################################################################
# SELFTEST
###############################################################################

def selftest() -> int:
    """Exercise the decision logic against synthetic responses, no network.

    These are the shapes that have each produced a wrong report. A change
    that breaks one of them is a regression, not a refactor.
    """
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, wanted {want!r}")

    # 1. A site that 301s every unknown path to the homepage. The homepage
    #    body is real content and a following client reports it as the file.
    redirecting = {"status": 200, "no_redirect_status": 301,
                   "redirects_unknown_paths": True, "stable": True,
                   "fingerprint": body_fingerprint("<h1>Welcome</h1>")}
    check("301 site: nonsense path rejected",
          path_is_exposed("/backup.sql", 200, "<h1>Welcome</h1>",
                          redirecting, 301), False)
    check("301 site: a real file is still reported",
          path_is_exposed("/license.txt", 200, "GNU GENERAL PUBLIC LICENSE",
                          redirecting, 200), True)

    # 2. A themed 404 served with status 200, where the body echoes the path
    #    that was asked for. Comparing raw lengths fails here; the
    #    fingerprint removes the echoed token first.
    probe_name = "zz-does-not-exist-aaaa.zip"
    template = "<h1>Sorry</h1><p>Nothing at /{}</p><p>Try search.</p>"
    body_a = template.format(probe_name)
    body_b = template.format("backup.zip")
    soft = {"status": 200, "no_redirect_status": 200,
            "redirects_unknown_paths": False, "stable": True,
            "fingerprint": body_fingerprint(body_a, probe_name)}
    check("soft 404 echoing the path is still recognised",
          path_is_exposed("/backup.zip", 200, body_b, soft, 200), False)
    check("a real file on the same site is still reported",
          path_is_exposed("/backup.zip", 200,
                          "PK\x03\x04 binary archive contents", soft, 200),
          True)

    # 3. A soft 404 carrying a nonce never matches itself, so calibration is
    #    inconclusive. That must be visible, not silently ignored: an
    #    unstable signature used to let all five false criticals through.
    unstable = {"status": 200, "no_redirect_status": 200,
                "redirects_unknown_paths": False, "stable": False,
                "fingerprint": ""}
    check("unstable calibration is flagged ambiguous",
          calibration_is_ambiguous(unstable), True)
    check("clean 404 site needs no fingerprint",
          calibration_is_ambiguous({"status": 404, "stable": False}), False)
    check("stable calibration is not ambiguous",
          calibration_is_ambiguous(soft), False)

    # 4. The installer answers on every WordPress site. Only an installer
    #    that still offers to install is a finding.
    check("install.php 'Already Installed' is not a finding",
          path_is_exposed("/wp-admin/install.php", 200,
                          "<h1>Already Installed</h1>", None, 200), False)
    check("install.php offering to install IS a finding",
          path_is_exposed("/wp-admin/install.php", 200,
                          "<h1>Welcome</h1><form>Site Title</form>",
                          None, 200), True)

    # 5. A directory is only listed when the body says so; an empty 200 from
    #    an index.php exposes nothing.
    check("empty directory 200 is not a listing",
          path_is_exposed("/wp-content/uploads/", 200, "", None, 200), False)
    check("real directory listing is reported",
          path_is_exposed("/wp-content/uploads/", 200,
                          "<h1>Index of /wp-content/uploads</h1>",
                          None, 200), True)

    # 6. A real but empty file on a file path is still a file. Requiring a
    #    non-empty body hid a truncated dump.
    check("empty file on a file path is reported",
          path_is_exposed("/.env", 200, "", None, 200), True)

    # 7. Non-200 is never exposed, whatever the body says.
    check("403 is not exposed",
          path_is_exposed("/.env", 403, "Forbidden", None, 403), False)

    # 8. The fingerprint must ignore digits and whitespace but not words.
    check("fingerprint ignores counters",
          body_fingerprint("<p>7 posts</p>") ==
          body_fingerprint("<p>412 posts</p>"), True)
    check("fingerprint still separates different pages",
          body_fingerprint("<p>welcome</p>") ==
          body_fingerprint("<p>not found</p>"), False)

    # 9. Findings sort by severity, so the report leads with the worst.
    order = [f.severity for f in sorted(
        [Finding("b", "LOW", "t", "m", "r", [], "s"),
         Finding("a", "CRITICAL", "t", "m", "r", [], "s"),
         Finding("c", "MEDIUM", "t", "m", "r", [], "s")],
        key=lambda f: SEVERITY_ORDER.index(f.severity))]
    check("findings sort worst-first", order, ["CRITICAL", "MEDIUM", "LOW"])

    # 10. Evidence tables take the union of keys: rows from different joins
    #     legitimately carry different columns, and row 0's keys would drop
    #     the rest.
    finding = Finding("x", "INFO", "t", "m", "r",
                      [{"A": 1}, {"B": 2}], "s")
    table = _evidence_table(finding)
    check("evidence table keeps both columns",
          "<th>A</th>" in table and "<th>B</th>" in table, True)

    # 11. Evidence is capped, and the report says so rather than silently
    #     truncating.
    big = Finding("y", "INFO", "t", "m", "r",
                  [{"n": i} for i in range(EVIDENCE_ROWS + 5)], "s")
    check("evidence is capped", len(big.evidence), EVIDENCE_ROWS)
    check("truncation is disclosed", "Showing" in _evidence_table(big), True)

    # 12. Report HTML escapes evidence: a filename is attacker-influenced
    #     input and must not become markup.
    nasty = Finding("z", "INFO", "t", "m", "r",
                    [{"URL": "<script>alert(1)</script>"}], "s")
    check("evidence is escaped",
          "<script>" not in _evidence_table(nasty), True)

    # 13. Version ordering. A string comparison puts 1.10 below 1.9, which
    #     would clear a plugin that is actually inside the affected range.
    check("1.10 sorts above 1.9",
          version_key("1.10") > version_key("1.9"), True)
    check("a prerelease sorts below its release",
          version_key("6.6.0-beta1") < version_key("6.6.0"), True)
    check("2.0 and 2.0.0 are the same version",
          version_key("2.0") == version_key("2.0.0"), True)
    check("an unparseable version is not ordered",
          version_ordered("latest"), False)

    # 14. Vulnerability range matching, including the shapes the feed
    #     actually uses: "lt" on 93 of 96 WooCommerce records, "le" and "eq"
    #     on the rest, "ge" as the only lower bound seen.
    lt = {"max_version": "3.6.3", "max_operator": "lt"}
    check("a version inside a < range matches", vuln_applies("3.6.2", lt), True)
    check("the fixed version itself does not match",
          vuln_applies("3.6.3", lt), False)
    check("a beta of the fixed version is still affected",
          vuln_applies("3.6.3-beta1", lt), True)
    check("<= includes its bound",
          vuln_applies("2.1", {"max_version": "2.1", "max_operator": "le"}), True)
    check("= matches only itself",
          vuln_applies("2.2", {"max_version": "2.1", "max_operator": "eq"}), False)
    banded = {"min_version": "4.0", "min_operator": "ge",
              "max_version": "4.9", "max_operator": "lt"}
    check("a banded range excludes below the floor",
          vuln_applies("3.9", banded), False)
    check("a banded range includes the middle",
          vuln_applies("4.5", banded), True)

    # 15. An undecidable record is not a clean one. An operator this code
    #     does not implement, or a range with no bound at all, must return
    #     None so it can be counted and disclosed rather than dropped.
    check("an unknown operator is undecidable",
          vuln_applies("1.0", {"max_version": "2.0", "max_operator": "between"}),
          None)
    check("a range with no bounds is undecidable",
          vuln_applies("1.0", {"max_version": None, "min_version": None}), None)
    check("an unreadable running version is undecidable",
          vuln_applies("", lt), None)

    # 16. The single most dangerous shape in this module: wpvulnerability
    #     answers 200 with vulnerability:null BOTH for a plugin it has
    #     cleared and for a slug it has never heard of. Only data.name tells
    #     them apart. Reading the second as clean would put a green tick on
    #     every premium and custom plugin on the site.
    real_fetch_json = globals()["fetch_json"]
    try:
        globals()["fetch_json"] = lambda url: (200, {}, {
            "error": 0, "data": {"name": "Classic Editor",
                                 "plugin": "classic-editor",
                                 "vulnerability": None}})
        check("a known plugin with no vulnerabilities is covered",
              _wpvuln("plugin", "classic-editor")["covered"], True)
        globals()["fetch_json"] = lambda url: (200, {}, {
            "error": 0, "data": {"name": None, "plugin": "nope",
                                 "vulnerability": None}})
        check("a slug with no record is NOT covered",
              _wpvuln("plugin", "nope")["covered"], False)
        globals()["fetch_json"] = lambda url: (200, {}, None)
        check("a truncated or non-JSON body is NOT covered",
              _wpvuln("plugin", "huge")["covered"], False)
    finally:
        globals()["fetch_json"] = real_fetch_json

    # 16b. A withdrawn plugin is served as HTTP 404 with a body saying so,
    #      exactly like a plugin that never existed. Reading the status
    #      instead of the body reported two plugins closed for cause on a
    #      live site as "not in the directory", losing the finding entirely.
    real_fetch = globals()["fetch"]
    try:
        globals()["fetch"] = lambda *a, **k: (404, {}, json.dumps({
            "error": "closed", "closed": True, "closed_date": "2025-04-26",
            "reason": "author-request", "reason_text": "Author Request",
            "name": "Code Syntax Block", "slug": "code-syntax-block"}))
        closed = _currency("https://example.test", ["1.0"])
        check("a 404 closed response is still found", closed["found"], True)
        check("a closed plugin is flagged closed", closed["closed"], True)
        check("the closure reason is carried through",
              closed["closed_reason"], "Author Request")
        globals()["fetch"] = lambda *a, **k: (404, {}, json.dumps(
            {"error": "Plugin not found."}))
        check("a genuinely unknown plugin is not found",
              _currency("https://example.test", ["1.0"])["found"], False)
    finally:
        globals()["fetch"] = real_fetch

    # 16c. A cache-busting timestamp is not a version. Complianz served
    #      ?ver=1781763570 on a live site; it passed the hash filter and was
    #      then compared against real release numbers.
    check("a Unix timestamp is not treated as a version",
          bool(re.fullmatch(r"1[0-9]{9}", "1781763570")), True)
    check("a real version is not mistaken for a timestamp",
          bool(re.fullmatch(r"1[0-9]{9}", "1.7.0")), False)

    # 17. Severity comes from the published CVSS score, not from this tool.
    #     An unscored record is unknown, and unknown is not low.
    check("9.8 is critical", cvss_severity(9.8), "CRITICAL")
    check("7.0 is high", cvss_severity(7.0), "HIGH")
    check("3.9 is low", cvss_severity(3.9), "LOW")
    check("unscored is medium, not low", cvss_severity(0.0), "MEDIUM")
    check("a cap lowers", cap_severity("CRITICAL", "MEDIUM"), "MEDIUM")
    check("a cap never raises", cap_severity("LOW", "MEDIUM"), "LOW")
    check("a redirect is labelled as one in the appendix",
          path_verdict("/backup.zip", 200, "<h1>Home</h1>", False, 301),
          "redirected (not a file)")

    # 18. Row extraction keeps the matching records and counts the rest.
    record = {"vulnerability": [
        {"name": "affected", "operator": {"max_version": "2.0", "max_operator": "lt"},
         "impact": {"cvss": {"score": "8.8"}},
         "source": [{"id": "CVE-2026-0001", "link": "https://example.test"}]},
        {"name": "already fixed", "operator": {"max_version": "1.0", "max_operator": "lt"},
         "impact": {}, "source": []},
        {"name": "undecidable", "operator": {"max_operator": "between"},
         "impact": {}, "source": []},
    ]}
    rows, undecidable = _vuln_rows(record, "1.5")
    check("only the covering record matches", [r["name"] for r in rows], ["affected"])
    check("the CVE is carried through", rows[0]["cve"], "CVE-2026-0001")
    check("an undecidable record is counted, not dropped", undecidable, 1)

    # 19. Several Set-Cookie headers. A dict comprehension keeps only the
    #     last one, and splitting on commas breaks on an Expires date. Seen
    #     as a cookie called "21 Oct 2026 07:28:00 GMT; Path".
    import email.message
    msg = email.message.Message()
    msg["Set-Cookie"] = "a=1; Path=/; Secure; HttpOnly"
    msg["Set-Cookie"] = "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/"
    joined = _headers(msg)["set-cookie"]
    check("both cookies survive the header dict", joined.count("\n"), 1)
    check("cookie names parse cleanly",
          [c.split("=", 1)[0] for c in joined.split("\n")], ["a", "b"])

    # 20. A path that answers 200 with the wrong content is not readable. A
    #     WAF page or a soft 404 at /backup.sql is not a database dump.
    check("a 200 at .sql without SQL in it is not a dump",
          path_is_exposed("/backup.sql", 200, "<html>Blocked</html>", None, 200),
          False)
    check("a real dump is",
          path_is_exposed("/backup.sql", 200, "-- MySQL dump\nCREATE TABLE x",
                          None, 200), True)
    check("a 200 challenge page at install.php is not an open installer",
          path_is_exposed("/wp-admin/install.php", 200,
                          "<title>Just a moment...</title>", None, 200), False)
    check("an empty .env is still reported",
          path_is_exposed("/.env", 200, "", None, 200), True)
    check("an empty 200 gets the verdict 'empty'",
          path_verdict("/.env", 200, "", True), "empty")
    check("a timeout is 'no answer', never 'not readable'",
          path_verdict("/.env", 0, "", False), "no answer")

    # 21. The installer needs a positive marker; the mere absence of
    #     "Already Installed" is not evidence.
    check("the language chooser is an open installer",
          path_is_exposed("/wp-admin/install.php", 200,
                          "<select name='language' id='language-chooser'>",
                          None, 200), True)

    # 22. Edge identification and challenge pages.
    edge = edge_identity({"cf-ray": "abc", "server": "cloudflare",
                          "x-kinsta-cache": "HIT"}, "<title>Just a moment...</title>")
    check("edge names both layers", edge["edge"], ["Cloudflare", "Kinsta"])
    check("a challenge body is recognised", edge["challenged"], True)
    check("an ordinary body is not",
          edge_identity({"server": "nginx"}, "<h1>Hello</h1>")["challenged"], False)

    # 23. The REST index is bigger than a page and must not be read with the
    #     page cap. A truncated body sets _truncated so the caller can tell
    #     "cut off" from "not JSON".
    try:
        big = json.dumps({"routes": {f"/x/v1/r{i}": {} for i in range(30000)},
                          "namespaces": ["x/v1"]})

        class _Resp:
            status = 200
            headers = email.message.Message()

            def __init__(self, data):
                self._d = data

            def read(self, n):
                return self._d[:n]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        real_open = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=0: _Resp(big.encode())
        real_delay = globals()["REQUEST_DELAY"]
        globals()["REQUEST_DELAY"] = 0
        st, hd, body = fetch("https://example.test/wp-json/")
        check("a body at the page cap is flagged truncated",
              bool(hd.get("_truncated")), True)
        st, hd, body = fetch("https://example.test/wp-json/",
                             max_bytes=REST_INDEX_MAX_BYTES)
        check("the REST cap reads the whole index",
              json.loads(body)["namespaces"], ["x/v1"])
    finally:
        urllib.request.urlopen = real_open
        globals()["REQUEST_DELAY"] = real_delay

    # 24. A plugin that ships assets under several version strings on the
    #     SAME page is not a caching problem. Only pages that disagree with
    #     each other are.
    fake_assets = {"plugins": {"lib": {"versions": ["1.0", "2.0"], "pages": 2},
                               "cached": {"versions": ["3.0", "3.1"], "pages": 2}},
                   "pages": [{"url": "a", "cache": "", "plugins": ["lib 1.0", "lib 2.0", "cached 3.0"]},
                             {"url": "b", "cache": "", "plugins": ["lib 1.0", "lib 2.0", "cached 3.1"]}]}

    class _Ctx:
        def data(self, key):
            return fake_assets
    mixed = [f for f in check_assets(_Ctx()) if f.fid == "assets-mixed"]
    check("only the page-disagreeing plugin is reported as mixed",
          [e["Plugin"] for e in mixed[0].evidence] if mixed else [], ["cached"])

    # 25. A robots.txt Disallow list yields probe rows, minus wildcards,
    #     core directories and the default /wp-admin/ line.
    rows = _robots_probe_rows(["/wp-admin/", "/private/", "/*.pdf$", "/exports/",
                               "/wp-includes/", "https://x/"])
    check("robots rows keep only concrete non-core paths",
          [r[0] for r in rows], ["/private/", "/exports/"])

    # 26. Site-named backups derive from the host, not a static list.
    names = [p for p, _, _ in _site_named_backups("https://www.example.com")]
    check("site-named backups include the bare domain and stem",
          "/example.com.zip" in names and "/example.sql" in names, True)

    # 27. readme.txt Stable tag parsing rejects "trunk" and non-versions.
    real_fetch2 = globals()["fetch"]
    try:
        globals()["fetch"] = lambda *a, **k: (200, {}, "=== X ===\nStable tag: 4.2.1\n")
        check("stable tag is read", _readme_stable_tag("https://x", "p"), "4.2.1")
        globals()["fetch"] = lambda *a, **k: (200, {}, "Stable tag: trunk\n")
        check("trunk is not a version", _readme_stable_tag("https://x", "p"), "")
        globals()["fetch"] = lambda *a, **k: (200, {}, "<html>soft 404</html>")
        check("an HTML body is not a readme", _readme_stable_tag("https://x", "p"), "")
        globals()["fetch"] = lambda *a, **k: (200, {}, "/*\nTheme Name: Foo\nTemplate: bar\nVersion: 1.2.3\n*/")
        style = _theme_style("https://x", "foo")
        check("theme style.css yields version and parent",
              (style["version"], style["parent"]), ("1.2.3", "bar"))
    finally:
        globals()["fetch"] = real_fetch2

    if failures:
        print("selftest FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("selftest: all checks passed")
    return 0


###############################################################################
# CLI / MAIN
###############################################################################

def normalise_site(raw: str) -> Tuple[str, str]:
    """Return (site, note). Rejects a bare host and upgrades http to https.

    An http:// argument against a host that redirects to HTTPS is the most
    expensive mistake this tool can make: every real file 301s exactly like
    a missing one, the calibration discards all of them, and the run exits 0
    reporting nothing reachable. Upgrading here, and saying so in the
    report, is the fix. The control check in verify_calibration() is the
    backstop if it happens some other way.
    """
    site = raw.strip().rstrip("/")
    note = ""
    if not site:
        raise ValueError("a site is required")
    if "://" not in site:
        site = "https://" + site
        note = "no scheme was given, so https:// was assumed"
    parsed = urllib.parse.urlparse(site)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}://")
    if not parsed.netloc:
        raise ValueError(f"could not read a hostname from {raw!r}")

    # Where does the root actually live? Three shapes matter. http:// to
    # https:// on the same host is upgraded. example.com to www.example.com
    # (or back) is adopted: every unknown path on the bare host 301s to www,
    # so probing the bare host would classify every real file as missing.
    # A redirect to a DIFFERENT host is refused: one run audited a host whose
    # every path 301'd to another site's /blogs/ section, and the report
    # described that other site's homepage as this host's wp-cron.php.
    status, hdrs = fetch_no_redirect(site + "/")
    location = hdrs.get("location", "")
    if 300 <= status < 400 and location:
        target = urllib.parse.urlparse(urllib.parse.urljoin(site + "/", location))
        here = parsed.netloc.lower()
        there = target.netloc.lower()
        bare = here[4:] if here.startswith("www.") else here
        www_pair = there in (bare, "www." + bare) and there != here
        if target.scheme not in ("http", "https") or not there:
            pass
        elif there == here:
            if target.scheme == "https" and parsed.scheme == "http":
                site = "https://" + parsed.netloc
                note = ("the site was given as http:// but redirects to "
                        "HTTPS, so https:// was audited instead. Auditing the "
                        "http:// address would have reported every path as "
                        "absent, because on a redirecting host a real file "
                        "and a missing one answer identically.")
        elif www_pair and target.path in ("", "/"):
            site = f"{target.scheme}://{target.netloc}"
            note = (f"{parsed.netloc} redirects to {target.netloc}, so that "
                    "host was audited instead; on the host given, every path "
                    "redirects and a real file cannot be told from a missing "
                    "one.")
        else:
            raise ValueError(
                f"{site}/ redirects to {location}. This tool audits one host "
                "at its root and that is a different site, so it cannot say "
                "anything true about the address given. Run it against "
                f"{target.scheme}://{target.netloc} instead if that is the "
                "site you mean.")
    if site.startswith("http://"):
        note = note or ("audited over plain HTTP as given; this is almost "
                        "certainly not what you want")
    return site, note


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only external exposure audit of a WordPress site "
                    f"(v{SCRIPT_VERSION}). Collects the public surface, runs "
                    "a findings engine, renders a self-contained HTML "
                    "report.",
        epilog="Run this only against a site you own or have written "
               "permission to test.")
    parser.add_argument("--site", help="Site to audit, e.g. "
                        "https://www.example.com")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help=f"Root folder for run directories "
                             f"(default {OUTPUT_DIRECTORY})")
    parser.add_argument("--run-dir", type=Path, default=None,
                        help="Existing run directory to resume (completed "
                             "modules are skipped)")
    parser.add_argument("--only", help="Comma-separated module keys to run")
    parser.add_argument("--skip", help="Comma-separated module keys to skip")
    parser.add_argument("--url", action="append", default=[],
                        help="An extra document URL to check, for a file "
                             "found some other way such as through a search "
                             "engine. Repeatable.")
    parser.add_argument("--force", action="store_true",
                        help="Re-collect modules that already completed")
    parser.add_argument("--render-only", action="store_true",
                        help="Skip collection; re-run checks and render from "
                             "an existing --run-dir")
    parser.add_argument("--list", action="store_true",
                        help="List the module registry and exit")
    parser.add_argument("--no-open", action="store_true",
                        help="Do not open the finished report in a browser "
                             "(for headless or scheduled runs)")
    parser.add_argument("--no-colour", action="store_true",
                        help="Plain console output")
    parser.add_argument("--selftest", action="store_true",
                        help="Run the logic tests and exit; no network")
    args = parser.parse_args(argv)
    if args.render_only and not args.run_dir:
        # Without this the branch renders a fresh, empty directory: zero
        # findings, no coverage table, exit 0. That is the one report which
        # says nothing was checked and reads as clean.
        parser.error("--render-only needs --run-dir")
    if not (args.selftest or args.list or args.site or args.run_dir):
        parser.error("--site is required (or --run-dir to resume)")
    return args


def list_modules():
    print(f"wp_audit.py v{SCRIPT_VERSION} - module registry\n")
    for mod in MODULES:
        flag = "  [always runs]" if mod["required"] else ""
        print(f"  {mod['key']:<14} {mod['title']}{flag}")
        print(f"  {'':<14} {mod['about']}\n")


def open_report(path: Path, args) -> bool:
    """Open the finished report in the default browser.

    A file:// URI, not the bare path: on Linux webbrowser hands a bare path
    to the browser as a relative URL and it 404s. as_uri() needs an absolute
    path, and the default output directory is relative, so resolve first.
    """
    if args.no_open:
        return False
    try:
        opened = webbrowser.open(path.resolve().as_uri())
    except Exception as exc:                     # headless box, no browser
        print_warning(f"Could not open the report automatically: {exc}")
        return False
    if not opened:
        # webbrowser returns False rather than raising when none exists.
        print_warning(f"No browser found; open the report by hand: {path}")
    return opened


def main(argv=None):
    _force_utf8_console()
    if not _enable_windows_ansi() or not sys.stdout.isatty():
        Colours.strip_colours()
    signal.signal(signal.SIGINT, signal_handler)

    args = parse_args(argv)
    if args.no_colour:
        Colours.strip_colours()
    if args.selftest:
        return selftest()
    if args.list:
        list_modules()
        return 0

    scheme_note = ""
    if args.run_dir:
        run_dir = args.run_dir
        if not run_dir.is_dir():
            print(f"Run directory not found: {run_dir}")
            return 2
    else:
        try:
            args.site, scheme_note = normalise_site(args.site)
        except ValueError as exc:
            print(f"Bad --site: {exc}")
            return 2
        host = re.sub(r"[^a-z0-9]+", "_",
                      urllib.parse.urlparse(args.site).netloc.lower())
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = (args.output_dir or OUTPUT_DIRECTORY) / f"{host}_{stamp}"
        run_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(run_dir)
    print_header(f"WORDPRESS EXPOSURE AUDIT v{SCRIPT_VERSION}")
    ctx = RunContext(run_dir, args)
    print_info(f"Site:          {ctx.site}")
    print_info(f"Run directory: {run_dir}")
    if scheme_note:
        print_warning(scheme_note)
        ctx.manifest["meta"]["scheme_note"] = scheme_note
    ctx.manifest["meta"].setdefault(
        "started_at", datetime.now().isoformat(timespec="seconds"))
    ctx.save()

    if not args.render_only:
        check_for_updates()
        print_info("Read-only: GET and HEAD requests only. Nothing is "
                   "submitted, guessed or written.")
        collect(ctx, selected_modules(args))

    findings = run_checks(ctx)
    report_path = render_html(ctx, findings)

    if shutdown_requested:
        print_warning("Run was interrupted; the report covers the modules "
                      f"collected so far. Resume with --run-dir {run_dir}")
        open_report(report_path, args)
        return 130

    worst = next((f.severity for f in findings
                  if f.severity in ("CRITICAL", "HIGH")), None)
    if worst:
        print_warning(f"Highest severity found: {worst}. "
                      "Open exposure_report.html for the detail.")
    else:
        print_success("No critical or high findings. Read the Coverage and "
                      "Methodology sections before calling the site clean.")
    open_report(report_path, args)
    return 1 if worst else 0


if __name__ == "__main__":
    sys.exit(main())
