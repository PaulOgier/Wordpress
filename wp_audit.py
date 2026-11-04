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
Updated:      2026-11-04
Version:      1.13.0
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
a login. A full run is a few hundred ordinary page fetches. The one that
does work on the server is wp-cron.php, which runs any scheduled tasks due.

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
from html import escape, unescape
from pathlib import Path
from typing import Dict, List, Optional, Tuple

###############################################################################
# CONFIGURATION
###############################################################################

SCRIPT_VERSION = "1.13.0"
# Which exact file wrote a module: a version alone cannot tell apart the
# unreleased fixes made between releases, and a re-collect mixes them.
try:
    SCRIPT_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]
except OSError:
    SCRIPT_SHA = ""

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
EVIDENCE_ROWS_ALL = 5_000    # --standalone: the reader has no run
                             # directory, so truncating hides the rest
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
    ("/installer-log.txt", "MEDIUM", "the Duplicator installer's log, which names server paths, the database name and the migration's settings"),
    ("/wp-content/uploads/dump.sql", "CRITICAL", "a database dump in the uploads folder"),
    ("/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip", "CRITICAL", "a database migration archive"),
    ("/wp-content/backup-db/", "MEDIUM", "a browsable list of database backups"),
    ("/searchreplacedb2.php", "CRITICAL", "a database search-and-replace tool left on the server, which reads and rewrites the whole database with no login"),
    ("/emergency.php", "HIGH", "an emergency password-reset script, which can set a new administrator password"),
    # Credentials and configuration.
    ("/wp-config.php.bak", "CRITICAL", "the WordPress configuration file, which contains the database password"),
    ("/wp-config.php~", "CRITICAL", "an editor backup of the WordPress configuration file"),
    ("/wp-config.php.save", "CRITICAL", "an editor backup of the WordPress configuration file"),
    ("/wp-config.txt", "CRITICAL", "the WordPress configuration file as plain text"),
    ("/wp-config.old", "CRITICAL", "an old copy of the WordPress configuration file, which contains the database password"),
    ("/wp-config.php.old", "CRITICAL", "an old copy of the WordPress configuration file, which contains the database password"),
    ("/wp-config.php.orig", "CRITICAL", "a copy of the WordPress configuration file, which contains the database password"),
    ("/wp-config.bak", "CRITICAL", "a backup of the WordPress configuration file, which contains the database password"),
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
    ("/wp-includes/rss.php", "LOW", "a PHP error that prints the server's file path, so display_errors is on and every PHP warning reaches visitors; turn it off in the PHP settings"),
    # Developer artefacts. Not a way in, but they name every library and its
    # version, which is the shortlist of exploits worth trying.
    ("/composer.json", "LOW", "the Composer manifest, which lists the PHP packages installed and their versions"),
    ("/package.json", "LOW", "the Node manifest, which lists the JavaScript packages used to build the site"),
    ("/.DS_Store", "LOW", "a macOS folder index, which lists the names of every file in the directory including ones nothing links to"),
    ("/.wp-env.json", "LOW", "the wp-env development configuration, which names the plugins, themes and settings the site was built with"),
    ("/wp-cli.yml", "LOW", "the WP-CLI configuration, which can name server paths, SSH aliases and the site's internal address"),
    ("/.idea/workspace.xml", "LOW", "a JetBrains IDE workspace file, which names the developer's files, paths and recent changes"),
    ("/.vscode/settings.json", "LOW", "a VS Code settings file, which can name servers, paths and extensions"),
    ("/Dockerfile", "HIGH", "the container build file, which names the software stack and often build secrets"),
    ("/docker-compose.yml", "HIGH", "the Docker Compose file, which usually carries the database password"),
    ("/.ftpconfig", "CRITICAL", "an editor's FTP settings, which hold the server login"),
    ("/sftp-config.json", "CRITICAL", "Sublime Text's SFTP settings, which hold the server login"),
    ("/.remote-sync.json", "CRITICAL", "an editor's remote-sync settings, which hold the server login"),
    ("/web.config", "MEDIUM", "the IIS configuration, which names rewrite rules and sometimes connection strings"),
    ("/php.ini", "MEDIUM", "a PHP configuration file, which names paths and settings"),
    ("/.bash_history", "HIGH", "a shell history, which records commands typed on the server, sometimes with passwords"),
    ("/.gitignore", "LOW", "the Git ignore list, which names the files the developer chose to hide"),
    ("/composer.lock", "LOW", "the Composer lock file, which lists every PHP package at its exact version"),
    ("/package-lock.json", "LOW", "the npm lock file, which lists every JavaScript package at its exact version"),
    ("/yarn.lock", "LOW", "the Yarn lock file, which lists every JavaScript package at its exact version"),
    ("/wp-config.php.swp", "CRITICAL", "a Vim swap file of the WordPress configuration, which contains the database password"),
    ("/wp-config.php.swo", "CRITICAL", "a Vim swap file of the WordPress configuration, which contains the database password"),
    ("/.htaccess", "MEDIUM", "the Apache configuration, which the server should refuse to send; it names rewrite and access rules"),
    ("/wp-content/uploads/.htaccess", "MEDIUM", "the uploads folder's Apache configuration, which the server should refuse to send"),
    # Directory listings.
    ("/wp-content/uploads/", "MEDIUM", "a browsable list of every uploaded file"),
    ("/wp-content/plugins/", "MEDIUM", "a browsable list of every installed plugin"),
    ("/wp-content/themes/", "LOW", "a browsable list of every installed theme"),
    ("/wp-includes/", "LOW", "a browsable WordPress core directory"),
    ("/vendor/", "LOW", "a browsable Composer vendor directory"),
    ("/node_modules/", "LOW", "a browsable Node modules directory"),
    ("/wp-content/w3tc/dbcache/", "MEDIUM", "a browsable list of W3 Total Cache's cached database queries"),
    # Form and commerce upload directories. This is where client personal
    # information actually leaks: attachments visitors uploaded through a
    # form, order logs, file-manager backups. Only a browsable listing
    # counts; the directory existing is normal on any site with the plugin.
    ("/wp-content/uploads/wpforms/", "HIGH", "a browsable list of files visitors uploaded through WPForms"),
    ("/wp-content/uploads/formidable/", "HIGH", "a browsable list of files visitors uploaded through Formidable Forms"),
    ("/wp-content/uploads/gravity_forms/", "HIGH", "a browsable list of files visitors uploaded through Gravity Forms"),
    ("/wp-content/uploads/wc-logs/", "HIGH", "WooCommerce log files, which contain order and customer details"),
    ("/wp-content/uploads/wp-file-manager-pro/fm_backup/", "CRITICAL", "File Manager backups, which contain the whole site"),
    ("/wp-content/uploads/wp-personal-data-exports/", "HIGH", "a browsable list of the personal-data exports the site made for data subject requests, which contain exactly what each person asked to see"),
    ("/wp-content/cache/", "LOW", "a browsable page cache, which can include pages built for a signed-in user"),
    ("/wp-content/et-cache/", "LOW", "a browsable Divi cache"),
    ("/wp-content/uploads/sites/", "LOW", "a browsable list of every multisite subsite's uploads"),
    # Version and platform disclosure.
    ("/readme.html", "LOW", "the WordPress readme, which confirms the platform and the PHP floor"),
    ("/license.txt", "LOW", "the WordPress licence file, which confirms the platform and often narrows the version"),
    ("/wp-admin/install.php", "HIGH", "the WordPress installer, which can take over an unconfigured site"),
    ("/wp-admin/setup-config.php", "HIGH", "the WordPress setup wizard"),
    ("/wp-admin/maint/repair.php", "MEDIUM", "the database repair page, switched on with WP_ALLOW_REPAIR: anyone can run repair and optimise against the live database, which locks tables and can be run in a loop; remove the constant from wp-config.php"),
    # Miscellaneous. The REST users and media endpoints and xmlrpc.php are
    # deliberately absent: check_users(), check_media() and check_transport()
    # cover them with better evidence, and probing them here too reported the
    # same endpoint twice in one report.
]

# Paths where a 200 is normal and only the CONTENT decides whether it is a
# finding. Checked by name in path_is_exposed().
INSTALLER_PATHS = ("/wp-admin/install.php", "/wp-admin/setup-config.php")
REPAIR_PATH = "/wp-admin/maint/repair.php"

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
    "/.git/config": ("[core]", "repositoryformatversion"),
    "/.git/HEAD": ("ref:", "refs/"),
    "/.aws/credentials": ("aws_access_key_id", "aws_secret_access_key"),
    "/id_rsa": ("private key",),
    "/.user.ini": ("=",),
    "/wp-config.php.bak": ("db_name", "db_password", "<?php"),
    "/wp-config.php~": ("db_name", "db_password", "<?php"),
    "/wp-config.php.save": ("db_name", "db_password", "<?php"),
    "/wp-config.txt": ("db_name", "db_password", "<?php"),
    "/wp-config.old": ("db_name", "db_password", "<?php"),
    "/wp-config.php.old": ("db_name", "db_password", "<?php"),
    "/wp-config.php.orig": ("db_name", "db_password", "<?php"),
    "/wp-config.bak": ("db_name", "db_password", "<?php"),
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
    "/searchreplacedb2.php": ("by interconnect",),
    "/.idea/workspace.xml": ("<project",),
    "/docker-compose.yml": ("services:",),
    "/.ftpconfig": ('"password"', '"host"'),
    "/sftp-config.json": ('"password"', '"host"'),
    "/.remote-sync.json": ('"password"', '"hostname"', '"host"'),
    "/web.config": ("<configuration",),
    "/php.ini": ("memory_limit", "upload_max_filesize", "display_errors", "[php]"),
    "/composer.lock": ('"content-hash"', '"packages"'),
    "/package-lock.json": ('"lockfileversion"',),
    "/yarn.lock": ("# yarn lockfile", "resolved \""),
    "/.htaccess": ("rewriterule", "rewriteengine", "<ifmodule", "deny from", "require all"),
    "/wp-content/uploads/.htaccess": ("rewriterule", "rewriteengine", "<ifmodule", "deny from", "require all", "php_flag"),
    "/installer-backup.php": ("duplicator",),
    "/dup-installer/": ("index of /", "duplicator"),
    # A non-WordPress site can have a page at either of these. github.com
    # serves a user's profile at /readme.html, and it was reported as "the
    # WordPress readme".
    "/readme.html": ("wordpress",),
    "/license.txt": ("gnu general public license", "wordpress"),
}

# Paths that only mean something when the site advertises the plugin, keyed
# by slug. Requested only for slugs found in asset URLs, REST namespaces or
# the homepage, so no plugin is guessed. Paths from nuclei-templates.
PLUGIN_PROBE_PATHS: Dict[str, List[Tuple[str, str, str]]] = {
    "wp-all-import": [
        ("/wp-content/uploads/wpallimport/", "HIGH", "a browsable list of WP All Import files, which are customer and product lists"),
        ("/wp-content/uploads/wpallimport/uploads/", "HIGH", "a browsable list of WP All Import uploads, which are customer and product lists")],
    "contact-form-7": [("/wp-content/uploads/wpcf7_uploads/", "HIGH", "a browsable list of files visitors sent through Contact Form 7")],
    "ninja-forms": [("/wp-content/uploads/ninja-forms/", "HIGH", "a browsable list of files visitors sent through Ninja Forms")],
    "woocommerce": [("/wp-content/uploads/woocommerce_uploads/", "HIGH", "a browsable list of WooCommerce downloadable products and customer files")],
    "wp-security-audit-log": [
        ("/wp-content/uploads/wp-security-audit-log/", "MEDIUM", "a browsable activity log directory, which names users and what they did"),
        ("/wp-content/uploads/wp-activity-log/", "MEDIUM", "a browsable activity log directory, which names users and what they did")],
    "wp-migrate-db": [("/wp-content/uploads/wp-migrate-db/", "CRITICAL", "a browsable list of WP Migrate DB database exports")],
    "hummingbird-performance": [("/wp-content/wphb-cache/", "LOW", "a browsable Hummingbird cache")],
    "wordfence": [
        ("/wp-content/wflogs/config.php", "HIGH", "the Wordfence firewall configuration, served as text"),
        ("/wp-content/wflogs/config-synced.php", "HIGH", "the Wordfence firewall configuration, served as text"),
        ("/wp-content/wflogs/rules.php", "MEDIUM", "the Wordfence firewall rules, served as text"),
        ("/wp-content/wflogs/", "MEDIUM", "a browsable list of the Wordfence firewall's data files"),
    ],
    "enable-media-replace": [("/wp-content/uploads/EnableMediaReplace.log", "MEDIUM", "the Enable Media Replace log")],
    "flexible-shipping": [("/wp-content/uploads/wpdesk-logs/wpdesk_debug.log", "MEDIUM", "the Flexible Shipping debug log")],
    "wp-statistics": [("/wp-content/uploads/wp-statistics/debug.log", "MEDIUM", "the WP Statistics debug log")],
    "gravityforms": [("/wp-content/plugins/gravityforms/debug.log", "MEDIUM", "the Gravity Forms debug log")],
    "nextgen-gallery": [("/wp-content/plugins/nextgen-gallery/admin/php_errors.log", "MEDIUM", "the NextGEN Gallery PHP error log")],
    "newsletter": [("/wp-content/plugins/newsletter/error_log", "MEDIUM", "a PHP error log inside the Newsletter plugin")],
    "wps-hide-login": [("/wp-content/plugins/wps-hide-login/classes/error_log", "MEDIUM", "a PHP error log inside WPS Hide Login, which can name the hidden login address")],
    "pretty-link": [("/wp-content/plugins/pretty-link/error_log", "MEDIUM", "a PHP error log inside the Pretty Links plugin")],
    "wordpress-importer": [("/wp-content/plugins/wordpress-importer/error_log", "MEDIUM", "a PHP error log inside the WordPress Importer plugin")],
    "easy-google-fonts": [("/wp-content/plugins/easy-google-fonts/error_log", "MEDIUM", "a PHP error log inside the Easy Google Fonts plugin")],
}

# Premium editions write to the same folders as the free ones.
for _free, _pro in (("wp-all-import", "wp-all-import-pro"), ("wp-migrate-db", "wp-migrate-db-pro"),
                    ("ninja-forms", "ninja-forms-pro")):
    PLUGIN_PROBE_PATHS[_pro] = PLUGIN_PROBE_PATHS[_free]

# Plugin logs must hold a timestamped or PHP-error line: a block page saying
# "Access Denied [403]" passed the looser debug.log markers.
PLUGIN_LOG_PATHS = set()
PLUGIN_LOG_RE = re.compile(
    r"(?im)^\[?\d{1,4}[-/.]\w{2,3}[-/.]\d{2,4}|php (?:warning|notice|fatal|deprecated|parse)")
for _slug, _probes in PLUGIN_PROBE_PATHS.items():
    for _path, _, _ in _probes:
        if _path.endswith("log"):
            PLUGIN_LOG_PATHS.add(_path)
        elif _path.endswith(".php"):
            # Wordfence data files open with __halt_compiler, its rules.php
            # with a WFWAF_VERSION guard. Run by PHP either prints "Access
            # denied"; only the source served as text carries the marker.
            CONTENT_MARKERS[_path] = ("__halt_compiler", "wfwaf_version")

# Requested directly, this core file calls a function nothing has loaded and
# PHP stops. With display_errors on, the error names the file's full path.
# Shipped without a direct-load guard from 4.9 to trunk (checked 2026-10-29).
FPD_PATH = "/wp-includes/rss.php"
FPD_RE = re.compile(
    r"(?is)fatal error.*?((?:[a-z]:\\|/)[^\s<>\"']+[/\\]wp-includes[/\\]rss\.php)")

# Paths that only mean something on WordPress. Skipped when the platform is
# known not to be WordPress, so the appendix does not list forty WordPress
# files as "not readable" on a static site.
WORDPRESS_ONLY_PATHS = {"/readme.html", "/license.txt", "/installer.php",
                        "/installer-backup.php", "/dup-installer/",
                        "/searchreplacedb2.php"}

# PHP tools whose real output is an HTML page, so the "an HTML document is
# not this file" rule in content_matches() does not apply; markers decide.
HTML_OUTPUT_PATHS = ("/searchreplacedb2.php", "/emergency.php")

# A PHP source file served as text: PHP is not running here, so
# wp-config.php would be served the same way.
PHP_SOURCE_RE = re.compile(r"<\?php|\$wp_version\s*=")

# Copies of wp-config.php whose names end in .php. The server runs these
# rather than sending them, and a configuration file defines constants and
# prints nothing, so a real copy answers HTTP 200 with an empty body. No
# content marker can match that; the empty 200 is the evidence, and only
# after calibrate_exec() has shown an unknown .php here answers differently.
EXEC_CONFIG_PATHS: List[Tuple[str, str, str]] = [
    (path, "MEDIUM", "a stale copy of the WordPress configuration file that "
                     "the server runs; its contents, including the database "
                     "password, leak if PHP ever stops handling the file")
    for path in ("/wp-config_old.php", "/wp-config-old.php",
                 "/wp-config.old.php", "/wp-config-backup.php")]

# Core files that print nothing when PHP runs them: the positive control for
# the empty-200 rule, tried in order. wp-load.php comes first because it sits
# in the web root beside the copies; Hostinger 403s every .php under
# wp-content and wp-includes, and so do some hardening plugins.
EXEC_CONTROL_PATHS = ("/wp-load.php", "/wp-content/index.php",
                      "/wp-includes/version.php")

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

# End of active support per PHP branch, from https://www.php.net/supported-versions.php
# read 2026-11-04. Security fixes continue to the branch's date_end, which
# comes from wpvulnerability.net. Some scanners call this date end of life.
PHP_ACTIVE_SUPPORT_END = {"8.2": "2024-12-31", "8.3": "2025-12-31",
                          "8.4": "2026-12-31", "8.5": "2027-12-31"}

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
#
# A slug is set only when the namespace string appears in that one plugin's
# source and no other's. A namespace from a shared vendor package (Jetpack's
# jetpack_vendor, Elementor's wp-one-package, WPChill's admin library) names
# the family with no slug: a slug sends the plugin to the vulnerability
# lookup, and an unreadable readme there matches every advisory that covers
# all releases. Matching is exact, never by prefix: elementor/v1/blog and
# wc/store/marketplace are the vendors' own site code, in no public plugin.
# Entries added 2026-09-23 were checked against the wordpress.org source.
NAMESPACE_PLUGINS: Dict[str, Tuple[str, Optional[str]]] = {
    "acf/v3": ("Advanced Custom Fields", "advanced-custom-fields"),
    "age-gate/v3": ("Age Gate", "age-gate"),
    "aioseo/v1": ("All in One SEO", "all-in-one-seo-pack"),
    "akismet/v1": ("Akismet", "akismet"),
    "apple-news/v1": ("Publish to Apple News", "publish-to-apple-news"),
    "bctt/v1": ("Better Click To Tweet", "better-click-to-tweet"),
    "block-visibility/v1": ("Block Visibility", "block-visibility"),
    "buddypress/v1": ("BuddyPress", "buddypress"),
    "carbon-fields/v1": ("Carbon Fields", "carbon-fields"),
    "categoryPosts": ("Category Posts", "category-posts"),
    "caxton/v1": ("Caxton", "caxton"),
    "ccb-gutenberg/v1": ("Cost Calculator Builder", "cost-calculator-builder"),
    "cky/v1": ("CookieYes", "cookie-law-info"),
    "coauthors/v1": ("Co-Authors Plus", "co-authors-plus"),
    "code-snippets/v1": ("Code Snippets", "code-snippets"),
    "complianz/v1": ("Complianz", "complianz-gdpr"),
    "contact-form-7/v1": ("Contact Form 7", "contact-form-7"),
    "cookie-notice/v1": ("Cookie Notice", "cookie-notice"),
    "cookieyes/v1": ("CookieYes", "cookie-law-info"),
    "download-monitor/v1": ("Download Monitor", "download-monitor"),
    "duplicate-post/v1": ("Yoast Duplicate Post", "duplicate-post"),
    "duplicator/v1": ("Duplicator", "duplicator"),
    "ea11y/v1": ("Ally by Elementor", "pojo-accessibility"),
    "elasticpress/v1": ("ElasticPress", "elasticpress"),
    "elementor-ai/v1": ("Elementor", "elementor"),
    "elementor-one/v1": ("Elementor, Ally or Image Optimizer", None),
    "elementor/v1": ("Elementor", "elementor"),
    "elementor/v1/documents": ("Elementor", "elementor"),
    "elementor/v1/feedback": ("Elementor", "elementor"),
    "fluent-smtp": ("FluentSMTP", "fluent-smtp"),
    "forminator/v1": ("Forminator", "forminator"),
    "get": ("Squirrly SEO", None),
    "gf/v2": ("Gravity Forms", "gravityforms"),
    "google-site-kit/v1": ("Site Kit by Google", "google-site-kit"),
    "health-check/v1": ("Health Check", "health-check"),
    "hostinger-ai-assistant/v1": ("Hostinger AI Assistant", None),
    "hostinger-tools-plugin/v1": ("Hostinger Tools", None),
    "hub-connector/v1":
        ("a WPMU DEV plugin (Forminator, Smush, Hummingbird or Broken Link Checker)", None),
    "image-optimizer/v1":
        ("Image Optimizer by Elementor", "image-optimization"),
    "ithemes-security/v1": ("Solid Security", "better-wp-security"),
    "jetpack-boost/v1": ("Jetpack Boost", "jetpack-boost"),
    "jetpack/v4": ("Jetpack", "jetpack"),
    "jetpack/v4/blaze": ("Jetpack", None),
    "jetpack/v4/blaze-app": ("Jetpack", None),
    "jetpack/v4/explat": ("Jetpack or Jetpack Boost", None),
    "jetpack/v4/import": ("Jetpack", None),
    "jetpack/v4/stats-app": ("Jetpack or Jetpack Boost", None),
    "kadence-blocks/v1": ("Kadence Blocks", "kadence-blocks"),
    "kirki/v1": ("Kirki", "kirki"),
    "litespeed/v1": ("LiteSpeed Cache", "litespeed-cache"),
    "litespeed/v3": ("LiteSpeed Cache", "litespeed-cache"),
    "mainwp/v1": ("MainWP Dashboard", "mainwp"),
    "mainwp/v2": ("MainWP Dashboard", "mainwp"),
    "mc4wp/v1": ("MC4WP: Mailchimp for WordPress", "mailchimp-for-wp"),
    "mcp": ("MCP adapter", None),
    "metricool/v1": ("Metricool", "metricool"),
    "monsterinsights/v1":
        ("MonsterInsights", "google-analytics-for-wordpress"),
    "my-jetpack/v1": ("Jetpack or Jetpack Boost", None),
    "payments/woopay": ("WooPayments", "woocommerce-payments"),
    "pinterest/v1": ("Pinterest for WooCommerce", "pinterest-for-woocommerce"),
    "popup-maker/v2": ("Popup Maker", "popup-maker"),
    "qsm": ("Quiz and Survey Master", "quiz-master-next"),
    "quiz-survey-master/v1": ("Quiz and Survey Master", "quiz-master-next"),
    "quiz-survey-master/v2": ("Quiz and Survey Master", "quiz-master-next"),
    "rankmath/v1": ("Rank Math SEO", "seo-by-rank-math"),
    "rankmath/v1/ai-visibility": ("Rank Math SEO", "seo-by-rank-math"),
    "rankmath/v1/an": ("Rank Math SEO", "seo-by-rank-math"),
    "rankmath/v1/ca": ("Rank Math SEO", "seo-by-rank-math"),
    "rankmath/v1/setupWizard": ("Rank Math SEO", "seo-by-rank-math"),
    "rankmath/v1/status": ("Rank Math SEO", "seo-by-rank-math"),
    "redirection/v1": ("Redirection", "redirection"),
    "regenerate-thumbnails/v1":
        ("Regenerate Thumbnails", "regenerate-thumbnails"),
    "save": ("Squirrly SEO", None),
    "seopress/v1": ("SEOPress", "wp-seopress"),
    "sg-security/v1": ("SiteGround Security", "sg-security"),
    "simple-page-ordering/v1":
        ("Simple Page Ordering", "simple-page-ordering"),
    "siteground-settings/v1": ("SiteGround Optimizer", "sg-cachepress"),
    "squirrly": ("Squirrly SEO", "squirrly-seo"),
    "squirrly/v1": ("Squirrly SEO", "squirrly-seo"),
    "ssp/v1": ("Seriously Simple Podcasting", "seriously-simple-podcasting"),
    "test": ("Squirrly SEO", None),
    "tribe/events/v1": ("The Events Calendar", "the-events-calendar"),
    "two-factor/1.0": ("Two-Factor", "two-factor"),
    "videopress/v1": ("Jetpack", None),
    "wc-admin": ("WooCommerce", "woocommerce"),
    "wc-admin-email": ("WooCommerce", "woocommerce"),
    "wc-analytics": ("WooCommerce", "woocommerce"),
    "wc-push-notifications": ("WooCommerce", "woocommerce"),
    "wc-telemetry": ("WooCommerce", "woocommerce"),
    "wc/pos/v1/catalog": ("WooCommerce", "woocommerce"),
    "wc/private": ("WooCommerce", "woocommerce"),
    "wc/store": ("WooCommerce", "woocommerce"),
    "wc/store/v1": ("WooCommerce", "woocommerce"),
    "wc/v1": ("WooCommerce", "woocommerce"),
    "wc/v2": ("WooCommerce", "woocommerce"),
    "wc/v3": ("WooCommerce", "woocommerce"),
    "wccom-site/v3": ("WooCommerce", "woocommerce"),
    "weglot/v1": ("Weglot", "weglot"),
    "weglot/v2": ("Weglot", "weglot"),
    "woocommerce-analytics/v1": ("Jetpack", None),
    "wordfence-login-security/v1": ("Wordfence Login Security", None),
    "wordfence/v1": ("Wordfence", "wordfence"),
    "wordlift/v1": ("WordLift", "wordlift"),
    "wp-mail-smtp/v1": ("WP Mail SMTP", "wp-mail-smtp"),
    "wp-parsely/v2": ("Parse.ly", "wp-parsely"),
    "wp-rocket/v1": ("WP Rocket", "wp-rocket"),
    "wp-rollback/v1": ("WP Rollback", "wp-rollback"),
    "wpchill/v1": ("Download Monitor, Modula or Strong Testimonials", None),
    "wpcom/v2": ("Jetpack", None),
    "wpcom/v3": ("Jetpack", None),
    "wpforms/v1": ("WPForms", "wpforms-lite"),
    "wpmudev_blc/v1": ("Broken Link Checker", "broken-link-checker"),
    "wpmudev_pcs/v1":
        ("a WPMU DEV plugin (Forminator, Smush, Hummingbird or Broken Link Checker)", None),
    "wptelegram-bot/v1": ("WP Telegram", "wptelegram"),
    "wptelegram/v1": ("WP Telegram", "wptelegram"),
    "yoast/v1": ("Yoast SEO", "wordpress-seo"),
    "zapier/v1": ("Zapier for WordPress", "zapier"),
    "zoninator/v1": ("Zoninator", "zoninator"),
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
# these, every later module is reading the edge and not the site. These count
# only on a non-200: Cloudflare's JS Detections (forced on by Bot Fight Mode)
# puts /cdn-cgi/challenge-platform/ into every ordinary page, and a small
# homepage carrying it once read as a block page and lost its header findings.
CHALLENGE_MARKERS = ("just a moment", "cf-chl", "challenge-platform",
                     "attention required", "sucuri website firewall",
                     "generated by wordfence", "access denied",
                     "your access to this site has been limited",
                     "enable javascript and cookies to continue")
# Signals only a challenge carries, whatever the status: Cloudflare sets
# cf-mitigated: challenge on every Challenge Page (its only value), and
# Sucuri's JavaScript challenge, which can arrive as a 200, carries this name.
CHALLENGE_ANY_STATUS = ("sucuri_cloudproxy_js",)

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

# PHP CVE descriptions that confine the bug to Windows builds.
WINDOWS_ONLY = re.compile(r"\bon Windows\b|Windows environment|Windows codepage",
                          flags=re.I)

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
    # Two CSP headers are both enforced; a comma is how CSP separates policies.
    for name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
        try:
            values = msg.get_all(name) or []
        except AttributeError:
            values = []
        if len(values) > 1:
            out[name.lower()] = ", ".join(values)
    return out


def fetch(url: str, method: str = "GET", timeout: int = REQUEST_TIMEOUT,
          max_bytes: int = MAX_BODY_BYTES,
          headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
    """One request with a browser UA, redirects followed.

    Returns (status, lowercased headers, body text). Status 0 means the
    request never completed, and headers carries "_error" with the reason.
    A body cut off at max_bytes sets "_truncated", so a caller parsing JSON
    can tell a truncated document from a non-JSON one.
    """
    time.sleep(_delay())
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                _served()
                _count(url, r.status)
                body = r.read(max_bytes) if method == "GET" else b""
                hdrs = _headers(r.headers)
                if len(body) >= max_bytes:
                    hdrs["_truncated"] = str(max_bytes)
                return r.status, hdrs, body.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            _count(url, e.code)
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
RATE_LIMIT_GIVE_UP = 6        # consecutive 429s before retries stop
RATE_LIMIT_RECOVER = 20      # clean requests in a row before the pace halves
# Statuses that say nothing about the resource: refused, overloaded, or never
# answered. A module that reads one of these reports "not examined", never
# "closed, the safer state".
UNMEASURED_STATUSES = (0, 429, 503)
_slowdown = 1.0
# Requests to the audited host this session, and how many were refused.
# The report states these as a measured fact about the run (7.9).
_site_host = ""
_traffic = {"requests": 0, "refused": 0}
_consecutive_429 = 0
_consecutive_ok = 0


def _count(url: str, status: int) -> None:
    """Tally a request if it went to the audited host (www or bare)."""
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if _site_host and re.sub(r"^www\.", "", host) == _site_host:
        _traffic["requests"] += 1
        if status in (429, 503):
            _traffic["refused"] += 1


def _delay() -> float:
    """The gap before the next request: the chosen pace times the slowdown,
    capped at the longer of RATE_LIMIT_PAUSE and --delay itself. Uncapped,
    --delay 2 against a Cloudflare limit reached 32 s a request and a path
    sweep ran for over an hour without finishing."""
    return min(REQUEST_DELAY * _slowdown, max(RATE_LIMIT_PAUSE, REQUEST_DELAY))


def _back_off(headers) -> bool:
    """Wait as the server asked, and slow the rest of the run.

    Returns False once the limiter has refused RATE_LIMIT_GIVE_UP requests in
    a row: pausing eight seconds before every one of a hundred probes turned
    a five-minute module into a forty-minute one and did not get a single
    request through. Past that point refusals are recorded as rate limited
    without waiting, and the report says which paths were not checked.
    """
    global _slowdown, _consecutive_429, _consecutive_ok
    _consecutive_429 += 1
    _consecutive_ok = 0
    if _consecutive_429 > RATE_LIMIT_GIVE_UP:
        return False
    try:
        pause = float((headers or {}).get("Retry-After", RATE_LIMIT_PAUSE))
    except (TypeError, ValueError):
        pause = RATE_LIMIT_PAUSE
    pause = min(max(pause, 1.0), RATE_LIMIT_MAX_PAUSE)
    _slowdown = min(_slowdown * 2, 16.0)
    print_warning(f"HTTP 429: pausing {pause:.0f}s and slowing the run "
                  f"({_delay():.2f}s between requests)")
    if _consecutive_429 == RATE_LIMIT_GIVE_UP:
        print_warning(f"{RATE_LIMIT_GIVE_UP} refusals in a row; further 429s "
                      "will be recorded as rate limited without waiting")
    time.sleep(pause)
    return True


def _served() -> None:
    """A request got through: the limiter has relented.

    The pace steps back down one halving per RATE_LIMIT_RECOVER clean
    requests. Without this, one burst of 429s during calibration held a
    Hostinger run at 8 s per request for its remaining 35 minutes.
    """
    global _consecutive_429, _consecutive_ok, _slowdown
    _consecutive_429 = 0
    _consecutive_ok += 1
    if _slowdown > 1.0 and _consecutive_ok >= RATE_LIMIT_RECOVER:
        _slowdown = max(_slowdown / 2, 1.0)
        _consecutive_ok = 0


def fetch_no_redirect(url: str, timeout: int = REQUEST_TIMEOUT,
                      headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str]]:
    """One request with redirects NOT followed. Returns (status, headers).

    urllib follows redirects by default, and that hides two findings. A
    plain-HTTP check through fetch() reports the final HTTPS 200 with no
    Location header, which reads as "this site does not redirect" when it
    does; and ?author=N looks blocked because you never see where it pointed.
    """
    time.sleep(_delay())
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in (1, 2):
        try:
            with opener.open(req, timeout=timeout) as r:
                _served()
                _count(url, r.status)
                return r.status, _headers(r.headers)
        except urllib.error.HTTPError as e:
            _count(url, e.code)
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


def edge_identity(hdrs: Dict[str, str], body: str = "",
                  status: Optional[int] = None) -> Dict:
    """Name what is in front of the site, and whether this response is a
    block or challenge page rather than the page asked for. Pass the status:
    without it every body marker counts, as it did before the status was known."""
    seen: List[str] = []
    for label, header, needle in EDGE_SIGNS:
        value = hdrs.get(header, "")
        if header in hdrs and (needle is None or needle in value.lower()):
            if label not in seen:
                seen.append(label)
    low = body.lower()[:20000]
    if "sucuri_cloudproxy_js" in low and "Sucuri" not in seen:
        seen.append("Sucuri")
    challenged = (hdrs.get("cf-mitigated", "").lower() == "challenge"
                  or any(marker in low for marker in CHALLENGE_ANY_STATUS)
                  or (status != 200 and any(marker in low for marker in CHALLENGE_MARKERS)))
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
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers = numbers[:-1]
    # Build metadata (+...) is not a prerelease and does not order.
    suffix = match.group(2).split("+", 1)[0].strip().lower()
    return (numbers, _prerelease_rank(suffix))


def _prerelease_rank(suffix: str) -> int:
    """0 for a release, below zero for a prerelease: alpha < beta < rc, each
    by its number. An unrecognised suffix sorts below every known one."""
    if not suffix:
        return 0
    match = re.fullmatch(r"[-_.]?(alpha|a|beta|b|rc)[-_.]?(\d*)", suffix)
    if not match:
        return -40000
    stage = {"alpha": 3, "a": 3, "beta": 2, "b": 2, "rc": 1}[match.group(1)]
    return -stage * 10000 + int(match.group(2) or 0)


def version_ordered(version: str) -> bool:
    """Whether version_key() could actually place this string."""
    return version_key(version)[0] != (-1,)


def running_version(versions: List[str]) -> str:
    """The best single estimate of the version a component is running.

    A `ver=` in an asset URL belongs to the FILE, not to the plugin: bundled
    libraries and hand-written enqueues carry their own numbers, and a
    hardcoded ver=1.0.0 on one script is common. Taking the lowest of them
    read a current plugin as its oldest bundled file, matched an advisory
    covering everything below a long-fixed release, and published a CVSS 9.8
    that was not there. The highest is the only one that cannot be a stale
    constant left inside an older file, so it is what the report measures.
    Lower ones stay in detected_versions.
    """
    ordered = [v for v in versions if version_ordered(v)]
    return max(ordered, key=version_key) if ordered else ""


def without_core(versions: List[str], core: set) -> List[str]:
    """A plugin's ver= values minus the WordPress core version, which
    WordPress stamps on any file a plugin enqueues without its own."""
    return [v for v in versions if v not in core]


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


def _cvss(entry: Dict) -> Dict:
    """The scored CVSS block of a wpvulnerability record.

    Some records carry only `cvss3` (every PHP record, and a few core and
    plugin ones); reading `cvss` alone showed those as unscored MEDIUM, which
    put php2shell's 9.8 below a 7.2 plugin bug.
    """
    impact = entry.get("impact") or {}
    for key in ("cvss", "cvss3"):
        block = impact.get(key) or {}
        try:
            if float(block.get("score")) > 0:
                return block
        except (TypeError, ValueError):
            pass
    return impact.get("cvss") or {}


def _vuln_rows(record: Dict, version: str) -> Tuple[List[Dict], int]:
    """Vulnerabilities from a wpvulnerability record that cover `version`.

    Returns (matching rows, count of records that could not be decided).
    """
    matched, undecidable = [], 0
    entries = record.get("vulnerability") or []
    # The same bug often arrives twice, once per source, and one copy can
    # drop the lower bound: Oxygen's 6.0-6.1.1 access-control bug is listed
    # as "< 6.1.2" by Patchstack and ">= 6.0 - < 6.1.2" by Wordfence, and
    # the unbounded copy flagged every 4.x install. When a bounded record
    # shares the upper bound and excludes this version, the unbounded one is
    # undecidable rather than a finding. It is not dropped: a second bug
    # fixed in the same release may really cover every version.
    bounded = [(e.get("operator") or {}) for e in entries
               if (e.get("operator") or {}).get("min_version")]
    for entry in entries:
        operator = entry.get("operator") or {}
        verdict = vuln_applies(version, operator)
        if verdict and not operator.get("min_version") and any(
                b.get("max_version") == operator.get("max_version")
                and b.get("max_operator") == operator.get("max_operator")
                and vuln_applies(version, b) is False for b in bounded):
            verdict = None
        if verdict is None:
            undecidable += 1
            continue
        if not verdict:
            continue
        cvss = _cvss(entry)
        try:
            score = float(cvss.get("score"))
        except (TypeError, ValueError):
            score = 0.0
        sources = entry.get("source") or []
        cve = next((s.get("id") for s in sources
                    if str(s.get("id", "")).startswith("CVE-")), "")
        operator = entry.get("operator") or {}
        matched.append({
            "name": entry.get("name") or "",
            "cve": cve,
            "reference": next((s.get("link") for s in sources if s.get("link")), ""),
            "score": score,
            "vector": cvss.get("vector") or "",
            "fixed_in": operator.get("max_version") or "",
            "max_operator": (operator.get("max_operator") or "").lower(),
            "min_version": operator.get("min_version") or "",
            "unfixed": str(operator.get("unfixed")) == "1",
        })
    matched.sort(key=lambda row: row["score"], reverse=True)
    return matched, undecidable


def fix_text(row: Dict) -> str:
    """What a reader should update to, from a vulnerability row.

    `max_version` is the top of the AFFECTED range, not a fix, and the two
    only coincide when the operator is `lt`. An unfixed advisory sits at
    `<= <the current release>` until the author ships something, so printing
    max_version there tells the reader to update to the exact version they
    are already running and that is still vulnerable.
    """
    if row.get("unfixed"):
        return "no fix published"
    if not row.get("fixed_in"):
        return ""
    if row.get("max_operator") == "lt":
        return row["fixed_in"]
    return f"a release later than {row['fixed_in']}"


def _every_release_rows(record: Dict, current: str) -> List[Dict]:
    """Vulnerabilities that cover every published release of a component.

    A record with no lower bound whose upper bound still reaches the CURRENT
    release covers whatever version is installed, so it can be matched
    without knowing that version. This is not a corner case: an advisory with
    no fix published sits at `<= <current release>` by definition, which is
    exactly the situation where "we could not read the version" would
    otherwise hide a live, unpatchable issue behind an INFO coverage note.
    """
    if not version_ordered(current):
        return []
    rows, _ = _vuln_rows(record, current)
    return [row for row in rows if not row["min_version"]]


def _core_rows(record: Dict) -> List[Dict]:
    """Vulnerabilities from a wpvulnerability CORE record.

    Kept apart from _vuln_rows() because the two endpoints are shaped
    differently: /core/<version>/ is already scoped to the version asked for
    and its records carry no operator block, so there is no range to match.
    """
    rows = []
    for entry in record.get("vulnerability") or []:
        cvss = _cvss(entry)
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
            "max_operator": ((entry.get("operator") or {}).get("max_operator")
                             or "").lower(),
            "min_version": (entry.get("operator") or {}).get("min_version") or "",
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
    # An HTML document is not a config backup, a dump, a key or a log,
    # whatever words it contains. A documentation site served a 229 KB page
    # at /wp-config.php~ that mentioned DB_NAME, and it was a CRITICAL. The
    # Content-Type header is no use here: nginx serves unknown extensions as
    # text/html, so a real .env can carry that header; the body decides.
    if (not path.endswith((".html", "/")) and path not in HTML_OUTPUT_PATHS
            and re.match(r"\s*(<!doctype\s+html|<html)", low)):
        return False
    # Both words, as WPScan keys on: "password" alone is on every login widget.
    if path == "/emergency.php":
        return "password" in low and "emergency" in low
    if path == "/installer-log.txt":
        return "duplicator" in low and "install-log" in low
    if path.endswith(".zip"):
        return body.startswith("PK")
    if path.endswith(".gz") or path.endswith(".tgz"):
        return body.startswith("\x1f")
    if path.endswith(".sql"):
        return any(m in low for m in SQL_MARKERS)
    # One "=" or ":" anywhere passed a challenge page ("token=abc") and an
    # error line ("Access denied: retry") as credentials. The file's shape
    # is a line: NAME=value, or user:hash.
    if path == "/.env":
        return bool(re.search(r"(?m)^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=", body))
    if path == "/.htpasswd":
        return bool(re.search(r"(?m)^[^:\s<>]+:[^\s:<>]{13,}[ \t]*$", body))
    if path == FPD_PATH:
        return bool(FPD_RE.search(body))
    if path == "/wp-cli.yml":
        return bool(re.search(
            r"(?m)^(?:@[\w-]+|path|url|user|ssh|http|color|debug|quiet|require"
            r"|disabled_commands|apache_modules|core|config|skip-plugins"
            r"|skip-themes)\s*:", body))
    if path in PLUGIN_LOG_PATHS:
        return bool(PLUGIN_LOG_RE.search(body))
    if path in ("/wp-config.php.swp", "/wp-config.php.swo"):
        return body.startswith("b0VIM")
    if path == "/Dockerfile":
        return bool(re.search(r"(?mi)^\s*FROM\s+\S", body))
    if path == "/.vscode/settings.json" or path.endswith(".css.map"):
        return body.lstrip().startswith("{") and (
            '"mappings"' in low if path.endswith(".map") else '":' in body)
    if path == "/.bash_history":
        return bool(re.search(r"(?m)^(?:cd|ls|sudo|wp|mysql|git|cat|nano|vi|php|rm|cp|mv)\b", body))
    if path == "/.gitignore":
        lines = [l.strip() for l in body.splitlines() if l.strip()]
        return (len(lines) >= 2 and any(c in body for c in "/*.")
                and all(l.startswith("#") or re.fullmatch(r"[^\s<>]+", l) for l in lines))
    if path == "/.wp-env.json":
        return body.lstrip().startswith("{") and any(
            k in low for k in ('"core"', '"plugins"', '"themes"', '"port"',
                               '"mappings"', '"config"'))
    markers = CONTENT_MARKERS.get(path)
    if markers is None:
        # No rule, but a bare HTML document at a non-HTML path is still not
        # that file. Paths with no rule are the ones without a fixed shape.
        return None
    return any(m in low for m in markers)


def _same_resource(path: str, location: str) -> bool:
    """Is a redirect Location the same path, give or take scheme, host and
    a trailing slash? Those redirects still lead to the file asked for."""
    if not location:
        return False
    target = urllib.parse.urlparse(location).path or "/"
    return target.rstrip("/") == path.rstrip("/")


def path_is_exposed(path: str, status: int, body: str,
                    missing: Optional[Dict],
                    no_redirect_status: Optional[int] = None,
                    location: str = "") -> bool:
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
    # The same holds on a site that 404s unknown paths: a probe that
    # redirects to a DIFFERENT path did not return the file, it returned
    # wherever WordPress's canonical redirect sent it. A documentation site
    # sent /wp-config.php~ to an article about wp-config.php and the article
    # was reported as a CRITICAL config backup. Only a redirect to the same
    # path (scheme, host or trailing slash) still counts as the file.
    if (no_redirect_status is not None and 300 <= no_redirect_status < 400
            and location and not _same_resource(path, location)):
        return False
    if status != 200:
        return False

    low = body.lower()

    # The installer and setup wizard answer on every WordPress site. They are
    # only a finding if they still offer to install; "Already Installed" is
    # the safe response and reporting it sends a client a false positive. So
    # is a WAF page served with a 200, which is why a positive marker of the
    # install form is required rather than the mere absence of the refusal.
    # Answers on every install; only the enabled page links to ?repair=.
    # Wording from wp-admin/maint/repair.php (6.8.3).
    if path == REPAIR_PATH:
        return "repair.php?repair=" in low and "database repair" in low

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
        # Except where the evidence is what PHP prints: there, nothing
        # printed is the safe answer.
        return path != FPD_PATH

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
    if path == FPD_PATH and status == 200 and not body.strip():
        return "answered, nothing printed"
    if no_redirect_status and 300 <= no_redirect_status < 400:
        return "redirected (not a file)"
    if (status == 200 and body.strip() and not path.endswith("/")
            and content_matches(path, body) is False):
        return "answered, unexpected content"
    return "not readable"


def exec_copy_is_hit(status: int, no_redirect_status: Optional[int],
                     body: str) -> bool:
    """Did a .php path answer the way PHP running a config file does?

    A 200 with no redirect and nothing but whitespace in the body. A soft
    404 and a WAF page both carry a body, so neither qualifies. This is only
    evidence once calibrate_exec() has shown the site does not answer every
    unknown .php the same way.
    """
    return status == 200 and no_redirect_status == 200 and not body.strip()


def config_source_leaked(status: int, body: str) -> bool:
    """Is this the text of a wp-config.php, not its output? Two of the
    defines it cannot run without, so a page mentioning one does not pass."""
    low = body.lower()
    return (status == 200 and "<?php" in low
            and "db_password" in low and "db_name" in low)


def php_source_served(status: int, body: str) -> bool:
    """Did a core .php file come back as its source text? Then PHP is off
    for that directory and wp-config.php is served the same way."""
    return status == 200 and bool(PHP_SOURCE_RE.search(body))


def calibrate_exec(site: str) -> Dict:
    """Can an empty 200 on a .php path be read as a real file that ran?

    Two nonsense paths are requested: a bare one, and one shaped like the
    copies probed, so a server rule keyed on "wp-config" is measured too.
    Either answering an empty 200 means the signal belongs to the site, not
    the file, and the rule stands down. Then the positive control: a core
    file that prints nothing when run must still be classified a hit, or the
    rule would suppress real copies and the report would read as clean.
    """
    out = {"usable": False, "control_path": "", "control_ran": False,
           "note": ""}
    for path in (f"/zz-does-not-exist-{uuid.uuid4().hex[:16]}.php",
                 f"/wp-config-zz-{uuid.uuid4().hex[:16]}.php"):
        no_redirect_status, _ = fetch_no_redirect(site + path)
        status, _, body = fetch(site + path)
        if (status in UNMEASURED_STATUSES
                or no_redirect_status in UNMEASURED_STATUSES):
            out["note"] = (
                f"a .php path that cannot exist was answered HTTP {status} "
                "(rate limited or unreachable), so the check for "
                "configuration copies the server runs was not run")
            return out
        if exec_copy_is_hit(status, no_redirect_status, body):
            out["note"] = (
                "this site answers a .php path that cannot exist with an "
                "empty HTTP 200, so an empty answer proves nothing and the "
                "check for configuration copies the server runs was not run")
            return out
    for path in EXEC_CONTROL_PATHS:
        no_redirect_status, _ = fetch_no_redirect(site + path)
        status, _, body = fetch(site + path)
        if status != 200:
            continue
        if php_source_served(status, body):
            out["php_disabled"] = {"path": path, "url": site + path,
                                   "status": status, "bytes": len(body)}
        out.update(control_path=path, control_ran=True)
        if not exec_copy_is_hit(status, no_redirect_status, body):
            out["note"] = (
                f"{path}, a core file that prints nothing when run, did not "
                "answer with an empty HTTP 200, so the check for "
                "configuration copies the server runs could not see a real "
                "one and was not run")
            return out
        out["usable"] = True
        return out
    out["usable"] = True
    out["note"] = ("no core control file answered (" +
                   ", ".join(EXEC_CONTROL_PATHS) + "), so the check for "
                   "configuration copies the server runs is unproven")
    return out


def _readme_probe(site: str, slug: str) -> Tuple[str, int, str]:
    """The version from a plugin's own readme.txt, the HTTP status, and the
    Stable tag when the changelog overrode it ("" otherwise).

    Independent of the page cache and of asset URLs, so it cross-checks the
    version read from ?ver= and supplies one where no asset carried it. It is
    a second witness, not the authority: authors forget to bump it, and
    "trunk" is a legal value. Both are rejected here.

    The status is returned because an empty tag has two very different
    causes. A WAF that answers every /wp-content/plugins/*/readme.txt with
    403 means no version could be read for ANY plugin, which is a fact about
    the edge and not about the plugins. Reporting that as "no version could
    be read" invites the reader to go looking on the Plugins screen for
    something that was never observable from outside.
    """
    status, _, body = fetch(f"{site}/wp-content/plugins/{slug}/readme.txt",
                            max_bytes=65_536)
    if status != 200 or "<html" in body[:2000].lower():
        return "", status, ""
    match = re.search(r"(?im)^\s*stable tag:\s*([0-9][0-9a-zA-Z.\-]*)\s*$", body)
    tag = match.group(1).strip() if match else ""
    # The tag can lag the code it ships with: Forminator's own 1.57.3 release
    # says "Stable tag: 1.57.2", which raised a false CRITICAL for a CVE fixed
    # in 1.57.3. The newest changelog heading in the same file is the better
    # witness when it is higher, but a changelog can also list a release
    # that is not out yet, which would clear a vulnerable plugin. So the old
    # tag is returned as well, and check_vulns reports what it would match.
    log = re.split(r"(?im)^\s*==\s*changelog\s*==\s*$", body, maxsplit=1)
    if len(log) == 2:
        heads = re.findall(r"(?m)^\s*=+\s*v?(\d+(?:\.\d+)+)\b", log[1])
        newest = max(heads, key=version_key, default="")
        if newest and version_key(newest) > version_key(tag):
            return newest, status, tag
    return tag, status, ""


def _readme_stable_tag(site: str, slug: str) -> str:
    """The Stable tag alone. See _readme_probe for the status."""
    return _readme_probe(site, slug)[0]


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
            "completed_at": datetime.now().isoformat(timespec="seconds"),
            "tool": SCRIPT_VERSION, "tool_sha": SCRIPT_SHA}
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
    # A refusal is not the site's answer for a missing path. Learning one as
    # the signature (one live site: three empty 429s) passes the robots.txt
    # control and would then file every refused probe as absent.
    if signature.get("status") in UNMEASURED_STATUSES:
        return ("error", 0,
                f"the missing-path probes were answered HTTP "
                f"{signature['status']} (rate limited or unreachable), so "
                "the site's not-found shape is unknown and the paths module "
                "cannot run. Re-run with a larger --delay")
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


# Security, firewall, login-protection and two-factor plugins by
# wordpress.org slug (premium editions where they differ).
SECURITY_PLUGINS = {
    "wordfence": "Wordfence", "better-wp-security": "Solid Security",
    "ithemes-security-pro": "Solid Security Pro", "sucuri-scanner": "Sucuri",
    "all-in-one-wp-security-and-firewall": "All-In-One Security",
    "jetpack-protect": "Jetpack Protect",
    "limit-login-attempts-reloaded": "Limit Login Attempts Reloaded",
    "wp-2fa": "WP 2FA", "two-factor": "Two Factor",
    "miniorange-2-factor-authentication": "miniOrange 2FA",
    "cloudflare": "Cloudflare", "patchstack": "Patchstack",
    "malcare-security": "MalCare", "wp-simple-firewall": "Shield Security"}


def security_plugins_seen(slugs: set, cookies: List[Dict]) -> List[str]:
    """Names of the security plugins the site shows from outside."""
    names = {SECURITY_PLUGINS[s] for s in slugs if s in SECURITY_PLUGINS}
    if any(c.get("name", "").startswith(("wfwaf-", "wordfence_")) for c in cookies or []):
        names.add("Wordfence")
    return sorted(names)


def detected_plugins(ctx: RunContext) -> set:
    """Plugin slugs the site itself advertised: asset URLs, REST namespaces
    and the homepage. Plugin-specific paths are requested only for these."""
    assets = ctx.data("assets") or {}
    rest = ctx.data("rest") or {}
    headers = ctx.data("headers") or {}
    return (set(assets.get("plugins") or {})
            | set(rest.get("namespace_plugins") or {})
            | set(headers.get("homepage_plugins") or []))


def collect_paths(ctx: RunContext) -> Tuple[str, int, str]:
    """Request every path in PROBE_PATHS, redirect-aware and calibrated."""
    missing = ctx.missing_signature
    calibration = ctx.data("calibration") or {}
    disallow = (calibration.get("control") or {}).get("robots_disallow", [])
    platform = ctx.manifest["meta"].get("platform", {})
    base_paths = PROBE_PATHS
    if platform.get("decided") and not platform.get("wordpress"):
        base_paths = [t for t in PROBE_PATHS
                      if "wp-" not in t[0] and t[0] not in WORDPRESS_ONLY_PATHS]
    probed = {p for p, _, _ in base_paths}
    extra = [t for t in _site_named_backups(ctx.site) if t[0] not in probed]
    extra += [t for slug in sorted(detected_plugins(ctx) & PLUGIN_PROBE_PATHS.keys())
              for t in PLUGIN_PROBE_PATHS[slug] if t[0] not in probed]
    # A listing of each advertised plugin's folder shows its full file set
    # and version. One request per plugin, capped.
    extra += [(f"/wp-content/plugins/{slug}/", "LOW",
               "a browsable plugin folder, which lists the plugin's full file set and version")
              for slug in sorted(detected_plugins(ctx))[:40]
              if f"/wp-content/plugins/{slug}/" not in probed]
    # Source maps for the theme the site advertises; never guessed.
    extra += [(f"/wp-content/themes/{slug}/style.css.map", "LOW",
               "a source map for the theme's stylesheet, which carries the original source and comments")
              for slug in ((ctx.data("headers") or {}).get("theme") or [])[:3]]
    probed |= {p for p, _, _ in extra}
    extra += [t for t in _robots_probe_rows(disallow) if t[0] not in probed]
    rows = []
    for path, severity, why in list(base_paths) + extra:
        if shutdown_requested:
            ctx.write("paths", rows)
            return "partial", len(rows), "stopped by the operator"
        url = ctx.site + path
        no_redirect_status, nr_hdrs = fetch_no_redirect(url)
        location = nr_hdrs.get("location", "")
        status, hdrs, body = fetch(url)
        exposed = path_is_exposed(path, status, body, missing,
                                  no_redirect_status, location)
        rows.append({
            "path": path,
            "url": url,
            "severity": severity,
            "why": why,
            "status": status,
            "no_redirect_status": no_redirect_status,
            "location": location,
            "bytes": len(body),
            "content_type": hdrs.get("content-type", ""),
            "exposed": exposed,
            "verdict": path_verdict(path, status, body, exposed,
                                    no_redirect_status),
            "error": hdrs.get("_error", ""),
        })
    exec_cal: Dict = {}
    if not (platform.get("decided") and not platform.get("wordpress")):
        exec_cal = calibrate_exec(ctx.site)
        ctx.write("exec_calibration", exec_cal)
        for path, severity, why in EXEC_CONFIG_PATHS:
            if shutdown_requested:
                ctx.write("paths", rows)
                return "partial", len(rows), "stopped by the operator"
            row = {"path": path, "url": ctx.site + path, "severity": severity,
                   "why": why, "rule": "exec-config", "status": 0,
                   "no_redirect_status": 0, "location": "", "bytes": 0,
                   "content_type": "", "exposed": False,
                   "verdict": "not checked", "error": ""}
            if exec_cal["usable"]:
                no_redirect_status, nr_hdrs = fetch_no_redirect(row["url"])
                status, hdrs, body = fetch(row["url"])
                hit = exec_copy_is_hit(status, no_redirect_status, body)
                leaked = config_source_leaked(status, body)
                row.update(
                    status=status, no_redirect_status=no_redirect_status,
                    location=nr_hdrs.get("location", ""), bytes=len(body),
                    content_type=hdrs.get("content-type", ""), exposed=hit,
                    error=hdrs.get("_error", ""),
                    verdict=("runs, empty 200" if hit else
                             path_verdict(path, status, body, False,
                                          no_redirect_status)))
            else:
                status, hdrs, body = fetch(row["url"])
                leaked = config_source_leaked(status, body)
            # PHP not running the file serves its source: the credentials
            # themselves. Content decides, so no calibration is needed.
            if leaked:
                row.update(status=status, bytes=len(body), exposed=True,
                           severity="CRITICAL", rule="config-source",
                           content_type=hdrs.get("content-type", ""),
                           verdict="readable",
                           why="The configuration source is served as text: "
                               "database password and salts.")
            rows.append(row)
        if exec_cal.get("php_disabled"):
            pd = exec_cal["php_disabled"]
            rows.append({"path": pd["path"], "url": pd["url"], "severity": "CRITICAL",
                         "why": "PHP source served as text: PHP is not running "
                                "here, so wp-config.php, with the database "
                                "password, is served the same way",
                         "rule": "php-disabled", "status": pd["status"],
                         "no_redirect_status": pd["status"], "location": "",
                         "bytes": pd["bytes"], "content_type": "", "exposed": True,
                         "verdict": "readable", "error": ""})
    ctx.write("paths", rows)
    notes = []
    unanswered = [r for r in rows if r["verdict"] in ("no answer", "rate limited")]
    if unanswered:
        # A probe that never got an answer was not checked. Saying "ok" here
        # would let the appendix read those rows as clean.
        notes.append(f"{len(unanswered)} path(s) got no answer or were rate "
                     "limited, so they were not checked: "
                     + ", ".join(r["path"] for r in unanswered[:8])
                     + ("..." if len(unanswered) > 8 else ""))
    if exec_cal.get("note"):
        notes.append(exec_cal["note"])
    if notes:
        return "partial", len(rows), "; ".join(notes)
    return "ok", len(rows), ""


def _php_version(hdrs: Dict[str, str]) -> str:
    """The PHP release named in X-Powered-By or Server, or "" if none."""
    match = re.search(r"\bPHP[ /](\d+\.\d+\.\d+)",
                      hdrs.get("x-powered-by", "") + " " + hdrs.get("server", ""),
                      flags=re.I)
    return match.group(1) if match else ""


def collect_headers(ctx: RunContext) -> Tuple[str, int, str]:
    """Security headers, leaky headers and cookie flags from the homepage."""
    status, hdrs, body = fetch(ctx.site + "/")
    if status == 0:
        ctx.write("headers", {})
        return "error", 0, hdrs.get("_error", "homepage unreachable")
    edge = edge_identity(hdrs, body, status)
    cookies = []
    # Multiple cookies arrive newline-joined from _headers(). Each one is
    # then "name=value; attr; attr".
    for chunk in hdrs.get("set-cookie", "").split("\n"):
        if "=" not in chunk:
            continue
        cookies.append(dict(name=chunk.split("=", 1)[0].strip(),
                            **cookie_flags(chunk)))
    generators = re.findall(r'<meta name="generator" content="([^"]+)"', body)

    # Core version, from every free source, because the generator tag is the
    # first thing a hardening guide removes and the homepage may be a cached
    # copy built before the last update. Sources are kept apart so a
    # disagreement is visible rather than averaged away.
    core_versions: Dict[str, str] = {}
    # A LiteSpeed cache hit replays the X-Powered-By it stored, so a cached
    # homepage reported PHP 8.2.34 a day after the site moved to 8.3.35.
    php_versions: Dict[str, str] = {}
    if _php_version(hdrs):
        php_versions["homepage"] = _php_version(hdrs)
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
        _, fresh_hdrs, fresh = fetch(f"{ctx.site}/?nc={uuid.uuid4().hex[:8]}")
        php = _php_version(fresh_hdrs)
        if php:
            php_versions["homepage (cache-busted)"] = php
        for g in re.findall(r'<meta name="generator" content="([^"]+)"', fresh):
            if g.lower().startswith("wordpress"):
                core_versions["generator (cache-busted)"] = re.sub(
                    r"^wordpress\s*", "", g, flags=re.I).strip()
        f_status, _, feed = fetch(ctx.site + "/feed/")
        if f_status == 200:
            match = re.search(r"<generator>[^<]*\?v=([^<\s]+)</generator>", feed)
            if match:
                core_versions["feed"] = match.group(1).strip()
        # The links OPML carries its own generator comment, which hardening
        # that strips the homepage tag usually leaves in place.
        o_status, _, opml = fetch(ctx.site + "/wp-links-opml.php")
        if o_status == 200:
            match = re.search(r'generator="WordPress/([^"\s]+)"', opml)
            if match:
                core_versions["opml"] = match.group(1).strip()

    themes = wp_slugs("themes", body)
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

    csp_metas = meta_csp(body)
    hsts_preload = ""
    if hdrs.get("strict-transport-security"):
        # One GET to hstspreload.org naming the domain, only when HSTS is sent.
        domain = urllib.parse.urlparse(ctx.site).hostname or ""
        _, _, pre = fetch_json("https://hstspreload.org/api/v2/status?domain="
                               + urllib.parse.quote(re.sub(r"^www\.", "", domain)))
        hsts_preload = pre.get("status", "") if isinstance(pre, dict) else "not measured"
    data = {
        "platform": ctx.manifest["meta"]["platform"],
        "mixed_content": mixed,
        "status": status,
        "headers": {k: v for k, v in hdrs.items() if not k.startswith("_")},
        # A meta CSP counts as sent; a report-only header enforces nothing.
        "missing": [h for h, _, _ in SECURITY_HEADERS if h not in hdrs
                    and not (h == "content-security-policy" and csp_metas)],
        "csp": csp_assessment(hdrs.get("content-security-policy", ""),
                              tuple(csp_metas)),
        "csp_report_only": bool(hdrs.get("content-security-policy-report-only"))
                           and "content-security-policy" not in hdrs,
        "pingback": pingback_advertised(hdrs, body),
        "hsts_preload": hsts_preload,
        "canonical_hosts": canonical_hosts(body),
        "custom_css": custom_css_signal(body, themes),
        "leaky": {h: hdrs[h] for h in LEAKY_HEADERS if h in hdrs},
        "cookies": cookies,
        "generators": generators,
        "core_versions": core_versions,
        "php_versions": php_versions,
        "theme": themes,
        "theme_info": theme_info,
        "homepage_plugins": wp_slugs("plugins", body),
        "author_links": homepage_author_slugs(body),
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
    # The index is cache-busted for the same reason the asset sweep is, and
    # the consequence here is worse. A page cache that serves a stale index
    # keeps advertising the namespace of a plugin that has just been
    # deactivated, and there is nothing in the response to say so: measured
    # on a live site where /wp-json/ came back x-kinsta-cache: HIT with 16
    # namespaces and the busted URL came back BYPASS with 15. That run put a
    # CVE against a plugin that was no longer running. It fails the other way
    # too - a cached index taken before a plugin was installed reports a
    # clean site - so the cache headers are recorded either way and a HIT
    # that survives the buster is said out loud rather than swallowed.
    bust = "nc=" + uuid.uuid4().hex[:8]
    attempts = []
    data = None
    cache = ""
    for base, url in (("/wp-json", f"{ctx.site}/wp-json/?{bust}"),
                      ("/?rest_route=", f"{ctx.site}/?rest_route=/&{bust}")):
        status, hdrs, data = fetch_json(url, max_bytes=REST_INDEX_MAX_BYTES)
        cache = (hdrs.get("x-kinsta-cache") or hdrs.get("x-cache")
                 or hdrs.get("cf-cache-status") or hdrs.get("x-litespeed-cache")
                 or "")
        attempts.append({"base": base, "status": status,
                         "truncated": bool(hdrs.get("_truncated")),
                         "cache": cache,
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
        if any(a["status"] in UNMEASURED_STATUSES for a in attempts):
            return ("error", 0,
                    "the REST index could not be read: HTTP "
                    + "/".join(str(a["status"]) for a in attempts)
                    + " (rate limited or unreachable). This is not the safer "
                    "state; the endpoint was not examined")
        last = attempts[-1]
        fallback = (f"HTTP {last['status']}" if last["status"] != 200 else
                    "a page rather than JSON, meaning the site ignores the "
                    "query string")
        return ("empty", 0,
                f"/wp-json/ returned HTTP {first['status']} and the "
                f"/?rest_route=/ fallback returned {fallback}, so the REST "
                "index is not anonymously readable, which is the safer state")
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
        tag, readme_status, lagging = _readme_probe(ctx.site, slug)
        namespace_plugins[slug] = {"name": name, "namespace": ns,
                                   "readme_version": tag,
                                   "readme_stable_tag": lagging,
                                   "readme_status": readme_status}
    # Discussion settings, from public content: a sample of posts and the
    # newest comments.
    p_status, _, posts = fetch_json(ctx.rest_url(
        "/wp/v2/posts?per_page=10&_fields=id,date,comment_status,ping_status"))
    c_status, _, comments = fetch_json(ctx.rest_url(
        "/wp/v2/comments?per_page=5&_fields=author_name,date,content"))
    # The site's JSON is untrusted: keep only well-formed entries, so a
    # malformed answer cannot stop the inventory above from being written.
    def _rendered(c):
        content = c.get("content")
        return str(content.get("rendered", "")) if isinstance(content, dict) else ""
    discussion = {
        "posts_status": p_status, "comments_status": c_status,
        "posts": [{"date": str(p.get("date") or ""), "comment_status": str(p.get("comment_status") or ""),
                   "ping_status": str(p.get("ping_status") or "")}
                  for p in (posts if isinstance(posts, list) else []) if isinstance(p, dict)],
        "comments": [{"author_name": str(c.get("author_name") or "")[:80],
                      "date": str(c.get("date") or "")[:10],
                      "links": len(re.findall(r"<a\b", _rendered(c)))}
                     for c in (comments if isinstance(comments, list) else []) if isinstance(c, dict)],
    }
    ctx.write("rest", {
        "discussion": discussion,
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "home": data.get("home", ""),
        "base": ctx.manifest["meta"].get("rest_base", "/wp-json"),
        "attempts": attempts,
        "cache": cache,
        "cache_hit": "hit" in cache.lower(),
        "route_count": len(routes),
        "namespaces": namespaces,
        "third_party": third_party,
        "namespace_plugins": namespace_plugins,
        "write_routes": write_routes,
        "authentication": data.get("authentication", {}),
    })
    notes = []
    if ctx.manifest["meta"].get("rest_base") != "/wp-json":
        notes.append("read via /?rest_route=/ because /wp-json/ did not answer")
    if "hit" in cache.lower():
        notes.append(f"the edge served this from cache ({cache}) despite the "
                     "cache-buster, so the plugin inventory below may be a "
                     "snapshot rather than the site as it stands now")
    return "ok", len(routes), "; ".join(notes)


def collect_users(ctx: RunContext) -> Tuple[str, int, str]:
    """Author names leak from many routes, not one.

    /wp-json/wp/v2/users is the one people close. ?author=N redirects to
    /author/<slug>/ and that slug is usually, but not always, the login name;
    the users sitemap and oEmbed's author_name publish display names. All
    four are read here, and oEmbed is reported only when author_name differs
    from provider_name, since most sites return the site name there and
    disclose nothing. Also read: author IDs 1 to 10, Yoast's
    author-sitemap.xml and the feed's dc:creator; homepage author links are
    read by the headers module.
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

    # ?author=N, redirects NOT followed, so the Location is visible. IDs have
    # gaps after deletions, so a miss does not stop the loop.
    for n in range(1, 11):
        code, h = fetch_no_redirect(f"{ctx.site}/?author={n}")
        location = h.get("location", "")
        if 300 <= code < 400 and "/author/" in location:
            slug = location.rstrip("/").rsplit("/", 1)[-1]
            if slug:
                result["author_redirect"].append({"n": n, "slug": slug})

    status, _, body = fetch(ctx.site + "/wp-sitemap-users-1.xml")
    if status == 200 and "<loc>" in body:
        result["sitemap"] = re.findall(r"<loc>([^<]+)</loc>", body)[:100]

    # Yoast's author sitemap; some Rank Math versions use the same path.
    status, _, body = fetch(ctx.site + "/author-sitemap.xml")
    result["yoast_sitemap"] = author_sitemap_slugs(body) if status == 200 else []

    # The feed's dc:creator carries display names. A feed that is off or
    # blocked is "not measured", never "none".
    # A feed switched off by redirecting to the homepage arrives as a 200
    # HTML page, so the body must be RSS or Atom to count as measured.
    status, _, body = fetch(ctx.site + "/feed/")
    result["feed_status"] = status
    result["feed_measured"] = is_feed(status, body)
    result["feed_creators"] = feed_creators(body) if result["feed_measured"] else []

    status, _, data = fetch_json(ctx.rest_url(
        "/oembed/1.0/embed?url=" + urllib.parse.quote(ctx.site + "/", safe="")))
    if isinstance(data, dict):
        author = data.get("author_name", "")
        provider = data.get("provider_name", "")
        if author and author != provider:
            result["oembed"] = author

    ctx.write("users", result)
    feed_note = ("" if result["feed_measured"] else
                 f"/feed/ answered HTTP {result['feed_status']}"
                 + (" with a page that is not a feed" if result["feed_status"] == 200 else "")
                 + ", so feed author names were not measured")
    if result["rest_status"] in UNMEASURED_STATUSES:
        return ("partial", len(result["rest"]),
                "; ".join(filter(None, [
                    f"/wp/v2/users answered HTTP {result['rest_status']} (rate "
                    "limited or unreachable), so the REST user list was not "
                    "examined; the other routes were", feed_note])))
    return "ok", len(result["rest"]), feed_note


def is_feed(status: int, body: str) -> bool:
    """Is this an RSS or Atom document rather than a page?"""
    return status == 200 and bool(re.search(r"<(?:rss|feed|rdf:rdf)\b", body[:3000], re.I))


def feed_creators(body: str) -> List[str]:
    """Display names from a feed's <dc:creator>, CDATA stripped, each
    capped at 60 characters, deduplicated in order."""
    out: List[str] = []
    for raw in re.findall(r"<dc:creator>(.*?)</dc:creator>", body, flags=re.S):
        name = unescape(re.sub(r"^\s*<!\[CDATA\[|\]\]>\s*$", "", raw).strip())[:60]
        if name and name not in out:
            out.append(name)
    return out


def author_sitemap_slugs(body: str) -> List[str]:
    """Author slugs from an author-sitemap.xml's /author/<slug>/ entries."""
    out: List[str] = []
    for slug in re.findall(r"<loc>\s*[^<]*/author/([^/<\s]+)/?\s*</loc>", body):
        if valid_slug(slug) and slug not in out:
            out.append(slug)
    return out


def homepage_author_slugs(body: str) -> List[str]:
    """Slugs from /author/<slug>/ links in a page. The ?author=N link form
    gives no slug and is ignored."""
    return sorted({s for s in re.findall(r"href=[\"'][^\"']*/author/([^/\"']+)/[\"']", body)
                   if valid_slug(s)})


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
    if probe_status in UNMEASURED_STATUSES:
        ctx.write("media", {})
        return ("error", 0,
                f"the media endpoint answered HTTP {probe_status} (rate "
                "limited or unreachable), so the library was not examined")
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
        "attachment_page": attachment_page_probe(items, ctx.site),
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


def attachment_page_probe(items: List[Dict], site: str) -> Dict:
    """Does one media item have its own HTML page? Since WordPress 6.4 a
    site with attachment pages off links straight to the file, so a link
    equal to the file URL needs no request."""
    item = next((i for i in items if i.get("link") and i.get("source_url")), None)
    # The link comes from the site's JSON; only the audited host is requested.
    if not item or not _in_scope(item["link"], site):
        return {}
    if item["link"] == item["source_url"]:
        return {"link": item["link"], "status": 0, "enabled": False}
    status, hdrs = fetch_no_redirect(item["link"])
    return {"link": item["link"], "status": status,
            "location": hdrs.get("location", ""),
            "enabled": status == 200}


def previous_run(run_dir: Path, filename: str, kind: type = list):
    """The most recent earlier run for the same host whose `filename`
    parses as `kind`. Returns (run name, data), or ("", None).

    Run directories are named <host>_<YYYYMMDD>_<HHMMSS>, so the name sorts by
    time. Only names older than this run count: a resumed old run must not
    inherit from a newer one.
    """
    host = run_dir.name.rsplit("_", 2)[0]
    pattern = re.compile(re.escape(host) + r"_\d{8}_\d{6}$")
    earlier = sorted((d for d in run_dir.parent.glob(f"{host}_*")
                      if pattern.match(d.name) and d.name < run_dir.name
                      and (d / filename).is_file()),
                     key=lambda d: d.name, reverse=True)
    for d in earlier:
        try:
            data = json.loads((d / filename).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            print_warning(f"{d.name}/{filename} unreadable, trying the run before it")
            continue
        if isinstance(data, kind):
            return d.name, data
    return "", None


def previous_documents(run_dir: Path) -> Tuple[str, List[Dict]]:
    """The most recent earlier run for the same host that has documents.json."""
    name, rows = previous_run(run_dir, "documents.json", list)
    return name, rows or []


def _check_document(url: str, library: Optional[set]) -> Dict:
    """HEAD one document URL (GET for one byte where HEAD is refused).

    library is None when the media walk did not complete: absence from an
    incomplete walk is not absence from the library, so in_library is None.
    """
    status, hdrs, _ = fetch(url, method="HEAD")
    if status in (405, 501):
        # Some hosts refuse HEAD. A GET capped at one byte of body is
        # the same question asked politely.
        status, hdrs, _ = fetch(url, max_bytes=1)
    return {
        "url": url,
        "status": status,
        "bytes": hdrs.get("content-length", ""),
        "content_type": hdrs.get("content-type", ""),
        "in_library": (None if library is None
                       else url.split("?")[0] in library),
        "sensitive": sensitive_hits(urllib.parse.urlparse(url).path.lower()),
    }


def collect_documents(ctx: RunContext) -> Tuple[str, int, str]:
    """Confirm each document resolves, and flag filenames worth opening.

    Also takes --url for a file found some other way, such as through a
    search engine. That is how the files an older install left behind get
    into the report at all: they are on disk, readable by URL, absent from
    the media library, and invisible in wp-admin.

    Every URL in the previous run's documents.json is re-checked too. The
    discovery routes do not return the same set every time: on 2026-09-07 and
    2026-09-10 a re-run found 30 documents, lost the 12 known orphans, and the
    report read as an improvement. A URL still answering 200 is carried
    forward; one that no longer does is reported as removed, never dropped.
    """
    media = ctx.data("media") or {}
    library = ({u.split("?")[0] for u in media.get("all_urls", [])}
               if ctx.module_status("media") == "ok" and ctx.data("media")
               else None)
    candidates = [d["url"] for d in media.get("documents", [])]
    # --url is a command-line flag, so a resumed run would otherwise drop the
    # extras and quietly produce different findings from the same run
    # directory. Merge with whatever the run already recorded and persist.
    known = ctx.manifest["meta"].get("extra_urls", [])
    merged = list(dict.fromkeys(known + list(ctx.args.url or [])))
    ctx.manifest["meta"]["extra_urls"] = merged
    ctx.save()
    extra = [u if u.startswith("http") else ctx.site + u for u in merged]
    prev_run, prev_rows = previous_documents(ctx.run_dir)
    if ctx.data("media") is None and not extra and not prev_rows:
        # Nothing to confirm. "ok, 0 rows" here read as "no documents" when
        # the media module had been skipped and no document was ever listed.
        ctx.write("documents", [])
        return ("skipped", 0, "depends on the media module, which did not "
                              "run, and no --url was given")
    rows = []
    discovered = list(dict.fromkeys(candidates + extra))
    for url in discovered:
        if shutdown_requested:
            break
        rows.append(_check_document(url, library))

    carried = removed = unmeasured = 0
    if not prev_run:
        print_info("documents: no previous run for this host, nothing to "
                   "carry forward")
    seen = set(discovered)
    for prev in prev_rows:
        url = prev.get("url", "")
        if not url or url in seen or shutdown_requested:
            continue
        seen.add(url)
        row = _check_document(url, library)
        if row["status"] == 200:
            row["carried_from"] = prev_run
            carried += 1
        elif row["status"] not in (404, 410):
            # A failed request, a 429, a 403 or a 5xx says nothing about
            # whether the file is still there. Keep it so the next run asks
            # again, but it is not reported as removed.
            row["carried_from"] = prev_run
            unmeasured += 1
        else:
            # Keep the run it first went missing after, so a file gone for
            # three runs does not look freshly removed on each.
            row["removed_since"] = prev.get("removed_since") or prev_run
            removed += 1
        rows.append(row)
    carry = {"previous_run": prev_run, "discovered": len(discovered),
             "carried": carried, "removed": removed, "unmeasured": unmeasured}
    ctx.manifest["meta"]["documents_carry"] = carry
    ctx.save()
    if prev_run:
        print_info(f"documents: {len(discovered)} discovered on this run, "
                   f"{carried} carried forward from {prev_run}, {removed} "
                   f"removed since, {unmeasured} unmeasured (request failed)")
    ctx.write("documents", rows)
    if shutdown_requested:
        return "partial", len(rows), "stopped by the operator"
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
    listed = _sitemap_urls(ctx.site)
    # Counted before the cap, or a 120-page sitemap read as "80 of 80".
    urls = listed[:ASSET_MAX_PAGES]
    if not urls:
        urls = [ctx.site + "/"]
    plugins: Dict[str, Dict] = {}
    page_rows = []
    failed: Dict[int, int] = {}
    external: Dict[str, Dict] = {}
    page_hits: List[Dict] = []
    secrets: List[Dict] = []
    debug: List[Dict] = []
    own_scripts: List[str] = []
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
        # A path with no ?ver= at all is the same evidence of an install.
        for hit in injected_content(body, ctx.site):
            page_hits.append(dict(hit, page=url))
        secrets += [dict(h, where=url) for h in secret_hits(body)]
        debug += [dict(h, page=url) for h in debug_hits(body)]
        for src in re.findall(r"<script\b[^>]*\bsrc=[\"']([^\"']+)", body, re.I):
            full = urllib.parse.urljoin(url, unescape(src)).split("?")[0]
            if _in_scope(full, ctx.site) and full not in own_scripts:
                own_scripts.append(full)
        for marker in signed_in_view(body):
            page_hits.append({"kind": "signed-in view", "severity": "HIGH",
                              "detail": marker, "page": url})
        for res in third_party_resources(body, ctx.site):
            entry = external.setdefault(res["url"], dict(res, pages=0))
            entry["pages"] += 1
        found = [(s, v) for s, v in found if valid_slug(s)]
        bare = set(wp_slugs("plugins", body))
        for slug in bare | {s for s, _ in found}:
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
        for slug in bare | {s for s, _ in found}:
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
        tag, readme_status, lagging = _readme_probe(ctx.site, slug)
        entry["readme_version"] = tag
        entry["readme_stable_tag"] = lagging
        entry["readme_status"] = readme_status
        if tag and not entry["versions"]:
            entry["versions"][tag] = 0
    # First-party scripts, where a key built into a bundle usually sits.
    # Same host only, cache-busted, capped.
    scanned = 0
    for src in own_scripts[:20]:
        if shutdown_requested:
            break
        st, _, js = fetch(f"{src}?nc={uuid.uuid4().hex[:8]}")
        if st == 200:
            scanned += 1
            secrets += [dict(h, where=src) for h in secret_hits(js)]
    data = {
        "pages_checked": len(page_rows),
        "pages_in_sitemap": len(listed),
        "pages_failed": failed,
        "cache_states": sorted({r["cache"] for r in page_rows if r["cache"]}),
        "plugins": {slug: {
            "versions": sorted(v["versions"]),
            "readme_version": v.get("readme_version", ""),
            "readme_stable_tag": v.get("readme_stable_tag", ""),
            "readme_status": v.get("readme_status", 0),
            "pages": v["pages"],
        } for slug, v in sorted(plugins.items())},
        "pages": page_rows,
        # shortcut: capped at 50 rows by page count; raise if a client asks for all.
        "third_party_resources": sorted(external.values(),
                                        key=lambda r: (-r["pages"], r["url"]))[:50],
        "third_party_total": len(external),
        "integrity_hits": page_hits[:100],
        "secrets": secrets[:100],
        "debug": debug[:50],
        "scripts_scanned": scanned,
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
    if len(listed) > len(urls):
        notes.append(f"the sitemap lists {len(listed)} pages; the first "
                     f"{ASSET_MAX_PAGES} were read")
    status = "partial" if failed and sum(failed.values()) * 4 > len(urls) else "ok"
    if shutdown_requested:
        notes.append("stopped by the operator")
        status = "partial"
    return status, len(page_rows), "; ".join(notes)


# CDNs that serve immutable files at a versioned path, so a tag can carry an
# integrity hash. Anything else (tag managers, chat widgets, fonts) serves
# changing bytes and cannot be pinned.
PINNABLE_HOSTS = ("cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
                  "ajax.googleapis.com")


def third_party_resources(body: str, site: str) -> List[Dict]:
    """Cross-origin scripts and stylesheets named in a page's HTML, with
    whether each tag carries integrity=. www. and the bare host are the same
    site. Tags a script builds at runtime (GTM does) are not in the HTML and
    are not seen."""
    own = re.sub(r"^www\.", "", urllib.parse.urlparse(site).netloc.lower())
    out, seen = [], set()
    for tag in re.findall(r"<(?:script|link)\b[^>]*>", body, flags=re.I):
        is_script = tag[1:7].lower() == "script"
        if is_script:
            m = re.search(r"\bsrc\s*=\s*[\"']([^\"']+)", tag, flags=re.I)
        else:
            rel = re.search(r"\brel\s*=\s*[\"']([^\"']*)", tag, flags=re.I)
            if not rel or "stylesheet" not in rel.group(1).lower():
                continue
            m = re.search(r"\bhref\s*=\s*[\"']([^\"']+)", tag, flags=re.I)
        if not m:
            continue
        url = unescape(m.group(1).strip())
        if url.startswith("//"):
            url = "https:" + url
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.lower()
        if parsed.scheme not in ("http", "https") or not host or \
                re.sub(r"^www\.", "", host) == own or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "host": host,
                    "type": "script" if is_script else "stylesheet",
                    "integrity": bool(re.search(r"\bintegrity\s*=", tag, flags=re.I)),
                    "pinnable": host in PINNABLE_HOSTS
                                and bool(re.search(r"\d+\.\d+", parsed.path))})
    return out


# Credential shapes, with the vendor's documented prefix or format. Only a
# masked form is ever stored or printed. A Google Maps browser key is
# public by design and is reported apart, as INFO.
SECRET_PATTERNS: List[Tuple[str, str, "re.Pattern"]] = [
    ("Stripe live secret key", "CRITICAL", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}")),
    ("Private key", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("AWS access key ID", "HIGH", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Mailgun API key", "HIGH", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[abposr]-[0-9A-Za-z-]{10,}")),
    ("Google OAuth client secret", "HIGH", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b")),
    ("Twilio account SID with a token nearby", "HIGH",
     re.compile(r"\bAC[0-9a-f]{32}\b.{0,120}?\b[0-9a-f]{32}\b", re.S)),
    ("Credential assigned in code", "HIGH", re.compile(
        r"[\"']?(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|password|passwd)[\"']?"
        r"\s*[:=]\s*[\"']((?=[^\"'\s]*\d)(?=[^\"'\s]*[A-Za-z])[^\"'\s]{16,})[\"']", re.I)),
]
MAPS_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")


def _mask(value: str) -> str:
    """First four and last two characters; never the secret itself."""
    return value[:4] + "..." + value[-2:] if len(value) > 8 else "****"


def secret_hits(text: str) -> List[Dict[str, str]]:
    """Credential-shaped strings in a page or script, masked."""
    out = []
    for vendor, severity, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            out.append({"vendor": vendor, "severity": severity,
                        "masked": "-----BEGIN ... PRIVATE KEY-----" if vendor == "Private key"
                        else _mask(value)})
    out += [{"vendor": "Google Maps browser key", "severity": "INFO", "masked": _mask(k)}
            for k in set(MAPS_KEY_RE.findall(text))]
    seen, unique = set(), []
    for h in out:
        if (h["vendor"], h["masked"]) not in seen:
            seen.add((h["vendor"], h["masked"]))
            unique.append(h)
    return unique


DEBUG_RE = re.compile(
    r"(?:<b>)?(Notice|Warning|Deprecated|Fatal error|Parse error)(?:</b>)?:\s.{0,300}?"
    r"\bin\s+(?:<b>)?((?:[A-Za-z]:\\|/)[^<\s]+\.php)", re.S)


def debug_hits(body: str) -> List[Dict[str, str]]:
    """PHP errors printed into the page with a file path, and core scripts
    served unminified (SCRIPT_DEBUG)."""
    out = [{"kind": f"PHP {kind.lower()}", "detail": path}
           for kind, path in dict.fromkeys(DEBUG_RE.findall(body))][:10]
    unmin = re.search(r"/wp-includes/js/dist/([a-z0-9-]+)\.js\?ver=", body)
    if unmin:
        out.append({"kind": "unminified core script", "detail": f"wp-includes/js/dist/{unmin.group(1)}.js"})
    return out


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
            for child in [u for u in children if _in_scope(u, site)][:6]:
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
        if (u not in seen and not u.endswith((".xml", ".jpg", ".png"))
                and _in_scope(u, site)):
            seen.add(u)
            unique.append(u)
    return unique


def _in_scope(url: str, site: str) -> bool:
    """Is a URL the site published one this audit may request? Same host,
    with or without www., over http(s). A sitemap is the site's own content,
    and one pointing at 127.0.0.1 would have had this tool fetch it."""
    parsed = urllib.parse.urlparse(url)
    return (parsed.scheme in ("http", "https")
            and re.sub(r"^www\.", "", parsed.netloc.lower())
            == re.sub(r"^www\.", "", urllib.parse.urlparse(site).netloc.lower()))


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
                         "readme_version": tag,
                         "readme_stable_tag": info.get("readme_stable_tag", ""),
                         "readme_status": info.get("readme_status", 0),
                         "source": "rest namespace"}
    # Named in the homepage HTML but absent from the sweep (assets skipped
    # or the sitemap missed the homepage): still installed, still checked.
    for slug in headers.get("homepage_plugins", []) or []:
        plugins.setdefault(slug, {"versions": [], "pages": 0,
                                  "source": "homepage"})
    theme_info = headers.get("theme_info", {}) or {}
    theme_slugs = list(headers.get("theme", []) or [])
    # A child theme runs its parent's code, so the parent is checked too.
    for info in list(theme_info.values()):
        parent = (info or {}).get("parent", "")
        if parent and parent not in theme_slugs:
            theme_slugs.append(parent)

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
    for key in ("generator (cache-busted)", "generator", "feed", "opml"):
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
    # The release list and the vulnerability feed are separate services. An
    # api.wordpress.org outage used to skip the CVE lookup as well.
    if detected_core and version_ordered(detected_core):
        floor = version_key(detected_core)
        if latest_core:
            core["releases_behind"] = sum(
                1 for v in releases
                if version_ordered(v) and version_key(v) > floor)
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

    # PHP. /php/<version>/ returns every record for the branch, so ranges are
    # matched like a plugin's. An end-of-life branch gets no new records
    # (7.4 has no php2shell entry), which is why date_end is kept.
    php_sources = dict(headers.get("php_versions") or {})
    detected_php = (php_sources.get("homepage (cache-busted)")
                    or php_sources.get("homepage", ""))
    php: Dict = {"detected": detected_php, "sources": php_sources}
    if detected_php:
        lookup = _wpvuln("php", detected_php)
        php["covered"] = lookup["covered"]
        php["lookup_error"] = lookup["error"]
        php["branch_end"] = lookup["record"].get("date_end") or ""
        php["vulnerabilities"], php["undecidable"] = _vuln_rows(
            lookup["record"], detected_php)
        # Some PHP CVEs only exist on Windows builds (CVE-2024-4577 is a 9.8
        # that is "unfixed" on 7.4). The feed has no platform field, so the
        # CVE text decides, matched narrowly: a miss still counts against
        # the site, which is the safe direction.
        windows_text = {s.get("id"): bool(WINDOWS_ONLY.search(s.get("description") or ""))
                        for e in lookup["record"].get("vulnerability") or []
                        for s in e.get("source") or []}
        for row in php["vulnerabilities"]:
            row["windows_only"] = windows_text.get(row["cve"], False)
        server = " ".join((headers.get("headers") or {}).get(h, "")
                          for h in ("server", "x-powered-by"))
        php["windows_server"] = bool(re.search(r"iis|win32|win64|asp\.net",
                                               server, flags=re.I))
    data["php"] = php

    # WordPress stamps its own version on a file a plugin enqueues without
    # one, so the core version among a plugin's ver= values is WordPress's.
    # A plugin left with no version is then matched as unreadable, which is
    # the cautious reading; one that really shares the core number loses it.
    core_seen = {v for v in (headers.get("core_versions") or {}).values() if version_ordered(v)}

    # Plugins. Sorted so a resumed run and a fresh run produce the same file.
    for slug, info in sorted(plugins.items()):
        if shutdown_requested:
            break
        versions = [v for v in info.get("versions", []) if version_ordered(v)]
        own = without_core(versions, core_seen)
        core_dropped = len(own) < len(versions)
        versions = own
        entry: Dict = {"detected_versions": info.get("versions", []),
                       "readme_version": info.get("readme_version", ""),
                       "readme_stable_tag": info.get("readme_stable_tag", ""),
                       "readme_status": info.get("readme_status", 0),
                       "source": info.get("source", "assets"),
                       "pages": info.get("pages", 0),
                       "core_version_dropped": core_dropped}
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
        # Matched against the running version alone. Matching every detected
        # version reported a vulnerability the site does not have every time a
        # bundled script carried an old ver=.
        entry["version_running"] = running_version(versions)
        matched: List[Dict] = []
        undecidable = 0
        if entry["version_running"]:
            matched, undecidable = _vuln_rows(lookup["record"],
                                              entry["version_running"])
            matched = [dict(r, affected_version=entry["version_running"])
                       for r in matched]
        else:
            # No version was read, but a record with no lower bound that still
            # covers the current release covers every release, so the missing
            # version does not make it unknowable. Reporting these as an INFO
            # "could not be checked" line buried an unpatchable path traversal
            # that affected the site whatever it was running.
            matched = [dict(row, affected_version="", every_release=True)
                       for row in _every_release_rows(
                           lookup["record"],
                           (entry["wporg"] or {}).get("current_version", ""))]
        entry["vulnerabilities"] = sorted(matched, key=lambda r: r["score"],
                                          reverse=True)
        entry["undecidable"] = undecidable
        # The changelog raised the version above the readme's Stable tag.
        # Whatever the old tag would match and the running version does not
        # is reported as disputed, so the higher reading cannot hide it.
        lagging = entry["readme_stable_tag"]
        # A readme.txt below the highest asset version is the other witness:
        # a bundled library's ver= can sit above the plugin's own release.
        if (not lagging and readme and version_ordered(readme)
                and entry["version_running"]
                and version_key(readme) < version_key(entry["version_running"])):
            lagging = readme
        if lagging and version_ordered(lagging):
            seen = {r.get("cve") or r.get("name") for r in matched}
            at_tag, _ = _vuln_rows(lookup["record"], lagging)
            entry["disputed_vulnerabilities"] = sorted(
                (dict(r, affected_version=lagging) for r in at_tag
                 if (r.get("cve") or r.get("name")) not in seen),
                key=lambda r: r["score"] or 0, reverse=True)
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
                 "version_running": running_version(versions),
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
        else:
            rows = [dict(row, affected_version="", every_release=True)
                    for row in _every_release_rows(
                        lookup["record"],
                        (entry["wporg"] or {}).get("current_version", ""))]
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
    if shutdown_requested:
        return "partial", rows, "stopped by the operator"
    return "ok", rows, note


# A plugin's job, from the tags it gives itself on wordpress.org.
PLUGIN_JOBS = (("SEO", ("seo", "sitemap", "schema")),
               ("caching", ("cache", "caching", "performance", "minify")),
               ("security", ("security", "firewall", "malware", "brute force")),
               ("forms", ("form", "forms", "contact form", "form builder")),
               ("backup", ("backup", "backups", "restore")))


def plugin_job(tags: List[str]) -> str:
    """The job with the most matching tags. LiteSpeed Cache tags itself
    "seo" as well as "caching" and "performance", and first-match made it an
    SEO plugin and a false duplicate of the site's real one."""
    low = {t.lower() for t in tags}
    scored = [(len(low & set(words)), job) for job, words in PLUGIN_JOBS]
    best = max(scored)
    return best[1] if best[0] else ""


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
        "tags": list((payload.get("tags") or {}).values())
                if isinstance(payload.get("tags"), dict) else [],
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
    running = running_version(versions)
    if running and current["current_version"]:
        current["outdated"] = (version_key(running)
                               < version_key(current["current_version"]))
        # Only count releases when the list demonstrably reaches the current
        # release. wordpress.org returned 11 versions topping out at 1.7 for a
        # plugin then shipping 8.0.4, and counting against that list reported
        # a plugin two majors behind as perfectly current.
        if current["current_version"] in all_versions:
            floor = version_key(running)
            ceiling = version_key(current["current_version"])
            # Only releases up to the current one count. The list also
            # carries betas and tags above it, which reported a plugin ON the
            # current release as three releases behind it.
            current["releases_behind"] = sum(
                1 for v in all_versions
                if floor < version_key(v) <= ceiling)
    return current


def collect_transport(ctx: RunContext) -> Tuple[str, int, str]:
    """HTTP-to-HTTPS behaviour, TLS, CORS, XML-RPC and security.txt."""
    parsed = urllib.parse.urlparse(ctx.site)
    host = parsed.netloc
    data: Dict = {"host": host}

    http_status, http_hdrs = fetch_no_redirect("http://" + parsed.hostname + "/")
    data["http"] = {"status": http_status,
                    "location": http_hdrs.get("location", "")}

    data["tls"] = (_tls_info(parsed.hostname, parsed.port or 443)
                   if parsed.scheme == "https" else {"error": "site is not HTTPS"})
    # Run even when the main handshake failed: a server that speaks only
    # TLS 1.0 fails it, and that is the case this check exists for.
    if parsed.scheme == "https":
        data["tls_legacy"] = legacy_tls(parsed.hostname, parsed.port or 443)

    _, cors_hdrs, _ = fetch(ctx.site + "/wp-json/")
    data["cors"] = cors_hdrs.get("access-control-allow-origin", "")

    # XML-RPC without a POST: GET returns a one-line refusal when the
    # endpoint is live and a 403/404 when it is blocked. WordPress sends that
    # refusal with a 405 (WP #20986), so requiring a 200 read every stock
    # install as blocked. Listing the available methods would need
    # system.listMethods, which is a POST.
    status, _, body = fetch(ctx.site + "/xmlrpc.php")
    data["xmlrpc"] = {
        "status": status,
        "answering": xmlrpc_answering(status, body),
    }

    # The login page shows a Register link only while "Anyone can register"
    # is on. A renamed or blocked login page answers 404 and reads as closed.
    status, _, body = fetch(ctx.site + "/wp-login.php")
    data["registration"] = {"status": status,
                            "open": registration_open(status, body)}

    # GraphQL by GET with a query string, the same class of request as
    # ?author=1: it asks for one word (__typename) and changes nothing.
    # WPGraphQL answers /index.php?graphql even when /graphql is renamed. A
    # themed 200 or a redirect to the homepage is not JSON and reads absent.
    graphql = []
    for path in ("/graphql?query=%7B__typename%7D",
                 "/index.php?graphql&query=%7B__typename%7D"):
        status, _, obj = fetch_json(ctx.site + path)
        graphql.append({"url": ctx.site + path, "status": status,
                        "answering": graphql_answering(status, obj)})
        if graphql[-1]["answering"]:
            break
    data["graphql"] = graphql

    # The other host form (www or bare): a copy under a second name, or a
    # name with no valid certificate, is invisible from the audited one.
    hostname = parsed.hostname or ""
    other = hostname[4:] if hostname.startswith("www.") else "www." + hostname
    o_status, o_hdrs = fetch_no_redirect(f"https://{other}/")
    data["other_host"] = {"host": other, "status": o_status,
                          "location": o_hdrs.get("location", ""),
                          "state": other_host_state(o_status, o_hdrs.get("_error", ""),
                                                    o_hdrs.get("location", ""), hostname)}
    # The login form over plain HTTP, and the cookies it sets over HTTPS:
    # wp-login.php sets a cookie on every visit, the homepage often none.
    lh_status, lh_hdrs = fetch_no_redirect(f"http://{hostname}/wp-login.php")
    l_body = fetch(f"http://{hostname}/wp-login.php")[2] if lh_status == 200 else ""
    data["login_http"] = {"status": lh_status,
                          "form_in_clear": lh_status == 200 and 'name="log"' in l_body}
    _, ls_hdrs, _ = fetch(ctx.site + "/wp-login.php")
    data["login_cookies"] = [dict(name=c.split("=", 1)[0].strip(), **cookie_flags(c))
                             for c in ls_hdrs.get("set-cookie", "").split("\n") if "=" in c]

    status, _, body = fetch(ctx.site + "/.well-known/security.txt")
    data["security_txt"] = {"status": status,
                            "present": security_txt_present(status, body)}

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
    probes = [http_status, data["xmlrpc"]["status"], data["wp_cron"]["status"],
              data["robots"]["status"], data["security_txt"]["status"]]
    if not any(probes) and data["tls"].get("error"):
        return "error", 0, "no request got an answer"
    notes = []
    if probes.count(0):
        notes.append(f"{probes.count(0)} of {len(probes)} requests got no answer")
    if data["registration"]["status"] in UNMEASURED_STATUSES:
        notes.append(f"wp-login.php answered HTTP {data['registration']['status']}, "
                     "so open registration was not checked")
    if data["tls"].get("error") and not data["tls"].get("verify_error"):
        notes.append("TLS not measured: " + data["tls"]["error"])
    return ("partial" if notes else "ok"), 1, "; ".join(notes)


def graphql_answering(status: int, data) -> bool:
    """Is this a GraphQL endpoint's answer? A JSON object whose data names
    a __typename, or an errors list that talks about a query or GraphQL.
    A REST error object, HTML (data None) and a non-200 are not."""
    if status != 200 or not isinstance(data, dict):
        return False
    if isinstance(data.get("data"), dict) and isinstance(
            data["data"].get("__typename"), str):
        return True
    errors = data.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        return bool(re.search(r"query|graphql", str(errors[0].get("message", "")), re.I))
    return False


def graphql_profile(probes) -> str:
    """One profile line for the GraphQL probes: answering, absent with the
    statuses seen, or not measured when no probe got a usable answer."""
    if probes is None:
        return ""  # run before 1.13.0
    hit = next((g for g in probes if g.get("answering")), None)
    if hit:
        return f"answering at {hit['url']}"
    if probes and all(g.get("status") in UNMEASURED_STATUSES for g in probes):
        return "not measured (" + ", ".join(f"HTTP {g['status']}" for g in probes) + ")"
    return "absent (" + ", ".join(f"HTTP {g['status']}" for g in probes) + ")"


def other_host_state(status: int, error: str, location: str, canonical_host: str) -> str:
    """What the www or bare form of the host does over HTTPS: "redirects",
    "no DNS", "certificate error", "serves a copy" or "not measured"."""
    low = (error or "").lower()
    if status == 0:
        if "nodename nor servname" in low or "name or service not known" in low \
                or "getaddrinfo" in low or "no address" in low:
            return "no DNS"
        if "certificate" in low:
            return "certificate error"
        return "not measured"
    if 300 <= status < 400:
        return "redirects"
    if status == 200:
        return "serves a copy"
    return "not measured"


def xmlrpc_answering(status: int, body: str) -> bool:
    """Is xmlrpc.php the live WordPress endpoint? Its GET refusal names
    itself; a bare 405 from a WAF does not."""
    return status in (200, 405) and "xml-rpc server accepts" in body.lower()


def registration_open(status: int, body: str) -> bool:
    """Does the login page offer a Register link? WordPress prints one only
    when users_can_register is on; esc_url writes the & as &#038;."""
    return status == 200 and bool(re.search(
        r"href=[\"'][^\"']*[?&](?:amp;|#038;)?action=register\b", body))


def wpcom_unclaimed(body: str) -> bool:
    """Is this WordPress.com's page for a site name nobody holds? The two
    phrases are the nuclei-templates wordpress-takeover matchers."""
    low = body.lower()
    return bool(re.search(r"do you want to register\s*(?:<em>)?[\w.-]+\.wordpress\.com", low)
                or ".wordpress.com</em> doesn&#8217;t&nbsp;exist" in low)


def cookie_flags(set_cookie: str) -> Dict[str, bool]:
    """Secure, HttpOnly and SameSite as attributes of one Set-Cookie line.

    Only the parts after the first ';' are attributes. Searching the whole
    line let a value such as session=secure-httponly pass for both flags.
    """
    attrs = {part.split("=", 1)[0].strip().lower()
             for part in set_cookie.split(";")[1:]}
    return {"secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": "samesite" in attrs}


# wordpress.org slugs are lowercase letters, digits and hyphens; premium and
# custom plugins add underscores and the odd dot. wordpress.org is
# case-sensitive, so "MyPlugin" would not be found there anyway. Without
# this, "*" read from a preload hint was looked up as a plugin.
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")


def valid_slug(slug: str) -> bool:
    """Is this captured path segment a plausible plugin or theme slug?"""
    return bool(SLUG_RE.fullmatch(slug))


def wp_slugs(kind: str, body: str) -> List[str]:
    """Plugin or theme slugs (kind "plugins" or "themes") named in a page,
    dropping template placeholders such as *, %7Bslug%7D and ${plugin}."""
    return sorted({s for s in re.findall(rf"/wp-content/{kind}/([^/\"'?#]+)/", body)
                   if valid_slug(s)})


def custom_css_signal(body: str, themes: List[str]) -> str:
    """Evidence of styling written into the theme itself: a custom.css in a
    theme folder, or a large anonymous <style> block. WordPress's own inline
    styles (Additional CSS, global styles, enqueued -inline-css) are stored
    outside the theme and survive an update, so they do not count."""
    for slug in themes:
        if f"/wp-content/themes/{slug}/custom.css" in body:
            return f"wp-content/themes/{slug}/custom.css"
    for attrs, css in re.findall(r"<style\b([^>]*)>(.*?)</style>", body, re.I | re.S):
        if "id=" not in attrs.lower() and len(css) > 2000:
            return f"an inline style block of {len(css)} bytes"
    return ""


def canonical_hosts(body: str) -> Dict[str, str]:
    """Host named by <link rel="canonical"> and og:url, where present."""
    out = {}
    for label, rx in (("canonical", r"<link\b[^>]*rel=[\"']canonical[\"'][^>]*>"),
                      ("og:url", r"<meta\b[^>]*property=[\"']og:url[\"'][^>]*>")):
        tag = re.search(rx, body, re.I)
        if tag:
            m = re.search(r"(?:href|content)=[\"']([^\"']+)", tag.group(0), re.I)
            if m:
                out[label] = (urllib.parse.urlparse(unescape(m.group(1))).hostname or "").lower()
    return out


def hsts_assessment(value: str) -> Dict:
    """max-age in seconds (None if unreadable), includeSubDomains, preload."""
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    return {"max_age": int(m.group(1)) if m else None,
            "include_subdomains": bool(re.search(r"includesubdomains", value, re.I)),
            "preload": bool(re.search(r"\bpreload\b", value, re.I))}


def _csp_directives(policy: str) -> Dict[str, List[str]]:
    """One serialised policy as {directive: [sources]}. A repeated
    directive is ignored after the first, as browsers do."""
    out: Dict[str, List[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in out:
            out[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return out


def csp_assessment(header: str, metas: Tuple[str, ...] = ()) -> Dict[str, bool]:
    """Grade a Content-Security-Policy on what it actually restricts.

    `header` may hold several policies joined by commas (two CSP headers
    are both enforced); `metas` are the content of meta http-equiv tags.
    A directive enforced by any one policy counts, because the browser
    applies them all. A meta policy cannot carry frame-ancestors, so it is
    dropped there. object-src falls back to default-src; base-uri and
    frame-ancestors do not fall back to anything. "upgrade-insecure-requests"
    alone was counted as a CSP while restricting no script at all.
    """
    policies = [_csp_directives(p) for p in header.split(",") if p.strip()]
    for m in metas:
        d = _csp_directives(m)
        d.pop("frame-ancestors", None)
        policies.append(d)
    scripts = [p.get("script-src", p.get("default-src")) for p in policies]
    scripts = [s for s in scripts if s is not None]

    def object_none(p):
        src = p.get("object-src", p.get("default-src"))
        return src == ["'none'"]

    def loose(s):
        return any(t in ("*", "https:", "http:") for t in s)

    # A weakness only counts when every script policy has it: one policy
    # without 'unsafe-inline' is enough to block inline script.
    return {
        "present": bool(policies),
        "has_script_source": bool(scripts),
        "object_src_none": any(object_none(p) for p in policies),
        "has_base_uri": any("base-uri" in p for p in policies),
        "has_frame_ancestors": any("frame-ancestors" in p for p in policies),
        "unsafe_inline": bool(scripts) and all("'unsafe-inline'" in s for s in scripts),
        "unsafe_eval": bool(scripts) and all("'unsafe-eval'" in s for s in scripts),
        "wildcard": bool(scripts) and all(loose(s) for s in scripts),
        "from_meta": bool(metas),
    }


def pingback_advertised(hdrs: Dict[str, str], body: str) -> Dict[str, str]:
    """Where the site advertises XML-RPC: the X-Pingback header and the
    <link rel="pingback"> tag. Other scanners list the header as version
    disclosure; it is the same endpoint xmlrpc.php, announced."""
    link = ""
    for tag in re.findall(r"<link\b[^>]*>", body, flags=re.I):
        if re.search(r"\brel\s*=\s*[\"']?pingback[\"'\s>/]", tag, flags=re.I):
            m = re.search(r"href\s*=\s*[\"']([^\"']+)", tag, flags=re.I)
            link = m.group(1) if m else ""
            break
    return {"header": hdrs.get("x-pingback", ""), "link": link}


def meta_csp(body: str) -> List[str]:
    """Content of every <meta http-equiv="Content-Security-Policy"> tag."""
    out = []
    for tag in re.findall(r"<meta\b[^>]*>", body, flags=re.I):
        if re.search(r"http-equiv\s*=\s*[\"']?content-security-policy[\"'\s>]",
                     tag, flags=re.I):
            m = re.search(r"content\s*=\s*(\"[^\"]*\"|'[^']*')", tag, flags=re.I)
            if m:
                out.append(unescape(m.group(1)[1:-1]))
    return out


def security_txt_present(status: int, body: str) -> bool:
    """Is this a security.txt, whatever its vintage?

    RFC 9116 requires a Contact field, but files that predate it use Email:
    and are still a working disclosure channel. One large site's file was
    reported absent for that. A 200 that is HTML is a soft 404, not a file.
    """
    if status != 200 or "<html" in body[:2000].lower():
        return False
    return bool(re.search(r"(?im)^\s*(contact|email|policy|encryption|expires|"
                          r"acknowledgments|acknowledgements):", body))


def _tls_info(host: str, port: int = 443) -> Dict:
    """Certificate issuer, expiry and negotiated protocol. Read-only
    handshake, no data sent beyond the TLS ClientHello.

    A certificate that fails verification (expired, wrong name, untrusted)
    never completes the handshake, so it has no expiry to read. It is kept
    as verify_error, which is a measurement, apart from a connection that
    failed, which is not.
    """
    out: Dict = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                out["protocol"] = tls.version()
                cert = tls.getpeercert() or {}
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        out["issuer"] = issuer.get("organizationName", "?")
        out["expires"] = cert.get("notAfter", "")
        if out["expires"]:
            out.update(_tls_time_left(out["expires"], time.time()))
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["verify_error"] = exc.verify_message or str(exc)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def classify_tls_failure(message: str) -> str:
    """A failed pinned-version handshake: "refused" when the server said no
    (protocol alert, handshake failure, a different version, a reset), "not
    measured" when this client could not offer the version or the
    connection failed for another reason. Measured with OpenSSL 4.1 against
    badssl.com's TLS 1.0 and 1.1 hosts, 2026-11-04."""
    low = message.lower()
    if "no protocols available" in low or "no ciphers available" in low:
        return "not measured"
    if any(k in low for k in ("alert protocol version", "handshake failure",
                              "unsupported protocol", "wrong version number",
                              "connection reset", "eof occurred")):
        return "refused"
    return "not measured"


def tls_version_probe(host: str, port: int, version) -> str:
    """Offer exactly one TLS version: "accepted", "refused" or "not
    measured". The certificate was verified by the main handshake, so these
    probes skip verification; old versions need SECLEVEL=0 to be offered."""
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError, AttributeError):
        return "not measured"
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "accepted"
    except Exception as exc:
        return classify_tls_failure(f"{type(exc).__name__}: {exc}")


def legacy_tls(host: str, port: int = 443) -> Dict[str, str]:
    """TLS 1.0 and 1.1 offered alone, with TLS 1.2 as the control: if the
    control got no usable answer, neither legacy result is trusted."""
    v = ssl.TLSVersion
    out = {"TLSv1.2": tls_version_probe(host, port, v.TLSv1_2)}
    for name, ver in (("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1")):
        out[name] = (tls_version_probe(host, port, getattr(v, ver))
                     if out["TLSv1.2"] != "not measured" else "not measured")
    return out


def _tls_time_left(not_after: str, now: float) -> Dict:
    """Seconds and whole days to a certificate's notAfter, both in UTC. A
    certificate that lapses later today has 0 days left but is not expired."""
    seconds = int(ssl.cert_time_to_seconds(not_after) - now)
    return {"seconds_left": seconds, "days_left": seconds // 86400}


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
    if data["spf"]:
        data["spf_lookups"], data["spf_loop"] = spf_lookup_count(data["spf"], _dns_txt)
    if data["mx"]:
        data["mta_sts_txt"] = next((r for r in _dns_txt("_mta-sts." + domain)
                                    if r.lower().startswith("v=stsv1")), "")
        st, _, pol = fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
        data["mta_sts_policy"] = bool(st == 200 and re.search(r"(?im)^version:\s*STSv1", pol))
        data["tls_rpt"] = next((r for r in _dns_txt("_smtp._tls." + domain)
                                if r.lower().startswith("v=tlsrptv1")), "")
    data["bimi"] = next((r for r in _dns_txt("default._bimi." + domain)
                         if r.lower().startswith("v=bimi1")), "")

    # CAA is inherited upward: the closest name with a CAA set governs. An
    # empty answer counts as "none" only if the zone resolved at all.
    labels = host.split(".")
    data["caa"], data["caa_at"] = [], ""
    for i in range(0, len(labels) - 1):
        name = ".".join(labels[i:])
        records = caa_records(_dig(name, "CAA") or _doh(name, "CAA"))
        if records:
            data["caa"], data["caa_at"] = records, name
            break
    data["caa_measured"] = bool(data["caa"]) or bool(
        _dig(".".join(labels[-2:]), "NS") or _doh(".".join(labels[-2:]), "NS"))
    # The AD flag from a validating resolver; dig +short does not show it.
    _, _, doh_a = fetch_json(f"{DOH_URL}?name={urllib.parse.quote(domain)}&type=A")
    data["dnssec_validated"] = dnssec_validated(doh_a)
    # A host name still pointing at a WordPress.com site that was deleted
    # can be claimed by whoever registers that name there.
    data["host"] = host
    data["cname"] = _dns_cname(host)
    data["wpcom_unclaimed"] = False
    if data["cname"].lower().endswith(".wordpress.com"):
        _, _, body = fetch(ctx.site + "/")
        data["wpcom_unclaimed"] = wpcom_unclaimed(body)
    ctx.write("dns", data)
    return "ok", 1, ""


def spf_lookup_count(spf: str, get_txt, seen=None, depth: int = 0) -> Tuple[int, bool]:
    """DNS lookups an SPF check costs (RFC 7208 section 4.6.4: include, a,
    mx, ptr, exists and redirect each count), following include: and
    redirect= recursively. Returns (count, a loop or depth over 10 seen)."""
    seen = set() if seen is None else seen
    # A hostile chain must not make the run resolve without end: past 20
    # distinct names the record is far over the limit of ten anyway.
    if depth > 10 or len(seen) > 20:
        return 0, True
    count, looped = 0, False
    for term in spf.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if re.match(r"(?:a|mx|ptr)(?:[:/]|$)|exists:", t):
            count += 1
        m = re.match(r"(?:include:|redirect=)(\S+)", t)
        if m:
            count += 1
            target = m.group(1)
            if not DNS_NAME_RE.fullmatch(target):
                continue
            if target in seen:
                looped = True
                continue
            if len(seen) >= 20:
                return count, True
            seen.add(target)
            child = next((r for r in get_txt(target) if r.lower().startswith("v=spf1")), "")
            n, lp = spf_lookup_count(child, get_txt, seen, depth + 1)
            count += n
            looped = looped or lp
    return count, looped


def caa_records(lines: List[str]) -> List[Dict[str, str]]:
    """CAA answer lines as {tag, value}; CNAME lines that dig prints
    for an aliased name are skipped."""
    out = []
    for line in lines:
        m = re.match(r'\s*\d+\s+(issue|issuewild|iodef)\s+"([^"]*)"', line, re.I)
        if m:
            out.append({"tag": m.group(1).lower(), "value": m.group(2).split(";")[0].strip()})
    return out


def dnssec_validated(doh: Optional[Dict]) -> Optional[bool]:
    """True or False from a DoH JSON answer's AD flag; None when the
    lookup failed, which is not a "no"."""
    if not isinstance(doh, dict) or doh.get("Status") != 0 or "AD" not in doh:
        return None
    return bool(doh["AD"])


# CAA identifiers for the issuers seen most, from the issuers' own records
# (dig CAA google.com and letsencrypt.org, 2026-11-04).
CAA_IDS = {"let's encrypt": "letsencrypt.org", "google trust services": "pki.goog"}


DNS_NAME_RE = re.compile(r"(?=.{1,253}\.?$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})"
                         r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62}))*\.?")


def _dig(name: str, rtype: str) -> List[str]:
    """dig +short. Names can come from other people's records (an SPF
    include:), so anything that is not a plain DNS name is refused rather
    than passed to dig, where "-f/etc/passwd" would be read as an option."""
    if not shutil.which("dig") or not DNS_NAME_RE.fullmatch(name or ""):
        return []
    try:
        out = subprocess.run(["dig", "+short", "-t", rtype, "-q", name],
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


# Published crawler user agent (Google's crawler overview, as of
# 2026-11-04). One crawler variant keeps the cloaking check at a handful of
# requests per page.
CRAWLER_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SEARCH_REFERER = "https://www.google.com/search?q=site"
CLOAK_VARIANTS = (("crawler", {"User-Agent": CRAWLER_UA}),
                  ("search referrer", {"Referer": SEARCH_REFERER}))


def page_shape(site: str, status: int, location: str, body: str,
               challenged: bool) -> Dict:
    """What one fetch of a page looked like, for the cloaking comparison."""
    own = re.sub(r"^www\.", "", urllib.parse.urlparse(site).netloc.lower())
    hosts = re.findall(r"<a\b[^>]*href=[\"']https?://([^/\"'?#:]+)", body, flags=re.I)
    loc_host = urllib.parse.urlparse(location).netloc.lower() if location else ""
    title = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    return {"status": status, "challenged": challenged,
            "redirect_host": loc_host if loc_host and
            re.sub(r"^www\.", "", loc_host) != own else "",
            "fingerprint": body_fingerprint(body),
            "title": re.sub(r"\s+", " ", unescape(title.group(1))).strip()[:120] if title else "",
            "outbound": sum(1 for h in hosts if re.sub(r"^www\.", "", h.lower()) != own)}


def cloaking_verdict(base: Dict, control: Dict, variant: Dict,
                     control2: Optional[Dict] = None) -> Tuple[str, str]:
    """Compare a crawler or referrer fetch with the browser fetch.

    HIGH: a redirect to another host the browser did not get, or a body
    whose title or outbound link count also differs. MEDIUM: only the
    fingerprint differs on a page whose two browser fetches agreed. A
    challenge or an unanswered fetch is "unmeasured"."""
    if any(x["challenged"] or x["status"] in UNMEASURED_STATUSES
           for x in (base, variant)):
        return "unmeasured", "a challenge page or no answer"
    if variant["redirect_host"] and variant["redirect_host"] != base["redirect_host"]:
        return "HIGH", f"redirected to {variant['redirect_host']}"
    # Edges refuse a crawler user agent from an address that is not the
    # crawler's (osh.co.za and tamingdns.com both 403 it). That is bot
    # protection, not cloaking, and it leaves the crawler's view unseen.
    if variant["status"] >= 400 or base["status"] >= 400:
        return "unmeasured", f"answered HTTP {variant['status']}"
    # Rotating content (a testimonial carousel) can match once by chance,
    # so a body-only difference needs two browser controls that agree; a run
    # from before the second control existed never raises the MEDIUM.
    stable = (control2 is not None and base["fingerprint"] == control["fingerprint"]
              == control2["fingerprint"])
    links_jump = abs(variant["outbound"] - base["outbound"]) >= max(10, base["outbound"] // 2)
    if variant["fingerprint"] != base["fingerprint"]:
        if variant["title"] != base["title"] or links_jump:
            return "HIGH", (f"title {base['title']!r} became {variant['title']!r}"
                            if variant["title"] != base["title"] else
                            f"outbound links went from {base['outbound']} to {variant['outbound']}")
        if stable:
            return "MEDIUM", "the page body differs; title and links match"
    return "", ""


# Hosts whose hidden iframes and scripts are normal: GTM's noscript frame
# is display:none by design, and embeds and challenges come from these.
WELL_KNOWN_HOSTS = ("googletagmanager.com", "google.com", "youtube.com",
                    "youtube-nocookie.com", "vimeo.com", "facebook.com",
                    "doubleclick.net", "cloudflare.com", "gstatic.com")
# Whole words and phrases only: "specialises" contains "cialis", and
# "practice-startup-loans" on a medical practice's blog is not spam.
SPAM_WORDS_RE = re.compile(
    r"\b(?:viagra|cialis|levitra|online[ -]pharmacy|casino|poker|sports[ -]betting|"
    r"payday[ -]loans?|replica[ -](?:watches|bags)|escorts?|essay[ -]writing)\b"
    r"|\u30b3\u30d4\u30fc", re.I)
_HIDDEN_STYLE = (r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*[;\"']"
                 r"|(?:left|top|text-indent)\s*:\s*-\d{3,}px")


def _well_known(host: str) -> bool:
    host = host.lower()
    return any(host == h or host.endswith("." + h) for h in WELL_KNOWN_HOSTS)


def _foreign(url: str, site: str) -> str:
    """The host of a URL when it is another site's, else ""."""
    own = re.sub(r"^www\.", "", urllib.parse.urlparse(site).netloc.lower())
    host = urllib.parse.urlparse(unescape(url)).netloc.lower().split(":")[0]
    return host if host and re.sub(r"^www\.", "", host) != own else ""


_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.I)


def _inline_scripts(body: str) -> List[str]:
    """Bodies of <script> tags with no src, in one linear pass. A regex
    with (.*?)</script> rescans to the end for every unclosed tag. There is
    no cap on the count, so padding cannot push a script out of view, and
    data-src (lazy loading) is not src."""
    out, pos = [], 0
    for m in re.finditer(r"<script\b([^>]*)>", body, re.I):
        if m.start() < pos:
            continue
        close = _SCRIPT_CLOSE.search(body, m.end())
        if not close:
            break
        pos = close.start()
        if not re.search(r"(?:^|\s)src\s*=", m.group(1), re.I):
            out.append(body[m.end():close.start()])
    return out


def signed_in_view(body: str) -> List[str]:
    """Markup WordPress prints only for a signed-in user. A theme's CSS
    mentioning .admin-bar does not count; the element and attributes do."""
    found = []
    if re.search(r"<div\b[^>]*\bid=[\"']wpadminbar[\"']", body, re.I):
        found.append("the admin bar (id=wpadminbar)")
    m = re.search(r"<body\b[^>]*\bclass=[\"']([^\"']*)", body, re.I)
    if m and re.search(r"(?:^|\s)logged-in(?:\s|$)", m.group(1)):
        found.append("body class logged-in")
    if re.search(r"class=[\"'][^\"']*\bpost-edit-link\b", body, re.I):
        found.append("an Edit link (post-edit-link)")
    if re.search(r"wp-admin/post\.php\?post=\d+(?:&|&amp;|&#038;)action=edit", body):
        found.append("a wp-admin edit link")
    return found


def injected_content(body: str, site: str) -> List[Dict[str, str]]:
    """Patterns injected markup leaves in a page. Nothing is fetched.

    Hidden iframes to another site; links to other sites inside a hidden
    element; inline script that decodes a long encoded string (size alone
    is not a signal, page builders emit huge JSON); a meta refresh to
    another site; links to other sites carrying spam words."""
    hits: List[Dict[str, str]] = []
    for tag in re.findall(r"<iframe\b[^>]*>", body, re.I):
        src = re.search(r"\bsrc=[\"']([^\"']+)", tag, re.I)
        host = _foreign(src.group(1), site) if src else ""
        hidden = (re.search(r"\b(?:width|height)=[\"']?0[\"'\s>]", tag, re.I)
                  or re.search(_HIDDEN_STYLE, tag, re.I))
        # WordPress's own oEmbed iframe is hidden until core's script shows
        # it. The class alone could be copied, so core's whole signature is
        # required: that class, sandbox="allow-scripts" and nothing more, and
        # a src that is a post's /embed/ endpoint.
        embed = (re.search(r"\bclass=[\"'](?:[^\"']*\s)?wp-embedded-content(?:\s|[\"'])", tag, re.I)
                 and re.search(r"\bsandbox=[\"']allow-scripts[\"']", tag, re.I)
                 and src and re.search(r"/embed/?(?:#[^\s]*)?$", src.group(1)))
        if host and hidden and not embed and not _well_known(host):
            hits.append({"kind": "hidden iframe", "severity": "HIGH",
                         "detail": f"to {host}"})
    # Quantifiers are bounded: a hostile page must not stall the scan.
    for m in re.finditer(r"<(div|span|p|section)\b[^>]{0,500}?style=[\"'][^\"']{0,500}?(?:"
                         + _HIDDEN_STYLE + r")[^>]{0,500}>(.{0,3000}?)</\1>", body, re.I | re.S):
        for href in re.findall(r"<a\b[^>]*href=[\"']([^\"']+)", m.group(2), re.I):
            host = _foreign(href, site)
            if host and not _well_known(host):
                hits.append({"kind": "link in a hidden element", "severity": "MEDIUM",
                             "detail": f"to {host}"})
    for script in _inline_scripts(body):
        if not re.search(r"\b(?:eval|atob|unescape|fromCharCode)\s*\(", script):
            continue
        literal = re.search(r"[\"']((?:\\x[0-9a-fA-F]{2}){40,}|[A-Za-z0-9+/=]{200,})[\"']", script)
        codes = re.search(r"fromCharCode\s*\(((?:\s*\d+\s*,){40,})", script)
        if not (literal or codes):
            continue
        decoded = ""
        try:
            if literal and literal.group(1).startswith("\\x"):
                decoded = bytes.fromhex(literal.group(1).replace("\\x", "")).decode("latin-1")
            elif literal:
                import base64
                decoded = base64.b64decode(literal.group(1) + "==").decode("latin-1")
            else:
                decoded = "".join(chr(int(n)) for n in codes.group(1).split(",") if n.strip())
        except Exception:
            pass
        url = re.search(r"https?://[\w.-]+", decoded)
        hits.append({"kind": "encoded inline script", "severity": "HIGH" if url else "MEDIUM",
                     "detail": f"decodes to a URL on {urllib.parse.urlparse(url.group(0)).netloc}"
                     if url else "decodes a long encoded string"})
    for tag in re.findall(r"<meta\b[^>]*http-equiv=[\"']?refresh[^>]*>", body, re.I):
        m = re.search(r"url\s*=\s*['\"]?([^'\";>\s]+)", tag, re.I)
        host = _foreign(m.group(1), site) if m else ""
        if host:
            hits.append({"kind": "meta refresh", "severity": "MEDIUM", "detail": f"to {host}"})
    for href, text in re.findall(r"<a\b[^>]*href=[\"']([^\"']+)[^>]*>(.{0,200}?)</a>", body, re.I | re.S):
        host = _foreign(href, site)
        if host and SPAM_WORDS_RE.search(href + " " + re.sub(r"<[^>]+>", "", text)):
            hits.append({"kind": "spam-word link", "severity": "MEDIUM", "detail": f"to {host}"})
    seen, out = set(), []
    for h in hits:
        key = (h["kind"], h["detail"])
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


# Static core files reachable on any recent install; one missing from a
# version's checksum list is skipped. PHP files are where real injections
# live and cannot be read from outside, so a clean result covers these only.
CORE_CHECK_FILES = (
    "wp-includes/js/jquery/jquery.min.js", "wp-includes/js/jquery/jquery-migrate.min.js",
    "wp-includes/js/wp-emoji-release.min.js", "wp-includes/css/dist/block-library/style.min.css",
    "wp-includes/js/dist/hooks.min.js", "wp-includes/js/dist/i18n.min.js",
    "wp-includes/js/wp-util.min.js", "wp-includes/css/dashicons.min.css",
    "wp-includes/css/admin-bar.min.css", "wp-admin/css/login.min.css",
    "wp-includes/js/wp-embed.min.js")


def core_checksum_result(expected: str, status: int, body: str, challenged: bool) -> str:
    """"match", "mismatch" or "unreadable" for one core file. A challenge,
    an HTML page or a non-200 is unreadable, never a mismatch."""
    if status != 200 or challenged or re.match(r"\s*(<!doctype\s+html|<html)", body[:200].lower()):
        return "unreadable"
    return "match" if hashlib.md5(body.encode("utf-8")).hexdigest() == expected else "mismatch"


def _core_checksums(ctx: RunContext, lang: str) -> Dict:
    """Fetch wordpress.org's checksums for the version WordPress itself
    disclosed (not asset URLs) and compare a set of static core files."""
    sources = (ctx.data("headers") or {}).get("core_versions") or {}
    version = next((sources[k] for k in ("generator (cache-busted)", "feed", "opml", "generator")
                    if sources.get(k)), "")
    out: Dict = {"version": version, "locale": "", "files": [], "note": ""}
    if not version:
        out["note"] = "the core version is not disclosed by WordPress itself"
        return out
    locale = (lang or "en-US").replace("-", "_")
    api = "https://api.wordpress.org/core/checksums/1.0/?version={}&locale={}"
    _, _, data = fetch_json(api.format(urllib.parse.quote(version), urllib.parse.quote(locale)))
    if not (isinstance(data, dict) and isinstance(data.get("checksums"), dict)) and locale != "en_US":
        out["note"] = f"no checksums for locale {locale}; en_US used"
        locale = "en_US"
        _, _, data = fetch_json(api.format(urllib.parse.quote(version), locale))
    if not (isinstance(data, dict) and isinstance(data.get("checksums"), dict)):
        out["note"] = f"wordpress.org returned no checksums for {version}"
        return out
    out["locale"] = locale
    for path in CORE_CHECK_FILES:
        expected = data["checksums"].get(path)
        if not expected or shutdown_requested:
            continue
        status, hdrs, body = fetch(f"{ctx.site}/{path}?nc={uuid.uuid4().hex[:8]}")
        out["files"].append({"path": path, "status": status,
                             "result": core_checksum_result(
                                 expected, status, body, edge_identity(hdrs, body, status)["challenged"])})
    return out


SITEMAP_MAX_CHILDREN = 50  # child sitemaps read per run; URLs are counted, never fetched


def sitemap_inventory(site: str) -> Dict:
    """Every URL in the site's sitemaps, counted, with spam-word slugs and
    the busiest lastmod minute. Child sitemaps are read up to a cap."""
    for name in ("/sitemap_index.xml", "/wp-sitemap.xml", "/sitemap.xml"):
        status, _, body = fetch(site + name)
        if status == 200 and "<loc>" in body:
            break
    else:
        return {"read": False}
    docs, children = [body], []
    if "sitemapindex" in body[:2000].lower():
        children = [u for u in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)
                    if _in_scope(u, site)]
        docs = []
        for child in children[:SITEMAP_MAX_CHILDREN]:
            if shutdown_requested:
                break
            s2, _, b2 = fetch(child)
            if s2 == 200:
                docs.append(b2)
    return dict(sitemap_stats(docs), read=True, index=name,
                children=len(children), children_read=min(len(children), SITEMAP_MAX_CHILDREN))


def sitemap_stats(docs: List[str]) -> Dict:
    """Pure part of sitemap_inventory: count, spam slugs, lastmod cluster."""
    urls, minutes = [], {}
    for doc in docs:
        urls += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", doc)
        for stamp in re.findall(r"<lastmod>\s*(\d{4}-\d\d-\d\dT\d\d:\d\d)", doc):
            minutes[stamp] = minutes.get(stamp, 0) + 1
    spam = [u for u in urls if SPAM_WORDS_RE.search(
        urllib.parse.unquote(urllib.parse.urlparse(u).path))][:20]
    busiest = max(minutes.items(), key=lambda kv: kv[1]) if minutes else ("", 0)
    return {"count": len(set(urls)), "spam": spam,
            "lastmod_minute": busiest[0], "lastmod_count": busiest[1]}


def collect_integrity(ctx: RunContext) -> Tuple[str, int, str]:
    """Signs the site may already be compromised, read from outside.

    Cloaking: the homepage and two sitemap pages are each fetched as a
    browser (twice, the second as a control for pages that vary on their
    own), as a search crawler, and as a browser arriving from a search
    result. All GETs, cache-busted, first hop read without following.
    """
    pages = [ctx.site + "/"] + _sitemap_urls(ctx.site)[:2]
    rows: List[Dict] = []
    hits: List[Dict] = []
    hits_done: Dict[str, bool] = {}
    lang_seen: List[str] = []
    for page in dict.fromkeys(pages):
        if shutdown_requested:
            break

        def shape(extra):
            url = f"{page}{'&' if '?' in page else '?'}nc={uuid.uuid4().hex[:8]}"
            nr, nr_hdrs = fetch_no_redirect(url, headers=extra)
            status, hdrs, body = fetch(url, headers=extra)
            if extra is None and status == 200 and not hits_done.get(page):
                hits_done[page] = True
                if page == ctx.site + "/":
                    lang_m = re.search(r"<html\b[^>]*\blang=[\"']([A-Za-z]{2}(?:-[A-Za-z]{2})?)", body)
                    lang_seen.append(lang_m.group(1) if lang_m else "")
                hits.extend(dict(h, page=page) for h in injected_content(body, ctx.site))
                hits.extend({"kind": "signed-in view", "severity": "HIGH",
                             "detail": m, "page": page} for m in signed_in_view(body))
            return page_shape(ctx.site, status if nr == 200 or status in UNMEASURED_STATUSES else nr,
                              nr_hdrs.get("location", "") if 300 <= nr < 400 else "",
                              body, edge_identity(hdrs, body, status)["challenged"])
        base, control, control2 = shape(None), shape(None), shape(None)
        for name, extra in CLOAK_VARIANTS:
            rows.append({"page": page, "variant": name, "base": base, "control": control,
                         "control2": control2, "fetched": shape(extra)})
    platform = ctx.manifest["meta"].get("platform") or {}
    sitemap = sitemap_inventory(ctx.site)
    prev_name, prev = previous_run(ctx.run_dir, "integrity.json", dict)
    if prev_name and (prev.get("sitemap") or {}).get("read"):
        sitemap["previous_run"] = prev_name
        sitemap["previous_count"] = prev["sitemap"]["count"]
    core = (_core_checksums(ctx, lang_seen[0] if lang_seen else "")
            if platform.get("wordpress") else {"note": "not a WordPress site"})
    ctx.write("integrity", {"cloaking": rows, "page_hits": hits, "core": core,
                            "sitemap": sitemap})
    unmeasured = [r for r in rows if cloaking_verdict(
        r["base"], r["control"], r["fetched"], r.get("control2"))[0] == "unmeasured"]
    if rows and len(unmeasured) == len(rows):
        return "partial", 0, "every cloaking comparison met a challenge or no answer"
    notes = []
    if unmeasured:
        notes.append(f"{len(unmeasured)} of {len(rows)} cloaking comparison(s) were not "
                     "measured (a refusal, a challenge or no answer); an edge that "
                     "blocks crawler user agents from addresses that are not the "
                     "crawler's leaves the crawler's view unseen")
    if platform.get("wordpress") and not any(
            f["result"] != "unreadable" for f in core.get("files", [])):
        notes.append("core file checksums not compared: "
                     + (core.get("note") or "no core file could be read"))
    elif core.get("note") and platform.get("wordpress"):
        notes.append("core checksums: " + core["note"])
    return "ok", len(rows), "; ".join(notes)


###############################################################################
# PRIVACY
###############################################################################
# Facts about what the pages do, for the client's lawyer. Never a compliance
# verdict, and nothing above LOW: a tracker is not an attacker. Which act
# applies depends on who the visitors are, not where the server is.
# Tables compiled 2026-11-04 from vendor host names in common use; a vendor
# that moves its host is missed, never misreported.
PRIVACY_REGIMES = (
    "POPIA (South Africa: consent for direct marketing, s69; cross-border "
    "transfers, s72; an Information Officer; a PAIA manual beside it), "
    "GDPR and UK GDPR with the ePrivacy rules and PECR (consent before "
    "non-essential cookies and trackers), CCPA/CPRA (a Do Not Sell or Share "
    "link, Global Privacy Control), and LGPD, PIPEDA, the Australian Privacy "
    "Act, Kenya's DPA, Nigeria's NDPA and Switzerland's revised FADP")

# name, wordpress.org slugs, script host or HTML marker
CONSENT_TOOLS = (
    ("CookieYes", ("cookie-law-info",), ("cdn-cookieyes.com", "cky-consent")),
    ("Complianz", ("complianz-gdpr", "complianz-gdpr-premium"), ("cmplz-",)),
    ("Cookiebot", ("cookiebot",), ("consent.cookiebot.com",)),
    ("Iubenda", ("iubenda-cookie-law-solution",), ("cdn.iubenda.com",)),
    ("OneTrust", (), ("cdn.cookielaw.org", "optanon")),
    ("Termly", (), ("app.termly.io",)),
    ("Osano", (), ("cmp.osano.com",)),
    ("Cookie Notice", ("cookie-notice",), ("cookie-notice-container",)),
    ("GDPR Cookie Compliance", ("gdpr-cookie-compliance",), ("moove_gdpr",)),
    ("Borlabs Cookie", ("borlabs-cookie",), ("borlabscookie",)),
    ("Real Cookie Banner", ("real-cookie-banner",), ("real-cookie-banner",)),
    ("Usercentrics", (), ("usercentrics.eu",)),
    ("Didomi", (), ("privacy-center.org",)),
    ("Quantcast Choice", (), ("cmp.quantcast.com",)),
    ("TrustArc", (), ("consent.trustarc.com",)),
    ("Axeptio", (), ("static.axept.io",)),
    ("Consentmanager", (), ("consentmanager.net",)),
    ("CookieFirst", (), ("cookiefirst.com",)),
)

# vendor, category, patterns (host fragments or inline calls)
TRACKERS = (
    ("Google Analytics", "analytics", ("googletagmanager.com/gtag/js", "google-analytics.com")),
    ("Google Tag Manager", "tag manager", ("googletagmanager.com/gtm.js",)),
    ("Google Ads", "advertising", ("googleadservices.com", "'aw-")),
    ("DoubleClick", "advertising", ("doubleclick.net",)),
    ("Meta Pixel", "advertising", ("connect.facebook.net", "fbq(")),
    ("Hotjar", "session recording", ("static.hotjar.com",)),
    ("Microsoft Clarity", "session recording", ("clarity.ms",)),
    ("LinkedIn Insight", "advertising", ("snap.licdn.com",)),
    ("TikTok pixel", "advertising", ("analytics.tiktok.com",)),
    ("Pinterest tag", "advertising", ("s.pinimg.com/ct",)),
    ("Snap pixel", "advertising", ("sc-static.net",)),
    ("X pixel", "advertising", ("static.ads-twitter.com",)),
    ("HubSpot", "email", ("js.hs-scripts.com", "js.hs-analytics.net")),
    ("Zoho SalesIQ", "chat", ("salesiq.zoho", "salesiq.zohopublic")),
    ("Zoho PageSense", "analytics", ("pagesense.io",)),
    ("Matomo Cloud", "analytics", ("matomo.cloud",)),
    ("Crazy Egg", "session recording", ("crazyegg.com",)),
    ("FullStory", "session recording", ("fullstory.com",)),
    ("Mouseflow", "session recording", ("mouseflow.com",)),
    ("Lucky Orange", "session recording", ("luckyorange",)),
    ("Intercom", "chat", ("widget.intercom.io",)),
    ("Drift", "chat", ("js.driftt.com",)),
    ("Tawk.to", "chat", ("embed.tawk.to",)),
    ("Criteo", "advertising", ("static.criteo.net",)),
    ("AdRoll", "advertising", ("s.adroll.com",)),
    ("Taboola", "advertising", ("cdn.taboola.com",)),
    ("Outbrain", "advertising", ("outbrain.com",)),
    ("Mailchimp", "email", ("chimpstatic.com",)),
    ("Klaviyo", "email", ("static.klaviyo.com",)),
)
_GATE_RE = re.compile(r"type\s*=\s*[\"']text/plain|data-cookieconsent|data-cmp|data-category"
                      r"|data-cookiecategory|data-cmplz|data-borlabs|data-usercentrics", re.I)

# cookie name prefix, purpose, strictly necessary
COOKIE_PURPOSES = (
    ("_ga", "Google Analytics", False), ("_gid", "Google Analytics", False),
    ("_gcl", "Google Ads", False), ("_fbp", "Meta Pixel", False),
    ("_hj", "Hotjar", False), ("_clck", "Microsoft Clarity", False),
    ("_clsk", "Microsoft Clarity", False), ("__hstc", "HubSpot", False),
    ("hubspotutk", "HubSpot", False), ("PHPSESSID", "PHP session", True),
    ("wordpress_test_cookie", "WordPress login check", True),
    ("wp-settings", "WordPress user settings", True),
    ("woocommerce_", "WooCommerce cart", True), ("wp_woocommerce_session", "WooCommerce cart", True),
    ("cf_clearance", "Cloudflare challenge", True), ("__cf_bm", "Cloudflare bot management", True),
    ("cookieyes", "consent record", True), ("cmplz_", "consent record", True),
    ("CookieConsent", "consent record", True), ("wfwaf-", "Wordfence firewall", True),
)

EMBEDS = (
    ("YouTube without privacy mode", r"youtube\.com/embed/", "use youtube-nocookie.com"),
    ("Google Maps embed", r"google\.com/maps/embed", "a static map image linking to Maps"),
    ("Vimeo without dnt=1", r"player\.vimeo\.com/video/(?![^\"']*dnt=1)", "add dnt=1 to the player URL"),
    ("Facebook embed", r"facebook\.com/plugins/", "a link instead of the embed, or load on click"),
    ("Instagram embed", r"instagram\.com/[^\"']*embed", "a link instead of the embed, or load on click"),
    ("X embed", r"platform\.twitter\.com/widgets", "a link instead of the embed, or load on click"),
    ("Google Fonts", r"fonts\.(?:googleapis|gstatic)\.com", "self-host the fonts; most page builders have a switch"),
    ("Gravatar", r"gravatar\.com/avatar", "turn avatars off or use a local avatar plugin"),
    ("Google reCAPTCHA", r"google\.com/recaptcha|gstatic\.com/recaptcha|recaptcha\.net", "Cloudflare Turnstile or hCaptcha"),
)


def consent_tools_seen(body: str, slugs: set) -> List[str]:
    """Consent tools named by slug, script host or HTML marker."""
    low = body.lower()
    found = [name for name, tool_slugs, marks in CONSENT_TOOLS
             if set(tool_slugs) & slugs or any(m in low for m in marks)]
    if "wp-comment-cookies-consent" in low:
        found.append("WordPress comment cookie checkbox")
    return found


def trackers_seen(body: str) -> List[Dict[str, str]]:
    """Each tracker in the markup and how it loads: unconditional, or gated
    by a consent tool (rewritten to type=text/plain or a consent attribute).
    Scripts a tag manager loads at runtime are not in the HTML."""
    out: Dict[str, Dict[str, str]] = {}
    for m in re.finditer(r"<script\b([^>]*)>", body, re.I):
        close = _SCRIPT_CLOSE.search(body, m.end())
        inner = body[m.end():close.start()] if close else ""
        text = (m.group(1) + " " + inner[:20000]).lower()
        gated = bool(_GATE_RE.search(m.group(1)))
        for vendor, category, pats in TRACKERS:
            if any(p in text for p in pats):
                prev = out.get(vendor)
                if not prev or prev["loading"] == "gated by a consent tool":
                    out[vendor] = {"vendor": vendor, "category": category,
                                   "loading": "gated by a consent tool" if gated
                                   else "unconditional script tag"}
    return list(out.values())


def cookie_purpose(name: str) -> Tuple[str, bool]:
    """What a cookie is for, and whether it is strictly necessary."""
    for prefix, purpose, necessary in COOKIE_PURPOSES:
        if name.startswith(prefix):
            return purpose, necessary
    return "unknown", True


def find_policy_link(body: str, site: str) -> str:
    """The privacy policy URL: WordPress's rel="privacy-policy" anchor
    (since 6.2) or an anchor whose text or href names a privacy notice."""
    for tag in re.findall(r"<a\b[^>]*>", body, re.I):
        if re.search(r"rel=[\"'][^\"']*privacy-policy", tag, re.I):
            href = re.search(r"href=[\"']([^\"']+)", tag, re.I)
            if href:
                return urllib.parse.urljoin(site + "/", unescape(href.group(1)))
    words = (r"privacy|privaatheid|privacybeleid|datenschutz|confidentialit|data protection")
    for href, text in re.findall(r"<a\b[^>]*href=[\"']([^\"']+)[^>]*>(.{0,200}?)</a>", body, re.I | re.S):
        if re.search(words, href + " " + re.sub(r"<[^>]+>", "", text), re.I):
            return urllib.parse.urljoin(site + "/", unescape(href))
    return ""


def policy_mentions(text: str, today: str) -> Dict[str, bool]:
    """Presence of the things a privacy notice is usually asked about.
    Words only: a lawyer decides whether what they say is adequate."""
    low = re.sub(r"<[^>]+>", " ", text).lower()
    years = [int(y) for y in re.findall(
        r"(?:updated|effective|revised|last modified)[^.\n]{0,40}?\b(20\d\d)\b", low)]
    return {
        "a contact for privacy requests": bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+|contact form", low)),
        "an Information Officer (POPIA)": "information officer" in low,
        "a data protection officer (GDPR)": "data protection officer" in low or re.search(r"\bdpo\b", low) is not None,
        "a lawful basis or legitimate interest": "lawful basis" in low or "legitimate interest" in low,
        "cross-border transfers": bool(re.search(r"outside (?:of )?(?:south africa|the eea|the european|the uk)|cross-border|transfer", low)),
        "how long data is kept": bool(re.search(r"retain|retention|kept for|keep (?:your|personal)", low)),
        "a cookies section": "cookie" in low,
        "a PAIA manual (South Africa)": "paia" in low or "promotion of access to information" in low,
        "the Information Regulator (South Africa)": "information regulator" in low,
        "a last-updated date within two years": bool(years) and max(years) >= int(today[:4]) - 2,
    }


def forms_consent_rows(body: str, page: str, strict_tld: bool) -> List[Dict[str, str]]:
    """Form markup that collects an email without consent wording, pre-ticks
    a marketing box, or (on a South African or European site) is a Contact
    Form 7 form with no acceptance checkbox. Nothing is submitted."""
    rows, pos = [], 0
    for m in re.finditer(r"<form\b([^>]*)>", body, re.I):
        if m.start() < pos:
            continue
        close = re.compile(r"</form\s*>", re.I).search(body, m.end())
        if not close:
            break
        end = close.start()
        pos = end
        form = body[m.start():end]
        low = re.sub(r"\s+", " ", form.lower())
        if not re.search(r"type=[\"']email|name=[\"'][^\"']*email", low):
            continue
        names = ", ".join(n for n in dict.fromkeys(re.findall(r"name=[\"']([\w\-\[\]]+)", form))
                          if not n.startswith("_"))[:120]
        text = re.sub(r"<[^>]+>", " ", low)
        if re.search(r"<input\b[^>]*type=[\"']checkbox[^>]*\bchecked\b", low) and \
                re.search(r"subscribe|newsletter|marketing|offers|updates", text):
            rows.append({"Page": page, "Issue": "a marketing checkbox is ticked in advance", "Fields": names})
        elif "type=\"checkbox\"" not in low and "type='checkbox'" not in low and \
                not re.search(r"privacy|consent|agree|terms|popia|gdpr", text):
            rows.append({"Page": page, "Issue": "collects an email with no consent checkbox or wording",
                         "Fields": names})
        elif strict_tld and "wpcf7-form" in m.group(1).lower() and "wpcf7-acceptance" not in low:
            rows.append({"Page": page, "Issue": "Contact Form 7 form with no acceptance checkbox",
                         "Fields": names})
    return rows


def embeds_seen(body: str) -> List[str]:
    """Kinds of third-party embed and font that send visitor data on load."""
    return [kind for kind, rx, _ in EMBEDS if re.search(rx, body, re.I)]


def legacy_tags(body: str) -> List[str]:
    """Dead or doubled tracking: Universal Analytics, Google+ widgets, two
    GA4 properties, gtag direct alongside Google Tag Manager."""
    out = []
    if re.search(r"['\"]UA-\d{4,}-\d+['\"]|google-analytics\.com/analytics\.js", body):
        out.append("Universal Analytics (switched off by Google in July 2023)")
    if "apis.google.com/js/plusone.js" in body:
        out.append("a Google+ widget (Google+ closed in 2019)")
    ga4 = set(re.findall(r"\bG-[A-Z0-9]{6,12}\b", body))
    if len(ga4) > 1:
        out.append(f"{len(ga4)} Google Analytics 4 properties on one page")
    if "googletagmanager.com/gtag/js" in body and "googletagmanager.com/gtm.js" in body:
        out.append("gtag loaded directly as well as Google Tag Manager, which can double-count")
    return out


def collect_privacy(ctx: RunContext) -> Tuple[str, int, str]:
    """What the pages do with visitor data, read from the markup.

    The homepage and up to four sitemap pages are read (cache-busted), plus
    the privacy policy page and one RDAP lookup for the site's address.
    JavaScript is not run, so cookies and tags a script adds later are not
    seen, and the report says so.
    """
    slugs = detected_plugins(ctx)
    hostname = urllib.parse.urlparse(ctx.site).hostname or ""
    strict_tld = bool(re.search(r"\.(?:za|eu|uk|de|fr|nl|be|ie|es|it|pt|at|se|dk|fi|no|ch|pl)$", hostname))
    pages = [ctx.site + "/"] + _sitemap_urls(ctx.site)[:4]
    data: Dict = {"pages": [], "consent_tools": [], "trackers": {}, "cookies": {},
                  "forms": [], "embeds": {}, "legacy": [], "policy": {}, "hosting": {}}
    home_body = ""
    for page in dict.fromkeys(pages):
        if shutdown_requested:
            break
        status, hdrs, body = fetch(f"{page}{'&' if '?' in page else '?'}nc={uuid.uuid4().hex[:8]}")
        if status != 200 or edge_identity(hdrs, body, status)["challenged"]:
            continue
        data["pages"].append(page)
        if page == ctx.site + "/":
            home_body = body
        for tool in consent_tools_seen(body, slugs):
            if tool not in data["consent_tools"]:
                data["consent_tools"].append(tool)
        for t in trackers_seen(body):
            row = data["trackers"].setdefault(t["vendor"], dict(t, pages=0))
            row["pages"] += 1
            if t["loading"] == "unconditional script tag":
                row["loading"] = t["loading"]
        for chunk in hdrs.get("set-cookie", "").split("\n"):
            if "=" in chunk:
                data["cookies"].setdefault(chunk.split("=", 1)[0].strip(), page)
        data["forms"] += forms_consent_rows(body, page, strict_tld)
        for kind in embeds_seen(body):
            data["embeds"][kind] = data["embeds"].get(kind, 0) + 1
        for tag in legacy_tags(body):
            if tag not in data["legacy"]:
                data["legacy"].append(tag)
    if not data["pages"]:
        ctx.write("privacy", data)
        return "error", 0, "no page could be read without a challenge"
    data["gtm"] = "Google Tag Manager" in data["trackers"]
    # The footer, where the policy link lives, is past MAX_BODY_BYTES on a
    # large homepage (one client site: 400 KB), so read it in full here.
    st, _, full = fetch(ctx.site + "/", max_bytes=4_000_000)
    if st == 200:
        home_body = full
    data["do_not_sell"] = bool(re.search(r"do not sell", home_body, re.I))
    policy_url = find_policy_link(home_body, ctx.site)
    if not policy_url:
        # WordPress's default policy page, unlinked from the homepage.
        nr, _ = fetch_no_redirect(ctx.site + "/privacy-policy/")
        st, _, pg = fetch(ctx.site + "/privacy-policy/") if nr == 200 else (0, {}, "")
        title = re.search(r"<title[^>]*>(.*?)</title>", pg, re.I | re.S)
        if st == 200 and title and re.search(r"privacy", title.group(1), re.I):
            policy_url = ctx.site + "/privacy-policy/"
            data["policy_unlinked"] = True
    if policy_url and _in_scope(policy_url, ctx.site):
        st, _, pol = fetch(policy_url)
        data["policy"] = {"url": policy_url, "status": st,
                          "mentions": policy_mentions(pol, datetime.now().strftime("%Y-%m-%d"))
                          if st == 200 else {}}
    elif policy_url:
        data["policy"] = {"url": policy_url, "status": 0, "mentions": {},
                          "note": "the policy is on another site and was not fetched"}
    try:
        ip = socket.gethostbyname(hostname)
        _, _, rdap = fetch_json(f"https://rdap.org/ip/{ip}")
        if isinstance(rdap, dict):
            data["hosting"] = {"ip": ip, "name": str(rdap.get("name") or ""),
                               "country": str(rdap.get("country") or "")}
    except OSError:
        pass
    ctx.write("privacy", data)
    return "ok", len(data["pages"]), ""


def check_privacy(ctx: RunContext) -> List[Finding]:
    data = ctx.data("privacy")
    if not data or not data.get("pages"):
        return []
    findings = []
    tools = data.get("consent_tools", [])
    findings.append(Finding(
        "privacy-consent-tool", "INFO",
        "Consent tool: " + (", ".join(tools) if tools else "none visible"),
        ("A consent tool is what asks visitors before non-essential cookies "
         "and trackers run. " if tools else
         "No consent tool was seen in the markup of the pages read. One could "
         "still load from inside a tag manager. ")
        + "The acts that may apply, depending on who the visitors are: "
        + PRIVACY_REGIMES + ". This section reports what the pages do; it is "
        "not a compliance verdict, and a lawyer decides what each item means.",
        "If visitors include people in South Africa, the EU or the UK and the "
        "site uses analytics or advertising tags, use a consent tool in a mode "
        "that blocks scripts until consent is given.",
        [{"Consent tool": t} for t in tools] or [{"Consent tool": "none visible"}],
        "privacy.json", len(tools)))
    trackers = list(data.get("trackers", {}).values())
    if trackers:
        rows = [{"Tracker": t["vendor"], "Category": t["category"], "How it loads": t["loading"],
                 "Pages": t["pages"]} for t in trackers]
        if data.get("gtm"):
            rows.append({"Tracker": "anything inside Google Tag Manager", "Category": "unknown",
                         "How it loads": "inside a tag manager, so not visible here", "Pages": "-"})
        ungated = [t for t in trackers if t["loading"] == "unconditional script tag"
                   and t["category"] != "tag manager"]
        findings.append(Finding(
            "privacy-trackers", "LOW" if ungated and not tools else "INFO",
            f"{len(trackers)} tracker(s) in the page markup"
            + (f", {len(ungated)} loading without a consent gate" if ungated else ""),
            "Under GDPR, UK GDPR and the ePrivacy rules these need consent "
            "before they run, and under POPIA section 69 the advertising ones "
            "need consent for direct marketing. A banner that appears after "
            "the tags have already fired is the most common failure and the "
            "easiest to see from outside. Session recording and advertising "
            "are the categories regulators act on. JavaScript was not run, so "
            "tags a tag manager adds at runtime are not listed.",
            "Use the consent tool's script-blocking mode, or Google Consent Mode "
            "for the Google tags, and move tags into the tag manager behind "
            "consent triggers.",
            rows, "privacy.json", len(trackers)))
    cookies = [(name, *cookie_purpose(name), page) for name, page in data.get("cookies", {}).items()]
    extra = [c for c in cookies if not c[2]]
    if extra:
        findings.append(Finding(
            "privacy-cookies", "LOW",
            f"{len(extra)} non-essential cookie(s) set by the server before any interaction",
            "These were set on the first anonymous request, before a visitor "
            "could agree to anything. Cookies set by JavaScript are not "
            "visible here and may add to this list.",
            "Set these only after consent, through the consent tool.",
            [{"Cookie": n, "Purpose": p, "First seen on": pg} for n, p, _, pg in extra],
            "privacy.json", len(extra)))
    policy = data.get("policy") or {}
    mentions = policy.get("mentions") or {}
    if mentions:
        findings.append(Finding(
            "privacy-policy", "INFO",
            "What the privacy policy mentions"
            + (" (the page exists but is not linked from the homepage)" if data.get("policy_unlinked") else ""),
            "These are presence checks on words in the policy page, not a "
            "review of what it says. The rows marked no are the questions to "
            "put to whoever drafted it."
            + (" The policy was found at /privacy-policy/ but nothing on the "
               "homepage links to it, so visitors are unlikely to find it."
               if data.get("policy_unlinked") else "")
            + ("" if data.get("do_not_sell") else
               " No \"Do Not Sell or Share\" link was seen on the homepage, which "
               "CCPA/CPRA expects where it applies."),
            "Take the table to the site's lawyer or privacy adviser.",
            [{"Item": k, "Mentioned": "yes" if v else "no"} for k, v in mentions.items()],
            "privacy.json", len(mentions)))
    elif not policy.get("url"):
        findings.append(Finding(
            "privacy-policy-missing", "LOW",
            "No privacy policy is linked from the homepage",
            "No link marked rel=privacy-policy and no link whose text or "
            "address names a privacy notice was found on the homepage, and "
            "WordPress's default /privacy-policy/ page does not exist. A "
            "policy may exist elsewhere on the site; visitors need to be able "
            "to find it. Most data protection acts require one where personal "
            "data is collected, including through a contact form or analytics.",
            "Publish a privacy notice and link it from every page, usually the "
            "footer; in WordPress, set it under Settings > Privacy.",
            [{"Homepage": ctx.data("privacy").get("pages", [""])[0]}], "privacy.json", 1))
    forms = data.get("forms", [])
    if forms:
        findings.append(Finding(
            "privacy-forms", "LOW",
            f"{len(forms)} form(s) collect personal data without clear consent",
            "Pre-ticked consent is invalid under GDPR, and POPIA section 69 "
            "wants opt-in for direct marketing. A form that takes an email with "
            "no consent wording leaves the purpose unstated. Read from the "
            "markup; nothing was submitted.",
            "Add an unticked consent checkbox naming the purpose, linked to the "
            "privacy policy; Contact Form 7 has an acceptance field for this.",
            forms, "privacy.json", len(forms)))
    embeds = data.get("embeds", {})
    if embeds:
        fix = {k: f for k, _, f in EMBEDS}
        findings.append(Finding(
            "privacy-embeds", "INFO",
            f"{len(embeds)} kind(s) of third-party embed or font send visitor data on load",
            "Each of these sends the visitor's address to another company as "
            "the page loads. A Munich court found in 2022 that loading Google "
            "Fonts from Google breached GDPR for that reason.",
            "Use the replacement listed for each.",
            [{"Embed": k, "Pages": n, "Replacement": fix.get(k, "")} for k, n in embeds.items()],
            "privacy.json", len(embeds)))
    host = data.get("hosting") or {}
    if host.get("country"):
        findings.append(Finding(
            "privacy-hosting", "INFO",
            f"The site is served from an address allocated to {host.get('name') or 'an unnamed network'} "
            f"in {host['country']}",
            "POPIA section 72 and GDPR Chapter V both regulate transfers of "
            "personal data across borders. This is the address visitors connect "
            "to, from its registry allocation; a CDN in front makes the origin "
            "server's location a separate question.",
            "Confirm with the host where the origin server and its backups are.",
            [{"Address": host.get("ip", ""), "Allocated to": host.get("name", ""),
              "Country": host["country"]}], "privacy.json", 1))
    if data.get("legacy"):
        findings.append(Finding(
            "privacy-legacy-tags", "INFO",
            f"{len(data['legacy'])} dead or doubled tracking tag(s)",
            "Dead tags send data nowhere useful, and doubled ones send it twice.",
            "Remove the dead tags and keep one analytics install.",
            [{"Tag": t} for t in data["legacy"]], "privacy.json", len(data["legacy"])))
    return findings


# The module registry. `key` names the JSON file and the manifest entry.
MODULES: List[Dict] = [
    {"key": "calibration", "title": "Missing-path calibration",
     "fn": collect_calibration, "required": True,
     "about": "Learns how the site answers a path that cannot exist, and "
              "proves the result still lets a real file through."},
    {"key": "headers", "title": "Security headers and site identity",
     "fn": collect_headers, "required": True,
     "about": "Reads the homepage for security response headers, what its "
              "Content-Security-Policy actually restricts, version "
              "disclosure, cookie flags and the theme."},
    {"key": "rest", "title": "REST API index",
     "fn": collect_rest, "required": False,
     "about": "Reads /wp-json/ for the plugin inventory and any route that "
              "accepts a write method. No route is called."},
    {"key": "users", "title": "Author and user disclosure",
     "fn": collect_users, "required": False,
     "about": "Reads the routes that publish account names: the REST users "
              "endpoint, ?author=1 to 10, the users sitemap, an SEO plugin's "
              "author sitemap, homepage author links, the feed and oEmbed."},
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
              "page in the sitemap, not just one, and reads the same pages and "
              "the site's own scripts for third-party resources without "
              "integrity, credential-shaped strings and PHP errors."},
    {"key": "vulns", "title": "Known vulnerabilities and currency",
     "fn": collect_vulns, "required": False,
     "about": "Looks each plugin, theme and core version up against "
              "api.wordpress.org for currency and withdrawal, and "
              "wpvulnerability.net for published CVEs. Where a component's "
              "asset URLs carry several versions the highest is the one "
              "measured, because the lower ones belong to individual files. "
              "Components with no record are reported as unchecked, never "
              "as clean."},
    # The path sweep is the one burst in a run (fifty-odd paths, two requests
    # each) and it is what trips rate limiters. It runs after the modules
    # whose data the vulnerability lookups depend on, so a WAF that starts
    # refusing halfway through costs path coverage rather than the inventory.
    {"key": "paths", "title": "Readable paths",
     "fn": collect_paths, "required": False,
     "about": "Requests backup archives, database dumps, credential files, "
              "logs, developer artefacts, form-upload directories and "
              "directory listings that should not be readable, plus backup "
              "names derived from the domain, the paths robots.txt hides, "
              "log and data files of plugins the site advertises, and a "
              "core file that shows whether PHP prints errors to visitors."},
    {"key": "transport", "title": "Transport and TLS",
     "fn": collect_transport, "required": False,
     "about": "HTTP-to-HTTPS behaviour, the certificate, whether TLS 1.0 and "
              "1.1 are still accepted, CORS, XML-RPC, GraphQL, "
              "open account registration and security.txt."},
    {"key": "dns", "title": "Mail spoofing and DNS posture",
     "fn": collect_dns, "required": False,
     "about": "SPF, DMARC and MX for the website domain, which is the half "
              "nobody owns when it differs from the mail domain. The MX "
              "records are read to tell a domain that sends no mail from one "
              "whose SPF record forgot its senders. The site's host name is "
              "checked for a CNAME to a WordPress.com site that no longer "
              "exists, for a CAA record limiting who may issue its "
              "certificates, and for DNSSEC validation."},
    {"key": "integrity", "title": "Signs of compromise",
     "fn": collect_integrity, "required": False,
     "about": "Fetches the homepage and two sitemap pages as a browser, as a "
              "search crawler and from a search result, and compares them: a "
              "compromised site often shows crawlers or search visitors "
              "something else. Reads every page fetched for injected markup "
              "and for a signed-in user's view served from cache, and "
              "compares static core files with wordpress.org's checksums. "
              "Counts sitemap URLs against the previous run and looks for "
              "spam words in them."},
    {"key": "privacy", "title": "Privacy: trackers, cookies and notices",
     "fn": collect_privacy, "required": False,
     "about": "Reads the homepage, four sitemap pages and the privacy policy "
              "for consent tools, trackers and how they load, cookies set "
              "before consent, what the policy mentions, consent wording on "
              "forms, third-party embeds and fonts, dead tags, and where the "
              "site's address is allocated. Facts for a lawyer, never a "
              "compliance verdict."},
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
    # A module left out with --skip or --only never ran, and a Coverage table
    # that does not list it reads as though it did. Fifteen reports produced
    # with --skip media,assets said nothing about media or assets.
    chosen = {m["key"] for m in modules}
    only = {k.strip() for k in (ctx.args.only or "").split(",") if k.strip()}
    # A module that already ran keeps its status: a re-collect with --only
    # once relabelled six "partial" path probes as never run.
    for mod in MODULES:
        if mod["key"] not in chosen and not ctx.module_status(mod["key"]):
            ctx.set_module(mod["key"], "skipped", 0,
                           "left out of this run with --skip or --only")
    for mod in modules:
        key = mod["key"]
        # "ok" is only trusted with a readable file behind it, and documents
        # re-runs when this invocation names a --url it has not checked.
        new_urls = (key == "documents" and set(ctx.args.url or [])
                    - set(ctx.manifest["meta"].get("extra_urls", [])))
        # --force redoes what --only names; a required module it does not
        # name is redone only when it is not already ok.
        forced = ctx.args.force and (not only or key in only)
        if (ctx.module_status(key) == "ok" and not forced
                and ctx.data(key) is not None and not new_urls):
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
        # Kept whole; _evidence_table() caps what the page shows.
        # findings.json promised every row and carried twelve.
        self.evidence = list(evidence)
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
    exec_hits: List[Dict] = []
    for row in rows:
        if not row["exposed"]:
            continue
        if row.get("rule") == "exec-config":
            exec_hits.append(row)
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

    if exec_hits:
        # MEDIUM, not CRITICAL: nothing was read, because PHP ran the file.
        # Not LOW either: the copy holds credentials one server change away
        # from being served, which outranks version disclosure.
        findings.append(Finding(
            "paths-config-copy", "MEDIUM",
            f"{len(exec_hits)} old copy(ies) of the configuration file the "
            "server runs",
            "The server answered these names with HTTP 200 and an empty page, "
            "while a made-up .php name on the same site answered differently. "
            "That is what a copy of wp-config.php does when PHP runs it: it "
            "holds the database password and the site's secret keys and "
            "prints nothing. Nothing was read. The contents leak if PHP ever "
            "stops handling the file.",
            "Delete each copy from the server. If the database password in "
            "it is still the live one, change it and the salts as well. "
            "wp core verify-checksums lists stray files like these as \"File "
            "should not exist\".",
            [{"Path": h["path"], "Status": h["status"], "Bytes": h["bytes"],
              "What it gives away": h["why"]} for h in exec_hits],
            "paths.json", len(exec_hits)))

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
    csp = data.get("csp")  # absent from runs before 1.13.0
    by_sev = {}
    for header, severity, cost in SECURITY_HEADERS:
        if header in missing:
            if header == "content-security-policy" and data.get("csp_report_only"):
                cost += (" A Content-Security-Policy-Report-Only header is sent; "
                         "it reports violations and blocks nothing.")
            by_sev.setdefault(severity, []).append(
                {"Header": header, "Without it": cost})
        elif (header == "content-security-policy" and csp
              and not csp["has_script_source"]):
            by_sev.setdefault(severity, []).append(
                {"Header": header, "Without it":
                 "the policy sent contains no script-src or default-src, so it "
                 "restricts nothing; it is listed here with the headers that "
                 "are absent."})
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

    themes = data.get("theme") or []
    if len(themes) == 1 and data.get("custom_css"):
        slug = themes[0]
        info = (data.get("theme_info") or {}).get(slug) or {}
        wporg = (((ctx.data("vulns") or {}).get("themes") or {}).get(slug) or {}).get("wporg") or {}
        if info.get("status") == 200 and not info.get("parent") and wporg.get("found"):
            findings.append(Finding(
                "hygiene-child-theme", "INFO",
                f"The site customises {info.get('name') or slug} directly, with no child theme",
                "The active theme is the wordpress.org theme itself (its "
                "style.css names no parent), and the page loads styling written "
                "into it. Changes made inside a theme are lost on its next "
                "update, and a theme that is never updated to protect them is a "
                "theme that never gets security fixes.",
                "Move the customisations into a child theme, or into Appearance > "
                "Customize > Additional CSS, then keep the parent theme updated.",
                [{"Theme": slug, "Evidence": data["custom_css"]}], "headers.json", 1))

    audited = (urllib.parse.urlparse(getattr(ctx, "site", "") or "").hostname or "").lower()
    off = {k: v for k, v in (data.get("canonical_hosts") or {}).items()
           if v and audited and re.sub(r"^www\.", "", v) != re.sub(r"^www\.", "", audited)}
    if off:
        findings.append(Finding(
            "headers-canonical-host", "LOW",
            "The homepage names another host as its canonical address",
            "The canonical link and og:url tell search engines and social "
            "sites which address is the real one. Pointing them at another "
            "host sends this site's ranking and shares there, which is a "
            "leftover from a migration or staging copy, or an injection.",
            "Set the site address in Settings > General and the SEO plugin's "
            "canonical settings to this host, then clear the cache.",
            [{"Tag": k, "Host": v} for k, v in off.items()], "headers.json", len(off)))

    hsts_value = (data.get("headers") or {}).get("strict-transport-security", "")
    if hsts_value:
        hs = hsts_assessment(hsts_value)
        gaps = []
        if hs["max_age"] is None or hs["max_age"] < 180 * 86400:
            gaps.append({"Directive": "max-age",
                         "State": f"{hs['max_age']} seconds" if hs["max_age"] is not None else "unreadable",
                         "What it costs": "browsers forget the rule quickly; the preload "
                                          "list needs at least one year"})
        if not hs["include_subdomains"]:
            gaps.append({"Directive": "includeSubDomains", "State": "absent",
                         "What it costs": "subdomains can still be reached over plain HTTP "
                                          "first, which also leaves cookies for the parent "
                                          "domain exposed"})
        if gaps:
            findings.append(Finding(
                "headers-hsts-weak", "LOW",
                "Strict-Transport-Security is sent but weaker than it could be",
                "The header tells browsers to use HTTPS only. A short max-age "
                "or no includeSubDomains leaves part of that protection off.",
                "Raise max-age in steps towards one year (31536000). Add "
                "includeSubDomains only after confirming every subdomain serves "
                "HTTPS. Submit to the preload list last, at hstspreload.org.",
                gaps, "headers.json", len(gaps)))

    if csp and csp["present"]:
        weak = []
        if not csp["object_src_none"]:
            weak.append(("object-src", "not 'none'",
                         "plugin-content injection (object and embed tags) "
                         "stays open."))
        if not csp["has_base_uri"]:
            weak.append(("base-uri", "absent",
                         "an injected <base> tag can redirect every relative "
                         "URL on the page, scripts included."))
        if not csp["has_frame_ancestors"]:
            weak.append(("frame-ancestors",
                         "absent" + (" (a meta tag cannot carry it)"
                                     if csp["from_meta"] else ""),
                         "clickjacking protection is left to the legacy "
                         "X-Frame-Options header."))
        if csp["unsafe_inline"]:
            weak.append(("script-src", "allows 'unsafe-inline'",
                         "an injected inline script still runs."))
        if csp["unsafe_eval"]:
            weak.append(("script-src", "allows 'unsafe-eval'",
                         "script built from strings at runtime still runs."))
        if csp["wildcard"]:
            weak.append(("script-src", "allows any host",
                         "scripts load from any site, so the policy does not "
                         "limit where an attacker's script comes from."))
        if weak:
            findings.append(Finding(
                "headers-csp-weak", "LOW",
                f"The Content-Security-Policy leaves {len(weak)} gap(s) open",
                "A Content-Security-Policy is sent, but parts of it restrict "
                "nothing. It is rated low because the gaps matter only once "
                "an attacker can already inject markup; the risk is false "
                "comfort, a policy that reads as protection and is not.",
                "frame-ancestors 'self', object-src 'none' and base-uri 'self' "
                "can be added today with no risk of breaking the page. "
                "script-src is the directive worth the effort; a WordPress "
                "site with a page builder almost always needs 'unsafe-inline' "
                "for styles, which is a separate directive. Add the policy at "
                "the CDN or web server, the same as the other headers.",
                [{"Directive": d, "State": st, "What it costs": c}
                 for d, st, c in weak], "headers.json", len(weak)))

    leaky = data.get("leaky", {})
    # A value with no number in it names a product, not a version, and the
    # finding below is about versions. "x-powered-by: WP Engine" and
    # "x-redirect-by: WordPress" were both reported as version disclosure.
    # A version looks like 8.3.31 or 1.24.0. Any digit was too loose: a
    # Kubernetes pod name in the Server header was reported as a version.
    interesting = {k: v for k, v in leaky.items()
                   if re.search(r"\d+\.\d+", v or "")}
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
        # The generator list is read from the first homepage fetch, which a
        # CDN can serve from cache. The cache-busted read and the feed are
        # written by WordPress on the spot, so they win the headline; a
        # report that leads with a stale number gets its other numbers
        # doubted too.
        sources = data.get("core_versions") or {}
        live = next((sources[k] for k in ("generator (cache-busted)", "feed", "opml")
                     if sources.get(k)), "")
        cached = sources.get("generator", "")
        stale = bool(live and cached and live != cached)
        headline = f"WordPress {live}" if live else wp_version
        rows = [{"Generator": g} for g in generators]
        if stale:
            rows.insert(0, {"Generator": f"WordPress {live} (read live, "
                                         "cache defeated)"})
        findings.append(Finding(
            "headers-generator", "INFO",
            f"The site publishes its WordPress version: {headline}",
            "WordPress adds a generator meta tag to every page unless it is "
            "removed. It saves an attacker the trouble of working out which "
            "core version they are looking at."
            + (f" The cached homepage still says {cached}; the version above "
               "was read with the cache defeated and is what the site is "
               "serving now. The gap is a cache that has not caught up, not "
               "two versions of WordPress."
               if stale else ""),
            "Remove it with a one-line filter "
            "(remove_action('wp_head', 'wp_generator')). Keeping the site "
            "patched matters far more than hiding the number.",
            rows, "headers.json"))
    return findings


# Account names that are host defaults or placeholders. A managed host's
# maintenance account is normal; an "admin" or "test" nobody owns is not.
# From the plan's list (2026-11-03), matched whole and case-insensitively.
SUSPICIOUS_ACCOUNT_NAMES = {
    "admin", "administrator", "test", "demo", "support", "user", "wpengine",
    "kinsta", "siteground", "hostinger", "flywheel", "dev", "backup", "temp"}


def suspicious_accounts(data: Dict, headers: Dict) -> List[Dict[str, str]]:
    """Rows for every published slug or display name on the list, once each."""
    seen: List[Tuple[str, str]] = []
    for u in data.get("rest", []):
        for value in (u.get("slug", ""), u.get("name", "")):
            seen.append(("REST users endpoint", value))
    seen += [(f"?author={r['n']}", r["slug"]) for r in data.get("author_redirect", [])]
    seen += [("users sitemap", u.rstrip("/").rsplit("/", 1)[-1])
             for u in data.get("sitemap", [])]
    seen += [("author-sitemap.xml", x) for x in data.get("yoast_sitemap", [])]
    seen += [("homepage author link", x) for x in (headers or {}).get("author_links", [])]
    seen += [("feed dc:creator", x) for x in data.get("feed_creators", [])]
    if data.get("oembed"):
        seen.append(("oEmbed author_name", data["oembed"]))
    rows, done = [], set()
    for route, value in seen:
        key = (value or "").strip().lower()
        if key in SUSPICIOUS_ACCOUNT_NAMES and key not in done:
            done.add(key)
            rows.append({"Name": value, "Where it was seen": route})
    return rows


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
        # X-WP-Total is the library size; the request read one page of 100.
        # "All 100 accounts" on a site with 272 was wrong in both words.
        try:
            total = int(data.get("rest_total") or 0)
        except ValueError:
            total = 0
        total = max(total, len(rest))
        findings.append(Finding(
            "users-rest", "HIGH",
            f"The REST API hands out {total} account(s) to anyone"
            + (f" (the first {len(rest)} were read)" if total > len(rest) else ""),
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
            evidence, "users.json", total))
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
    # A slug already listed by an earlier route is not repeated.
    listed = {r["slug"] for r in redirects} | {
        u.rstrip("/").rsplit("/", 1)[-1] for u in sitemap}
    extra = []
    for route, slugs in (("author-sitemap.xml", data.get("yoast_sitemap", [])),
                         ("homepage author link",
                          (ctx.data("headers") or {}).get("author_links", []))):
        for slug in slugs:
            if slug not in listed:
                listed.add(slug)
                extra.append({"Route": route, "Author slug": slug})
    if redirects or sitemap or extra:
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
        if any(e["Route"] == "author-sitemap.xml" for e in extra):
            routes.append("the SEO plugin's author sitemap")
        if any(e["Route"] == "homepage author link" for e in extra):
            routes.append("author links on the homepage")
        evidence = [{"Route": f"?author={r['n']}", "Author slug": r["slug"]}
                    for r in redirects]
        evidence += [{"Route": "wp-sitemap-users-1.xml",
                      "Author slug": u.rstrip("/").rsplit("/", 1)[-1]}
                     for u in sitemap]
        evidence += extra
        findings.append(Finding(
            "users-author", "MEDIUM",
            f"Author slugs are published through "
            f"{', '.join(routes[:-1]) + ' and ' + routes[-1] if len(routes) > 1 else routes[0]}",
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

    odd = suspicious_accounts(data, ctx.data("headers") or {})
    if odd:
        findings.append(Finding(
            "users-suspicious", "LOW",
            f"Names worth a look: {len(odd)} published account name(s) are "
            "defaults or placeholders",
            "These names are what hosts use for maintenance accounts and what "
            "people use for test accounts. On managed hosting a host's own "
            "account is normal. An admin, test or demo account that nobody "
            "can say they own is how an attacker's account hides, and an "
            "old test account is often the one with a weak password.",
            "Ask who owns each account. Remove any that nobody owns, and "
            "check the remaining ones have strong passwords and two-factor "
            "authentication.",
            odd, "users.json", len(odd)))

    names = ([{"Route": "oEmbed author_name", "Display name": data["oembed"]}]
             if data.get("oembed") else [])
    names += [{"Route": "feed dc:creator", "Display name": n}
              for n in data.get("feed_creators", [])]
    if names:
        findings.append(Finding(
            "users-names", "LOW",
            "Display names are published by "
            + " and ".join(dict.fromkeys(
                "the feed" if r["Route"].startswith("feed") else "oEmbed"
                for r in names)),
            "The oEmbed endpoint returns author_name for any page, and the "
            "feed names each post's author in dc:creator. Both give a real "
            "name rather than a slug, which is a smaller disclosure but "
            "survives closing the other routes.",
            "Filter oembed_response_data to drop author_name if the site "
            "does not need oEmbed previews elsewhere. The feed's author "
            "names come from the_author; a filter on the_author_rss, or "
            "turning feeds off if nobody subscribes, removes them.",
            names, "users.json", len(names)))
    return findings


def check_media(ctx: RunContext) -> List[Finding]:
    data = ctx.data("media")
    if not data:
        return []
    findings = []
    ap = data.get("attachment_page") or {}
    if ap.get("enabled"):
        findings.append(Finding(
            "hygiene-attachment-pages", "LOW",
            "Every upload has its own indexable page",
            "WordPress 6.4 stopped creating attachment pages on new sites; "
            "older sites still have them. Each uploaded file, documents "
            "included, gets an HTML page search engines can index, which "
            "makes a file meant to be shared by link findable by search.",
            "Turn attachment pages off (the wp_attachment_pages_enabled option, "
            "or the SEO plugin's setting to redirect attachment URLs to the file).",
            [{"Attachment page": ap["link"], "Status": ap["status"]}], "media.json", 1))
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
    # A PDF URL that redirects to the homepage ends on a 200 HTML page.
    live = [r for r in rows if r["status"] == 200
            and not (r.get("content_type", "").startswith("text/html")
                     and not urllib.parse.urlparse(r["url"]).path.endswith(
                         (".html", ".htm")))]

    orphans = [r for r in live if r["in_library"] is False]
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
              "Flagged words": ", ".join(r["sensitive"]) or "-",
              "Found on": ("run " + r["carried_from"]) if r.get("carried_from")
              else "this run"}
             for r in orphans], "documents.json", len(orphans)))

    unknown = [r for r in live if r["in_library"] is None]
    if unknown:
        findings.append(Finding(
            "docs-library-unknown", "INFO",
            f"{len(unknown)} downloadable document(s) could not be compared "
            "against the media library",
            "The media walk did not complete, so absence from it would not "
            "show that a file is missing from the library. These may be "
            "orphans or may be listed normally; this run cannot tell.",
            "Re-run once the media module completes, or compare these URLs "
            "against the Media screen by hand.",
            [{"URL": r["url"], "Bytes": r["bytes"]} for r in unknown],
            "documents.json", len(unknown)))

    sensitive = [r for r in live if r["sensitive"]]
    hidden_sensitive = [r for r in sensitive if r["in_library"] is False]
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
              "In library": {True: "yes", False: "NO"}.get(
                  r["in_library"], "not known (media walk incomplete)"),
              "Bytes": r["bytes"]} for r in sensitive],
            "documents.json", len(sensitive)))

    removed = [r for r in rows if r.get("removed_since")]
    if removed:
        findings.append(Finding(
            "docs-removed", "INFO",
            f"{len(removed)} document(s) found on an earlier run no longer "
            "resolve",
            "Each of these answered 200 on the earlier run named beside it "
            "and now answers 404 or 410. The file no longer resolves "
            "publicly; that is not proof it was deleted from disk.",
            "Nothing to do if the removal was intended. If a search engine "
            "still lists the URL, a removal request in Google Search Console "
            "clears it faster.",
            [{"URL": r["url"], "Status now": r["status"],
              "Last seen on run": r["removed_since"]} for r in removed],
            "documents.json", len(removed)))

    dead = [r for r in rows if r["status"] in (404, 410)
            and not r.get("removed_since") and not r.get("carried_from")]
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


def discussion_rows(disc: Dict, xmlrpc_on: bool, today: str) -> List[Dict[str, str]]:
    """What the discussion settings expose, from a post sample and the newest
    comments: comments open on posts over a year old, pingbacks open while
    XML-RPC answers, and recent comments that look like spam."""
    rows = []
    cutoff = f"{int(today[:4]) - 1}{today[4:10]}"
    old_open = [p for p in disc.get("posts", [])
                if p.get("comment_status") == "open" and (p.get("date") or "")[:10] < cutoff]
    if old_open:
        rows.append({"Signal": "comments open on posts over a year old",
                     "Detail": f"{len(old_open)} of {len(disc['posts'])} sampled posts"})
    if xmlrpc_on and any(p.get("ping_status") == "open" for p in disc.get("posts", [])):
        rows.append({"Signal": "pingbacks open while XML-RPC answers",
                     "Detail": "the pingback pair used to bounce traffic at other sites"})
    spam = [c for c in disc.get("comments", [])
            if c["links"] >= 2 or re.match(r"(?i)(?:https?://|www\.)|\S+\.(?:com|net|ru|xyz)$",
                                             c["author_name"])]
    if spam:
        rows.append({"Signal": "recent comments that look like spam",
                     "Detail": f"{len(spam)} of the newest {len(disc['comments'])}"})
    return rows


def check_rest(ctx: RunContext) -> List[Finding]:
    data = ctx.data("rest")
    if not data:
        return []
    findings = []
    disc = data.get("discussion") or {}
    if disc.get("posts_status") == 200:
        xmlrpc_on = bool(((ctx.data("transport") or {}).get("xmlrpc") or {}).get("answering"))
        rows = discussion_rows(disc, xmlrpc_on, datetime.now().strftime("%Y-%m-%d"))
        if rows:
            findings.append(Finding(
                "hygiene-comments", "LOW",
                "Discussion settings leave an opening for spam",
                "Comments open on old posts attract spam bots, pingbacks with "
                "XML-RPC let the site be used to bounce traffic at others, and "
                "spam in recent comments means moderation is not catching it. "
                "Read from a sample of posts and the newest comments.",
                "In Settings > Discussion, close comments on posts older than a "
                "few weeks, turn off pingbacks and trackbacks, and keep "
                "moderation on for first-time commenters.",
                rows, "rest.json", len(rows)))
        elif disc.get("posts") and all(p.get("comment_status") == "closed" for p in disc["posts"]):
            findings.append(Finding(
                "hygiene-comments-closed", "INFO",
                "Comments are closed on every sampled post",
                "Nothing to report: closed comments are not a spam target.",
                "Nothing to do.",
                [{"Posts sampled": len(disc["posts"])}], "rest.json", 1))
    third_party = data.get("third_party", [])
    if third_party:
        route_count = data.get("route_count", 0)
        findings.append(Finding(
            "rest-inventory", "INFO",
            (f"The REST index lists {route_count} routes across "
             f"{len(third_party)} non-core namespaces" if route_count else
             f"The REST index names {len(third_party)} non-core namespaces "
             "but withholds its route list"),
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
            "namespace that exists to drive the site programmatically. They "
            "are singled out from the "
            f"{len(data.get('write_routes', []))} routes on this site that "
            "accept a write method: the rest belong to ordinary plugins "
            "writing their own settings, while these exist to let something "
            "outside the site operate it. Whether they accept an anonymous "
            "call is UNKNOWN and was deliberately not tested, because "
            "finding out means sending a POST, which is submitting rather "
            "than observing. Most WordPress routes require authentication "
            "for writes, which is why this is rated medium on the evidence "
            "of a name; an unauthenticated route of this shape would be a "
            "way to change the site, so resolve it rather than filing it.",
            "First question, before any of the technical ones: did anyone "
            "mean to install this, and is it still being used for something? "
            "An interface for driving the site remotely that nobody "
            "remembers switching on is worth removing outright. If it is in "
            "use, determine from the plugin's own documentation or its "
            "source what authentication these routes require, restrict them "
            "to authenticated callers, and confirm from the plugin's "
            "settings that no long-lived token has been issued. Removing "
            "beats deactivating: a deactivated plugin's files stay on disk.",
            [{"Route": r["route"], "Methods": ", ".join(r["methods"])}
             for r in rpc], "rest.json", len(rpc)))

    # Application passwords. The REST index advertises them when they are
    # available, which is the WordPress default over HTTPS. On its own that
    # is unremarkable; next to an enumerable user list it is the other half
    # of a credential, so the report names it rather than leaving it in the
    # JSON for nobody to read.
    auth = (data.get("authentication") or {}).get("application-passwords") or {}
    if auth:
        users = ctx.data("users") or {}
        published = len(users.get("rest", []) or [])
        findings.append(Finding(
            "rest-app-passwords", "LOW" if published else "INFO",
            "Application passwords are enabled, which is the WordPress default",
            "An application password is a second credential on a real "
            "account: it is created in wp-admin, it carries that account's "
            "full permissions, it bypasses two-factor authentication by "
            "design, and it does not expire. That is what makes it useful "
            "for connecting other software, and it is also why it is worth "
            "an inventory."
            + (f" This site also publishes {published} usernames, so an "
               "attacker needs only the password half."
               if published else ""),
            "In wp-admin, open each administrator's profile and read the "
            "Application Passwords section: every entry there is a live "
            "credential, and 'Last used' says whether anything still needs "
            "it. Revoke the ones nothing is using. If no integration needs "
            "them at all, turn the feature off with the "
            "wp_is_application_passwords_available filter.",
            [{"Setting": "application passwords", "State": "enabled",
              "Authorisation screen": auth.get("endpoints", {}).get(
                  "authorization", "not published")}],
            "rest.json"))
    return findings


def check_assets(ctx: RunContext) -> List[Finding]:
    data = ctx.data("assets")
    if not data:
        return []
    findings = []
    keyed: Dict[Tuple[str, str], Dict] = {}
    for h in data.get("secrets", []):
        keyed.setdefault((h["vendor"], h["masked"]), h)
    real = [h for h in keyed.values() if h["severity"] != "INFO"]
    maps = [h for h in keyed.values() if h["severity"] == "INFO"]
    if real:
        findings.append(Finding(
            "leaks-secrets",
            "CRITICAL" if any(h["severity"] == "CRITICAL" for h in real) else "HIGH",
            f"{len(real)} credential-shaped string(s) in the page source or scripts",
            "These match the format of a vendor's secret key or a password "
            "assigned in code, in HTML or JavaScript that every visitor "
            "downloads. A live payment or cloud key is a direct way in. Only "
            "the first four and last two characters are shown here; the full "
            "value was not stored. A test key or a value that only looks like "
            "a key is possible, so confirm with the vendor's dashboard.",
            "Revoke each key at the vendor today and issue a new one, then "
            "move it to the server side (a constant in wp-config.php or an "
            "environment variable) so it never reaches the browser. Rotating "
            "is the fix; removing it from the page alone is not, because it "
            "has already been published.",
            [{"Vendor": h["vendor"], "Value": h["masked"], "Where": h["where"]} for h in real],
            "assets.json", len(real)))
    if maps:
        findings.append(Finding(
            "leaks-maps-key", "INFO",
            "A Google Maps browser key is in the page",
            "A Maps JavaScript key has to be in the page to work, so this is "
            "normal. What matters is that it is restricted to this site's "
            "addresses, or anyone can use it and the bill is the site's.",
            "In Google Cloud Console, restrict the key by HTTP referrer to this "
            "site's domains and to the Maps APIs it needs.",
            [{"Value": h["masked"], "Where": h["where"]} for h in maps], "assets.json", len(maps)))
    dbg = list({(h["kind"], h["detail"]): h for h in data.get("debug", [])}.values())
    php_errors = [h for h in dbg if h["kind"].startswith("PHP")]
    if php_errors:
        findings.append(Finding(
            "leaks-debug", "MEDIUM",
            f"{len(php_errors)} PHP error(s) printed into public pages",
            "PHP warnings and errors with file paths are reaching visitors, so "
            "WP_DEBUG_DISPLAY or display_errors is on in production. Each "
            "message names the server's directory layout and the plugin or "
            "theme that failed, which is a map for an attacker. The rss.php "
            "check in the paths section tests the same setting.",
            "Set WP_DEBUG_DISPLAY to false (and WP_DEBUG to false on a live "
            "site) in wp-config.php, and display_errors = Off in PHP. Log "
            "errors to a file outside the web root instead.",
            [{"Page": h["page"], "Message": h["kind"], "File": h["detail"]} for h in php_errors],
            "assets.json", len(php_errors)))
    unmin = [h for h in dbg if h["kind"] == "unminified core script"]
    if unmin:
        findings.append(Finding(
            "leaks-script-debug", "INFO",
            "Core scripts are served unminified, so SCRIPT_DEBUG is on",
            "WordPress serves the readable versions of its scripts only when "
            "SCRIPT_DEBUG is set. It slows pages and is a sign debugging was "
            "left on.",
            "Remove SCRIPT_DEBUG from wp-config.php on the live site.",
            [{"Page": unmin[0]["page"], "Script": unmin[0]["detail"]}], "assets.json", 1))
    unpinned = [r for r in data.get("third_party_resources", []) if not r["integrity"]]
    if unpinned:
        total = data.get("third_party_total", len(unpinned))
        findings.append(Finding(
            "assets-sri", "LOW",
            f"{len(unpinned)} third-party script(s) and stylesheet(s) load "
            "without Subresource Integrity",
            "A compromised or mistakenly changed file on one of these "
            "providers runs on every page that loads it, with this site's "
            "trust. An integrity attribute pins a hash, so the browser "
            "refuses a changed file. Tag managers, chat widgets, analytics "
            "and Google Fonts serve different bytes to different visitors "
            "and cannot be pinned; for those the control is a script-src "
            "list in the Content-Security-Policy naming only the hosts in "
            "use. Only tags present in the HTML were read: scripts a tag "
            "manager adds at runtime are not listed."
            + (f" The sweep saw {total} third-party resources; the 50 on the "
               "most pages are kept." if total > 50 else ""),
            "Add integrity and crossorigin attributes to the rows marked "
            "pinnable, which are fixed library versions on a public CDN. For "
            "the rest, list their hosts in a Content-Security-Policy "
            "script-src (see the security headers findings) and remove any "
            "provider the site no longer uses.",
            [{"Resource": r["url"], "Type": r["type"], "Pages": r["pages"],
              "Pinnable": "yes, versioned CDN file" if r["pinnable"] else "no, dynamic"}
             for r in unpinned], "assets.json", len(unpinned)))
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
    # A theme may share a plugin's slug, and {**plugins, **themes} dropped the
    # plugin, its advisories with it.
    themes = {(f"theme/{slug}" if slug in plugins else slug): entry
              for slug, entry in data.get("themes", {}).items()}
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
            others = [v for v in entry.get("detected_versions", [])
                      if v != matched]
            if others and not entry.get("version_conflict"):
                # Say what else was on the page. A reader who greps the source
                # and finds ver=1.0.0 needs to know it was seen and discounted.
                version_text = (f"{matched}; asset URLs also carry "
                                f"{', '.join(others)}, which belong to "
                                "individual files")
            if entry.get("source") == "rest namespace":
                version_text = f"{matched} (from the plugin's readme.txt)"
            elif entry.get("version_conflict"):
                # Two witnesses that disagree. Only the higher one was
                # measured, so nothing here is known about the lower, and the
                # component cannot carry more than MEDIUM until someone reads
                # the Plugins screen.
                other = readme if matched != readme else ", ".join(
                    v for v in entry.get("detected_versions", []) if v != readme)
                version_text = (f"{matched} per {'readme.txt' if matched == readme else 'asset URLs'}, "
                                "the higher of two disagreeing sources; "
                                f"{'asset URLs say' if matched == readme else 'readme.txt says'} "
                                f"{other}, which was not measured. "
                                "Confirm on the Plugins screen.")
                severity = cap_severity(severity, "MEDIUM")
            if top.get("every_release"):
                # Nothing was measured, and nothing needed to be: the range
                # has no lower bound and reaches the current release.
                current = (entry.get("wporg") or {}).get("current_version", "")
                version_text = (
                    "not read, and it does not decide this: the issue has no "
                    "lower bound and still covers the current release"
                    + (f" ({current})" if current else "")
                    + ", so every installed version is affected")
            if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(worst):
                worst = severity
            rows.append({
                "Component": f"{slug} ({'theme' if slug in themes else 'plugin'})",
                "Version running": version_text,
                "Known issues": len(entry["vulnerabilities"]),
                "Worst CVSS": f"{top['score']:.1f}" if top["score"] else "unscored",
                "Reference": top["cve"] or top["name"][:60],
                "Fixed in": fix_text(top),
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

    # 1b. Version read from the changelog over a lower Stable tag. MEDIUM, not
    #     the CVE's own score: the higher reading is usually right (Forminator
    #     1.57.3 shipped saying 1.57.2), but only the Plugins screen settles it.
    disputed = {s: e for s, e in plugins.items()
                if e.get("disputed_vulnerabilities")}
    if disputed:
        findings.append(Finding(
            "vulns-disputed", "MEDIUM",
            f"{len(disputed)} plugin(s) are vulnerable only if their readme's "
            "Stable tag is right",
            "The plugin's readme.txt names one version on its Stable tag line "
            "and a higher one at the top of its changelog. The check above used "
            "the changelog, because authors forget to bump the tag. A changelog "
            "can also list a release that is not installed, so these "
            "vulnerabilities apply if the Stable tag is the true version.",
            "Read the version in Plugins > Installed Plugins (or the dashboard "
            "that manages the site). At or above the changelog version, nothing "
            "to do; at the Stable tag version, update to the fixed release.",
            [{"Plugin": s,
              "Stable tag": e["readme_stable_tag"],
              "Changelog": e.get("readme_version", ""),
              "Issues at the Stable tag": len(e["disputed_vulnerabilities"]),
              "Reference": (e["disputed_vulnerabilities"][0].get("cve")
                            or e["disputed_vulnerabilities"][0].get("name", "")[:60]),
              "Fixed in": e["disputed_vulnerabilities"][0].get("fixed_in", "")}
             for s, e in sorted(disputed.items())],
            "vulns.json", len(disputed)))

    # 2. Withdrawn from the directory. No vulnerability database needed.
    #
    #    Two things this deliberately does NOT say, both of them corrections
    #    to what it used to say. First, a closure is not proof of
    #    abandonment: "Author Request" is also what a library looks like when
    #    its author moves distribution to Composer or GitHub and keeps
    #    shipping. Carbon Fields, closed 2019, was releasing eleven days
    #    before the run that produced this comment. Second, a namespace is
    #    not an installation. A slug seen only in the REST index can be a
    #    library bundled inside a theme or another plugin, so "installed" and
    #    "remove the plugin" are both claims the evidence does not support.
    closed = {slug: entry for slug, entry in {**plugins, **themes}.items()
              if (entry.get("wporg") or {}).get("closed")}
    if closed:
        def _seen_as(slug: str, entry: Dict) -> str:
            if slug in themes:
                return "named as the active theme in the homepage HTML"
            if entry.get("source") == "rest namespace":
                return ("a REST namespace only, which a bundled library "
                        "produces as readily as an installed plugin")
            return f"asset URLs on {entry.get('pages', 0)} page(s)"

        namespace_only = all(
            slug not in themes and entry.get("source") == "rest namespace"
            for slug, entry in closed.items())
        findings.append(Finding(
            "vulns-closed",
            # Direct evidence of an installed, closed plugin is a real
            # exposure. A namespace on its own is a question, and a question
            # does not belong in the same severity band as a finding.
            "MEDIUM" if namespace_only else "HIGH",
            f"{len(closed)} component(s) match a slug that wordpress.org has "
            "withdrawn",
            "WordPress.org has closed this slug, so nothing more will arrive "
            "through the update screen and WordPress will not warn the "
            "administrator about it. What the closure MEANS varies, and the "
            "directory's stated reason is the only clue on offer: a security "
            "report the author never answered is one cause, but so is a "
            "developer library whose author moved distribution to Composer "
            "or GitHub and is still shipping releases there. The second kind "
            "is usually bundled inside a theme or another plugin rather than "
            "installed, which is also why it can appear here without "
            "anything showing on the Plugins screen. Read the 'How it was "
            "seen' column before acting: where that says a REST namespace "
            "only, this report cannot tell the two cases apart.",
            "Start by asking the developer what this component is and where "
            "it comes from - a bundled library needs its bundled version "
            "checked against the author's own releases, not removal. Where "
            "it is genuinely an installed plugin nobody maintains, replace "
            "or remove it; do not leave it installed and deactivated, "
            "because its files stay on disk and stay reachable.",
            [{"Component": slug,
              "How it was seen": _seen_as(slug, entry),
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
        # A plugin released in the last three months has been looked at,
        # whatever its "Tested up to" says; authors lag that header. One
        # released nine days earlier was listed as "not looked at since".
        recently_released = days is not None and days < 90
        if tested and majors and version_ordered(tested) and not recently_released:
            floor = version_key(tested)[0][:2]
            behind = sum(1 for m in majors if version_key(m)[0][:2] > floor)
            if behind >= TESTED_MAJORS_BEHIND:
                reasons.append(f"declares support only up to WordPress {tested}, "
                               f"which is {behind} major releases ago")
        if not reasons:
            continue
        stale.append({
            "Component": slug,
            "How it was seen": ("named as the active theme" if slug in themes
                                else "a REST namespace only"
                                if entry.get("source") == "rest namespace"
                                else f"asset URLs on {entry.get('pages', 0)} page(s)"),
            # Derived here as well as at collect time so a run directory
            # written by an earlier version still renders a version.
            "Version running": (entry.get("version_running")
                                or running_version(entry.get("detected_versions", []))
                                or "not read"),
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

    # 3b. Hygiene from the same payloads: little-used and quiet, two plugins
    #     doing one job, and sheer count.
    quiet = [(slug, e["wporg"]) for slug, e in sorted(plugins.items())
             if (e.get("wporg") or {}).get("found") and not e["wporg"].get("closed")
             and (e["wporg"].get("active_installs") or 0) < 1000
             and (e["wporg"].get("days_since_release") or 0) > 365]
    if quiet:
        findings.append(Finding(
            "hygiene-low-installs", "LOW",
            f"{len(quiet)} plugin(s) have under 1,000 installs and no release in a year",
            "Few other sites run these, so when one breaks or turns out to be "
            "vulnerable, few people will notice and the author may not act.",
            "Check whether each is still needed, and look for a better-used "
            "plugin that does the same job.",
            [{"Plugin": slug, "Active installs": w.get("active_installs"),
              "Last released": (w.get("last_updated") or "")[:10]} for slug, w in quiet],
            "vulns.json", len(quiet)))
    jobs: Dict[str, List[str]] = {}
    for slug, e in sorted(plugins.items()):
        job = plugin_job((e.get("wporg") or {}).get("tags") or [])
        if job:
            jobs.setdefault(job, []).append(slug)
    doubled = {j: s for j, s in jobs.items() if len(s) > 1}
    if doubled:
        findings.append(Finding(
            "hygiene-duplicates", "INFO",
            f"More than one plugin does the same job: {', '.join(sorted(doubled))}",
            "Two plugins doing one job (from the tags each plugin gives "
            "itself on wordpress.org) usually means one was replaced and "
            "never removed. Each extra plugin is code to keep patched.",
            "Keep one per job and remove the other after checking nothing "
            "depends on it.",
            [{"Job": j, "Plugins": ", ".join(s)} for j, s in sorted(doubled.items())],
            "vulns.json", len(doubled)))
    if len(plugins) > 30:
        findings.append(Finding(
            "hygiene-plugin-count", "INFO",
            f"{len(plugins)} plugins are visible from outside",
            "Every plugin is code that needs updating, and most published "
            "WordPress vulnerabilities are in plugins. Past thirty, there are "
            "usually some nobody remembers installing.",
            "Review the list and remove what is not used.",
            [{"Plugins visible": len(plugins)}], "vulns.json", 1))

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

    # 4b. PHP, from X-Powered-By. A reading only a cached page gave is
    #     capped, like core: the cache replays the header it stored.
    php = data.get("php") or {}
    php_v = php.get("detected", "")
    php_sources = php.get("sources") or {}
    php_live = bool(php_sources.get("homepage (cache-busted)"))
    php_note = ("" if php_live else
                " Only a cached page disclosed the version, so this is "
                "something to confirm rather than a confirmed exposure.")
    if len(set(php_sources.values())) > 1:
        php_note += (" The cached homepage and a cache-busted request disagree ("
                     + "; ".join(f"{k}: {v}" for k, v in php_sources.items())
                     + "); the cache-busted reading is the one used.")
    if php.get("vulnerabilities"):
        rows = php["vulnerabilities"]
        counted = [r for r in rows
                   if php.get("windows_server") or not r.get("windows_only")]
        severity = (cvss_severity(max(row["score"] for row in counted))
                    if counted else "LOW")
        if not php_live:
            severity = cap_severity(severity, "MEDIUM")
        windows_note = ""
        if len(counted) < len(rows):
            windows_note = (f" {len(rows) - len(counted)} of these apply only to "
                         "PHP on Windows, by the CVE's own description, and "
                         "nothing in the headers suggests a Windows server, "
                         "so they do not set this finding's severity.")
        findings.append(Finding(
            "vulns-php", severity,
            f"PHP {php_v} has {len(rows)} published vulnerability(ies) against it",
            "The PHP release this site names in its X-Powered-By header falls "
            "inside the affected range of a published PHP vulnerability. A "
            "host can backport a fix without changing the version number, so "
            "this is the version's record, not proof the server is "
            "exploitable." + windows_note + php_note,
            "Move the site to a supported PHP release at or above the highest "
            "Fixed in version below. On shared hosting the patch level is the "
            "host's, so ask them when the patched build reaches this server.",
            [{"Reference": row["cve"] or row["name"][:60],
              "CVSS": f"{row['score']:.1f}" if row["score"] else "unscored",
              "Fixed in": "no fix" if row["unfixed"] else row["fixed_in"],
              "Platform": "Windows only" if row.get("windows_only") else "any",
              "Details": row["reference"]}
             for row in rows], "vulns.json", len(rows)))
    end = php.get("branch_end", "")
    if php_v and end and end < datetime.now().strftime("%Y-%m-%d"):
        branch = ".".join(php_v.split(".")[:2])
        findings.append(Finding(
            "vulns-php-eol", "HIGH" if php_live else "MEDIUM",
            f"PHP {branch} stopped receiving security fixes on {end}",
            f"The site names PHP {php_v}. Nothing found in PHP {branch} since "
            f"{end} has been fixed, and the vulnerability feed stops listing "
            "new issues for a dead branch, so any PHP vulnerability list in "
            "this report understates the exposure." + php_note,
            "Move the site to a supported PHP branch. Test on a staging copy "
            "first: themes and plugins written for old PHP are what break.",
            [{"Running": php_v, "Security support ended": end}],
            "vulns.json", 1))
    elif php_v and end:
        branch = ".".join(php_v.split(".")[:2])
        active = PHP_ACTIVE_SUPPORT_END.get(branch, "")
        if active and active < datetime.now().strftime("%Y-%m-%d"):
            findings.append(Finding(
                "vulns-php-security-only", "INFO",
                f"PHP {branch} receives security fixes only, until {end}",
                f"Active support for PHP {branch} ended on {active}. Security "
                f"issues are still fixed until {end}; other bugs are not, and "
                "new fixes land in the next branch. Some scanners report the "
                f"{active} date as end of life, which it is not." + php_note,
                "Plan the move to the current PHP branch on the normal "
                "maintenance cycle, tested on a staging copy first.",
                [{"Running": php_v, "Active support ended": active,
                  "Security fixes until": end}], "vulns.json", 1))

    # 5. What could not be checked. This finding exists because its absence
    #    is a lie: a plugin the vulnerability database has never heard of
    #    produces the same empty result as a plugin it has cleared.
    gaps = []
    # Core first. A core that could not be looked up, or was never
    # identified, was absent from this list for one release, so a report on
    # a site running a development build said nothing about core at all.
    if not detected:
        hint = sources.get("wp-includes assets", "")
        gaps.append({"Component": "WordPress core",
                     "What was not checked": "neither the generator tag nor the "
                     "feed discloses the version"
                     + (f"; core asset URLs suggest {hint}, but a reading from "
                        "asset URLs alone is not trusted for a vulnerability "
                        "lookup" if hint else
                        " and the core asset URLs carry no version either")
                     + ", so core could not be checked against the "
                     "vulnerability data. Hiding it is good practice; it also "
                     "means this report cannot say whether core is current."})
    elif not core.get("covered"):
        gaps.append({"Component": f"WordPress core {detected}",
                     "What was not checked": core.get("lookup_error")
                     or ("no vulnerability record for this version"
                         if "covered" in core else
                         "the vulnerability lookup did not run")})
    if not php_v:
        gaps.append({"Component": "PHP",
                     "What was not checked": "neither X-Powered-By nor Server "
                     "names a PHP version, so PHP could not be checked against "
                     "the vulnerability data. Hiding it is good practice; ask "
                     "the host which release serves the site."})
    elif not php.get("covered"):
        gaps.append({"Component": f"PHP {php_v}",
                     "What was not checked": php.get("lookup_error")
                     or "the vulnerability lookup did not run"})
    elif php.get("undecidable"):
        gaps.append({"Component": f"PHP {php_v}",
                     "What was not checked": f"{php['undecidable']} record(s) "
                     "could not be decided"})
    for slug, entry in sorted({**plugins, **themes}.items()):
        reasons = []
        if not entry.get("covered"):
            reasons.append(entry.get("lookup_error") or "no vulnerability record")
        if not (entry.get("wporg") or {}).get("found"):
            reasons.append("not in the wordpress.org directory")
        if not entry.get("detected_versions"):
            # A 403 on readme.txt is the edge refusing, not the plugin
            # hiding. Said plainly, because the reader's next move differs:
            # one is a question for the developer, the other is a WAF rule.
            blocked = entry.get("readme_status") in (401, 403)
            reasons.append("no version could be read"
                           + (" from style.css" if slug in themes else
                              (" from asset URLs, and readme.txt is blocked "
                               f"by the edge (HTTP {entry.get('readme_status')})"
                               if blocked else " from asset URLs or readme.txt"))
                           + (", so only issues covering every release could "
                              "be matched (those are reported above)"
                              if any(v.get("every_release")
                                     for v in entry.get("vulnerabilities") or [])
                              else ", so no range could be matched"))
        if entry.get("undecidable"):
            reasons.append(f"{entry['undecidable']} record(s) could not be "
                           "decided: a version range this tool does not "
                           "interpret, or two sources disagreeing on the "
                           "first affected version")
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


def xmlrpc_adverts(headers: Dict) -> List[Dict[str, str]]:
    """Evidence rows for each place the homepage advertises XML-RPC."""
    pb = (headers or {}).get("pingback") or {}
    rows = []
    if pb.get("header"):
        rows.append({"URL": pb["header"], "Status": "advertised by the X-Pingback header"})
    if pb.get("link"):
        rows.append({"URL": pb["link"], "Status": "advertised by link rel=pingback"})
    return rows


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
            "whether anyone publishes from the mobile app. Remove the "
            "advertisement too: filter wp_headers to drop X-Pingback and "
            "remove_action('wp_head', 'rsd_link'); many security plugins do "
            "both.",
            [{"URL": ctx.site + "/xmlrpc.php", "Status": "answering"}]
            + xmlrpc_adverts(ctx.data("headers")),
            "transport.json"))

    gql = [g for g in data.get("graphql", []) if g.get("answering")]
    if gql:
        findings.append(Finding(
            "transport-graphql", "INFO",
            "A GraphQL endpoint answers anonymous queries",
            "A GraphQL plugin, usually WPGraphQL, publishes posts, pages, "
            "menus, users and settings through one query language. It is a "
            "second API with its own authorisation rules, so closing the "
            "REST users endpoint does nothing for it: WPGraphQL shows any "
            "user with a published post to anyone. This report asked for "
            "one word (__typename) and did not read users or the schema.",
            "If nothing on the front end queries it without a login, turn on "
            "\"Only allow logged-in users\" in the WPGraphQL settings. Leave "
            "public introspection off, which is WPGraphQL's default in "
            "production. Remove the plugin if nothing uses it.",
            [{"URL": g["url"], "Status": g["status"]} for g in gql],
            "transport.json", 1))

    if data.get("registration", {}).get("open"):
        findings.append(Finding(
            "transport-registration", "MEDIUM",
            "Anyone can create an account on this site",
            "The login page offers a Register link, which WordPress shows "
            "only while Settings > General > Membership > Anyone can register "
            "is on. Each new account gets the default role, normally "
            "Subscriber. Many published plugin vulnerabilities need only a "
            "logged-in Subscriber, so open registration turns them from "
            "\"needs an account\" into \"needs an email address\". A site "
            "with a members' area may need this on purpose.",
            "If visitors do not need accounts, untick Anyone can register. "
            "If they do, confirm the New User Default Role on the same screen "
            "is Subscriber and nothing higher, and keep plugins current.",
            [{"URL": ctx.site + "/wp-login.php",
              "Status": "Register link offered"}], "transport.json"))

    legacy = [k for k in ("TLSv1.0", "TLSv1.1")
              if (data.get("tls_legacy") or {}).get(k) == "accepted"]
    if legacy:
        findings.append(Finding(
            "transport-tls-legacy", "MEDIUM",
            f"The server still accepts {' and '.join(legacy)}",
            "Old protocol versions are what a downgrade attack targets, and "
            "current browsers no longer speak them, so nothing legitimate "
            "breaks when they are turned off. Each version was offered on "
            "its own in a separate handshake. Cipher grading is not done "
            "here; use SSL Labs for that.",
            "Set the minimum protocol to TLS 1.2 at the CDN or web server "
            "(ssl_protocols TLSv1.2 TLSv1.3 in nginx, SSLProtocol -all "
            "+TLSv1.2 +TLSv1.3 in Apache).",
            [{"Protocol": k, "Result": "accepted"} for k in legacy],
            "transport.json", len(legacy)))

    oh = data.get("other_host") or {}
    if oh.get("state") in ("certificate error", "serves a copy"):
        cert = oh["state"] == "certificate error"
        findings.append(Finding(
            "transport-hosts", "MEDIUM" if cert else "LOW",
            f"https://{oh['host']} "
            + ("has no valid certificate" if cert else "serves the site without redirecting"),
            ("Visitors who type the other form of the address get a browser "
             "certificate warning, and some will click through it."
             if cert else
             "The site answers under two names. Search engines may index both, "
             "and protections set on one name (cookies, HSTS) do not carry to "
             "the other."),
            ("Add the name to the certificate, or remove its DNS record if it "
             "is not meant to be used." if cert else
             f"Redirect https://{oh['host']} to the audited address with a 301."),
            [{"Address": f"https://{oh['host']}/", "Result": oh["state"],
              "Status": oh.get("status")}], "transport.json", 1))
    if (data.get("login_http") or {}).get("form_in_clear"):
        findings.append(Finding(
            "transport-login-http", "HIGH",
            "The login form is served over plain HTTP",
            "http://.../wp-login.php answers with the login form instead of "
            "redirecting to HTTPS, so a password typed there crosses the "
            "network unencrypted.",
            "Redirect every HTTP request to HTTPS at the server or CDN, and set "
            "FORCE_SSL_ADMIN in wp-config.php.",
            [{"URL": f"http://{data.get('host', '')}/wp-login.php", "Status": 200}],
            "transport.json", 1))
    # Core's test cookie never carries HttpOnly by design, so only a cookie
    # sent without Secure from the login page is a finding.
    bare = [c for c in data.get("login_cookies", []) if not c["secure"]]
    if bare:
        findings.append(Finding(
            "transport-login-cookies", "LOW",
            f"The login page sets {len(bare)} cookie(s) without Secure",
            "A cookie without Secure is also sent over plain HTTP. The login "
            "page is where WordPress sets cookies on every visit, so this is "
            "where the site's cookie flags are really measured.",
            "Serve the site over HTTPS only and set the cookie's Secure flag; "
            "WordPress sets it itself when the site address is https.",
            [{"Cookie": c["name"], "Secure": "NO"} for c in bare], "transport.json", len(bare)))
    traffic = (getattr(ctx, "manifest", None) or {}).get("meta", {}).get("traffic") or {}
    if traffic.get("requests"):
        per_min = traffic["requests"] * 60 / max(traffic.get("seconds", 1), 1)
        findings.append(Finding(
            "transport-rate-limit", "INFO",
            ("No rate limiting was observed" if not traffic["refused"] else
             f"The site refused {traffic['refused']} request(s) with HTTP 429 or 503")
            + f" across {traffic['requests']} requests",
            (f"This run made {traffic['requests']} requests to the site over "
             f"{traffic['seconds']} seconds, about {per_min:.0f} a minute, and "
             + ("none was refused. A login page with the same behaviour accepts "
                "password guesses at that rate. This is a measured statement "
                "about this run, not a test of the login page."
                if not traffic["refused"] else
                f"{traffic['refused']} were refused, so something in front of the "
                "site limits request rates.")),
            "If nothing limits requests, add rate limiting at the CDN or a "
            "login-protection plugin, at least for wp-login.php and xmlrpc.php.",
            [{"Requests": traffic["requests"], "Seconds": traffic["seconds"],
              "Per minute": f"{per_min:.0f}", "Refused (429/503)": traffic["refused"]}],
            "transport.json", 1))

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
    expired = tls.get("seconds_left", days) is not None and \
        tls.get("seconds_left", days) < 0
    if tls.get("verify_error"):
        findings.append(Finding(
            "transport-tls-invalid", "CRITICAL",
            f"The TLS certificate fails verification: {tls['verify_error']}",
            "A browser shows a full-page security warning before the site "
            "loads, and most visitors leave. An expired certificate, one "
            "issued for a different name, and one from an untrusted issuer "
            "all land here.",
            "Check the certificate at the host or CDN today. If it expired, "
            "look for a failing renewal; if the name is wrong, the "
            "certificate on this server was issued for another site.",
            [{"Host": data.get("host", "?"),
              "Verification error": tls["verify_error"]}], "transport.json"))
    elif isinstance(days, int) and days < 21:
        findings.append(Finding(
            "transport-tls", "CRITICAL" if expired else "MEDIUM",
            "The TLS certificate has expired" if expired
            else f"The TLS certificate expires in {days} day(s)",
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


def check_integrity(ctx: RunContext) -> List[Finding]:
    data = ctx.data("integrity")
    if not data:
        return []
    findings = []
    # Pages from this module and from the asset sweep, one row per finding.
    hits, seen = [], set()
    for h in data.get("page_hits", []) + (ctx.data("assets") or {}).get("integrity_hits", []):
        key = (h["page"].split("?")[0].rstrip("/"), h["kind"], h["detail"])
        if key not in seen:
            seen.add(key)
            hits.append(h)
    signed_in = [h for h in hits if h["kind"] == "signed-in view"]
    if signed_in:
        findings.append(Finding(
            "integrity-cached-session", "HIGH",
            f"{len({h['page'] for h in signed_in})} page(s) were served as a "
            "signed-in user sees them",
            "The page carries markup WordPress prints only for a signed-in "
            "user. A cache configured to store signed-in pages serves that "
            "user's view to everyone: their toolbar, their name, and links "
            "carrying their security tokens. This report fetched the page "
            "without signing in.",
            "Purge the page cache, exclude logged-in users in the cache "
            "plugin's or host's cache settings, and change that user's "
            "password and log out their other sessions.",
            [{"Page": h["page"], "What was seen": h["detail"]} for h in signed_in],
            "integrity.json", len(signed_in)))
    injected = [h for h in hits if h["kind"] != "signed-in view"]
    if injected:
        findings.append(Finding(
            "integrity-injected",
            "HIGH" if any(h["severity"] == "HIGH" for h in injected) else "MEDIUM",
            f"{len(injected)} sign(s) of injected content in the page source",
            "These are patterns injected markup leaves behind: an iframe to "
            "another site that is hidden or sized to nothing, links to other "
            "sites inside a hidden element, inline script that decodes a long "
            "encoded string, a refresh to another site, or links with spam "
            "words. Each has innocent explanations (an embed, a menu, a "
            "consent tool), so this is a list to check, not a verdict. The "
            "suspicious scripts and links were not fetched.",
            "Compare the theme and plugin files on the server with fresh "
            "copies, search the database for the host names below, and change "
            "every password afterwards. The host's malware scan or a reputable "
            "cleanup service is the next step; this report cannot clean a site.",
            [{"Page": h["page"], "What": h["kind"], "Detail": h["detail"],
              "Severity": h["severity"]} for h in injected],
            "integrity.json", len(injected)))
    sm = data.get("sitemap") or {}
    if sm.get("read"):
        rows, prev = [], sm.get("previous_count")
        if prev is not None and sm["count"] > max(prev * 3, prev + 100):
            rows.append({"Signal": "URL count jumped",
                         "Detail": f"{prev} in {sm['previous_run']}, {sm['count']} now"})
        rows += [{"Signal": "spam word in a URL", "Detail": u} for u in sm.get("spam", [])]
        if rows:
            findings.append(Finding(
                "integrity-sitemap", "MEDIUM",
                "The sitemap shows signs of injected pages",
                "Spam injections usually add hundreds of pages and list them in "
                "the sitemap so search engines find them. A sudden jump in the "
                "URL count, or URLs about pharmacy, gambling or loans on a site "
                "that does not sell them, is the pattern. A real content import "
                "or a shop also explains a jump, so check what the new URLs are.",
                "Open the sitemap and look at the newest URLs. If they are not "
                "yours, search the database for them, compare theme and plugin "
                "files with fresh copies, and change every password afterwards.",
                rows, "integrity.json", len(rows)))
        elif prev is None:
            findings.append(Finding(
                "integrity-sitemap-count", "INFO",
                f"The sitemap lists {sm['count']} URL(s)",
                "Recorded so the next run can tell a sudden jump, which is how "
                "a spam injection usually shows, from normal growth."
                + (f" {sm['children_read']} of {sm['children']} child sitemaps were read."
                   if sm.get("children", 0) > sm.get("children_read", 0) else ""),
                "Nothing to do.",
                [{"Sitemap": sm.get("index", ""), "URLs": sm["count"]}], "integrity.json", 1))
        if sm.get("lastmod_count", 0) >= 100:
            findings.append(Finding(
                "integrity-sitemap-lastmod", "INFO",
                f"{sm['lastmod_count']} sitemap entries share one modification minute",
                "Hundreds of pages changed in the same minute is what a bulk "
                "injection looks like, and also what a bulk edit, an import or "
                "a plugin that rewrites every post looks like.",
                "If nobody on the site did a bulk change then, look at what "
                "changed on those pages.",
                [{"Minute": sm["lastmod_minute"], "Entries": sm["lastmod_count"]}],
                "integrity.json", 1))
    core = data.get("core") or {}
    files = core.get("files", [])
    bad = [f for f in files if f["result"] == "mismatch"]
    good = [f for f in files if f["result"] == "match"]
    edge = (ctx.data("headers") or {}).get("edge") or []
    if bad:
        findings.append(Finding(
            "integrity-core", "HIGH",
            f"{len(bad)} WordPress core file(s) differ from the official "
            f"{core['version']} release",
            "Each file was fetched and its MD5 compared with wordpress.org's "
            f"published checksums for WordPress {core['version']} "
            f"({core.get('locale') or 'en_US'}). A modified core file is a "
            "strong sign of compromise. A host or plugin that minifies, "
            "rewrites or injects into static files produces the same "
            "mismatch"
            + (f", and {', '.join(edge)} sits in front of this site" if edge else "")
            + ", so the next step is to compare the file on the server with "
            "a fresh download. Only static files can be read from outside; "
            "the PHP files, where injections usually live, were not checked.",
            "Run wp core verify-checksums on the server, which checks every "
            "core file including the PHP. Replace anything modified with a "
            "fresh copy of the same version, then work out how it changed.",
            [{"File": f["path"], "Result": "differs"} for f in bad]
            + [{"File": f["path"], "Result": "matches"} for f in good],
            "integrity.json", len(bad)))
    elif good:
        findings.append(Finding(
            "integrity-core-ok", "INFO",
            f"{len(good)} static core file(s) match the official "
            f"{core['version']} release",
            "Each file was fetched and its MD5 matched wordpress.org's "
            "published checksum. This covers static JavaScript and CSS only; "
            "the PHP files, where injections usually live, cannot be read "
            "from outside.",
            "Nothing to do. wp core verify-checksums on the server checks the "
            "PHP files too.",
            [{"File": f["path"], "Result": "matches"} for f in good],
            "integrity.json", len(good)))
    judged = [dict(r, verdict=v, reason=why) for r in data.get("cloaking", [])
              for v, why in [cloaking_verdict(r["base"], r["control"], r["fetched"], r.get("control2"))]]
    for severity in ("HIGH", "MEDIUM"):
        hits = [r for r in judged if r["verdict"] == severity]
        if not hits:
            continue
        findings.append(Finding(
            f"integrity-cloaking{'-medium' if severity == 'MEDIUM' else ''}", severity,
            f"{len(hits)} page(s) look different to a search crawler or a "
            "search visitor than to a browser",
            "A common sign of compromise is a site that shows search engines "
            "or visitors arriving from a search one thing and everyone else "
            "another, which is why owners usually hear of it from a "
            "blacklisting notice. "
            + ("A redirect elsewhere or a changed title or link count is a "
               "strong sign." if severity == "HIGH" else
               "Only the page body differed here. A/B testing, consent tools "
               "and personalisation produce the same result, so treat it as "
               "something to check, not a conclusion.")
            + " All fetches came from one address, so a redirect keyed on "
            "country would not show.",
            "Repeat the request in a browser's developer tools: load the page "
            "with the user agent set to Googlebot (Network conditions), and "
            "again by clicking through from a search result, and compare with "
            "a normal load. If they differ, compare the theme and plugin files "
            "on the server with fresh copies, search the database for the "
            "injected text, and change every password afterwards. The host's "
            "malware scan or a reputable cleanup service is the next step.",
            [{"Page": r["page"], "Fetched as": r["variant"], "What differed": r["reason"]}
             for r in hits], "integrity.json", len(hits)))
    return findings


def check_dns(ctx: RunContext) -> List[Finding]:
    data = ctx.data("dns")
    if not data:
        return []
    findings = []
    domain = data.get("domain", "")
    if data.get("caa_measured") and not data.get("caa"):
        issuer = ((ctx.data("transport") or {}).get("tls") or {}).get("issuer", "")
        caa_id = CAA_IDS.get(issuer.lower(), "")
        findings.append(Finding(
            "dns-caa", "LOW",
            "No CAA record limits which authorities may issue certificates "
            "for this domain",
            "Any of the hundreds of public certificate authorities may issue "
            f"a certificate for {data.get('host', domain)}. A CAA record names "
            "the ones allowed, so a mis-issuance by any other authority is "
            "refused. It is rated low because it guards against an "
            "authority's mistake, not an attacker on the site.",
            "Add one CAA record at the domain naming the authority in use"
            + (f": the certificate is from {issuer}, so 0 issue \"{caa_id}\"."
               if caa_id else
               (f". The certificate is from {issuer}; use the CAA identifier "
                "that authority publishes." if issuer else ".")),
            [{"Name checked": data.get("host", domain), "CAA": "none, up to "
              + ".".join(data.get("host", domain).split(".")[-2:])}],
            "dns.json", 1))
    if data.get("dnssec_validated") is False:
        findings.append(Finding(
            "dns-dnssec", "INFO",
            "The domain is not signed with DNSSEC",
            "A validating resolver could not confirm this domain's answers "
            "with DNSSEC. Most hosts do not sign, and nothing is broken; "
            "DNSSEC stops a resolver being fed false answers for the domain, "
            "which is an attack on the visitor's network rather than on the "
            "site.",
            "If the registrar and DNS host both support it, turn DNSSEC on at "
            "the DNS host and publish the DS record at the registrar. Many "
            "DNS hosts do this in one click.",
            [{"Domain": domain, "Resolver": DOH_URL, "AD flag": "false"}],
            "dns.json", 1))
    if data.get("wpcom_unclaimed"):
        findings.append(Finding(
            "dns-wpcom-takeover", "HIGH",
            f"{data.get('host', domain)} points at a WordPress.com site that "
            "does not exist",
            f"The host name's CNAME record points at {data.get('cname')}, and "
            "WordPress.com answers that no site by that name exists. Whoever "
            "registers that name on WordPress.com may be able to publish "
            "their own pages on this host name.",
            "Delete the CNAME record if the site has moved, or point it at "
            "the live site. If the WordPress.com site is still wanted, "
            "re-create it under that name.",
            [{"Record": "CNAME", "Value": data.get("cname", "")},
             {"Record": "WordPress.com", "Value": "no site by that name"}],
            "dns.json"))
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
            [{"Record": "Domain", "Value": domain},
             {"Record": "SPF", "Value": "absent"}]
            + ([{"Record": "Note",
                 "Value": f"rated low because {parent}'s DMARC policy "
                          f"({parent_policy}) already covers this subdomain"}]
               if inherits_enforcing else []), "dns.json"))
    # An SPF record naming no sender at all says "nothing may send as this
    # domain". That is the right record for a domain that sends no mail, and
    # the wrong one for a domain with a mailbox provider on its MX: every
    # message it sends fails SPF, and under p=reject the failure is fatal
    # unless DKIM happens to carry the alignment on its own.
    spf = data.get("spf", "")
    mx = data.get("mx", []) or []
    if data.get("spf_lookups", 0) > 10 or data.get("spf_loop"):
        findings.append(Finding(
            "dns-spf-lookups", "MEDIUM",
            f"The SPF record needs {data.get('spf_lookups')} DNS lookups, over the limit of ten"
            if not data.get("spf_loop") else "The SPF record includes itself in a loop",
            "Receiving servers stop after ten lookups and treat SPF as a "
            "permanent error, so mail from this domain fails SPF everywhere "
            "even from authorised senders.",
            "Remove senders the domain no longer uses, and replace include: "
            "chains with ip4:/ip6: ranges where a provider publishes them.",
            [{"Record": spf, "Lookups": data.get("spf_lookups"),
              "Loop": "yes" if data.get("spf_loop") else "no"}], "dns.json", 1))
    all_term = re.search(r"(?:^|\s)([+?]?)all\b", spf)
    if spf and all_term and all_term.group(1) in ("+", "?", ""):
        findings.append(Finding(
            "dns-spf-permissive", "MEDIUM",
            f"The SPF record ends in {all_term.group(1) or '+'}all, which authorises everyone",
            "+all lets any server on the internet pass SPF as this domain; "
            "?all says nothing either way. Neither stops spoofing.",
            "End the record with -all (or ~all while testing) once every "
            "legitimate sender is listed.",
            [{"Record": spf}], "dns.json", 1))
    if mx:
        missing_tls = []
        if not data.get("mta_sts_txt") or not data.get("mta_sts_policy"):
            missing_tls.append({"Record": "MTA-STS",
                                "What it adds": "tells sending servers to insist on encrypted, "
                                                "verified delivery to this domain"})
        if "tls_rpt" in data and not data["tls_rpt"]:
            missing_tls.append({"Record": "TLS-RPT (_smtp._tls)",
                                "What it adds": "daily reports of failed encrypted deliveries"})
        if missing_tls and "mta_sts_txt" in data:
            findings.append(Finding(
                "dns-mail-tls", "INFO",
                f"{domain} does not publish {' or '.join(r['Record'].split(' ')[0] for r in missing_tls)}",
                "Both are optional. Without MTA-STS, mail to this domain falls "
                "back to unencrypted delivery when an attacker on the path "
                "strips encryption; TLS-RPT is how you would hear about it.",
                "Publish a TLS-RPT record first (it only collects reports), then "
                "an MTA-STS policy in testing mode, then enforce.",
                missing_tls, "dns.json", len(missing_tls)))
    if spf and mx and not re.search(
            r"\b(include:|a[:\s]|mx\b|ptr\b|exists:|ip4:|ip6:|redirect=)", spf):
        policy = re.search(r"\bp=(\w+)", data.get("dmarc", "") or "")
        enforcing = policy and policy.group(1).lower() in ("quarantine", "reject")
        findings.append(Finding(
            "dns-spf-senders", "MEDIUM",
            f"{domain} has mail servers but its SPF record authorises no sender",
            f"The record is {spf}. It names no sender and ends in -all, which "
            "tells every receiving server that no host on earth is allowed to "
            "send as this domain. That is exactly right for a domain that "
            "sends no mail. This domain has MX records, so it receives mail, "
            "and a domain that receives mail usually sends it too. If it "
            "does, every message it sends fails SPF"
            + (f", and the DMARC policy on this domain is p={policy.group(1)}, "
               "so that failure is enough to have the message rejected "
               "outright unless DKIM signs it and aligns."
               if enforcing else ". ")
            + " This report cannot tell which case applies: the deliberate "
              "one, where all mail is sent from another domain, looks "
              "identical from outside.",
            "Confirm where this domain's mail is actually sent from. If it "
            "sends none, the record is correct and nothing needs doing - say "
            "so and move on. If it sends any, add the senders (for a Google "
            "Workspace tenant that is include:_spf.google.com) and check the "
            "DMARC reports the domain is already collecting before assuming "
            "delivery has been fine all along.",
            [{"Record": "SPF", "Value": spf},
             {"Record": "MX", "Value": ", ".join(mx)},
             {"Record": "DMARC",
              "Value": data.get("dmarc") or "absent"}], "dns.json"))
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
        if not re.search(r"\brua\s*=", data["dmarc"], re.I):
            findings.append(Finding(
                "dns-dmarc-no-rua", "LOW",
                f"{domain}'s DMARC record asks for no reports",
                "Without rua=, nobody receives the aggregate reports that show "
                "who is sending as this domain, legitimately or not.",
                "Add rua=mailto:<an address or a DMARC reporting service>.",
                [{"Record": data["dmarc"]}], "dns.json", 1))
        policy = re.search(r"\bp=(\w+)", data["dmarc"])
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
          check_transport, check_dns, check_integrity, check_privacy]


def run_checks(ctx: RunContext) -> List[Finding]:
    print_header("STAGE 2 - CHECK")
    findings: List[Finding] = []
    ctx.manifest["meta"]["check_errors"] = {}
    for check in CHECKS:
        try:
            findings.extend(check(ctx))
        except Exception as exc:                # one check must not end a run
            # A crashed check drops every finding it would have produced. The
            # console line is not enough: the report has to say so, or the
            # gap reads as clean. One release lost all DNS findings this way.
            ctx.manifest["meta"]["check_errors"][check.__name__] = (
                f"{type(exc).__name__}: {exc}")
            print_error(f"{check.__name__}: {type(exc).__name__}: {exc}")
    ctx.save()
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


# Paste-ready fixes, keyed by finding id. Directive syntax checked against
# the Apache 2.4 mod_headers and mod_authz_core docs, the nginx headers and
# access module docs, and the WordPress 6.8.3 source, on 2026-11-04.
_HEADER_BLOCK = {
    "Apache (.htaccess or vhost)": (
        "<IfModule mod_headers.c>\n"
        "  Header always set X-Content-Type-Options \"nosniff\"\n"
        "  Header always set X-Frame-Options \"SAMEORIGIN\"\n"
        "  Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
        "  Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n"
        "  Header always set Content-Security-Policy \"frame-ancestors 'self'; object-src 'none'; "
        "base-uri 'self'; upgrade-insecure-requests\"\n"
        "  # Last, and short at first: raise max-age once nothing needs HTTP.\n"
        "  Header always set Strict-Transport-Security \"max-age=300\"\n"
        "</IfModule>"),
    "nginx (server block)": (
        "add_header X-Content-Type-Options \"nosniff\" always;\n"
        "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
        "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
        "add_header Content-Security-Policy \"frame-ancestors 'self'; object-src 'none'; "
        "base-uri 'self'; upgrade-insecure-requests\" always;\n"
        "# Last, and short at first: raise max-age once nothing needs HTTP.\n"
        "add_header Strict-Transport-Security \"max-age=300\" always;"),
    "Cloudflare": "Rules > Transform Rules > Modify Response Header: add each header above as a static value.",
}
SNIPPETS: Dict[str, Dict[str, str]] = {
    "headers-medium": _HEADER_BLOCK,
    "headers-low": _HEADER_BLOCK,
    "headers-csp-weak": {k: v for k, v in _HEADER_BLOCK.items()},
    "headers-hsts-weak": {
        "Apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"},
    "transport-xmlrpc": {
        "Apache": "<Files \"xmlrpc.php\">\n  Require all denied\n</Files>",
        "nginx": "location = /xmlrpc.php {\n    deny all;\n}",
        "WordPress (code snippets plugin), drop the advertisement": (
            "add_filter( 'wp_headers', function ( $headers ) {\n"
            "    unset( $headers['X-Pingback'] );\n"
            "    return $headers;\n"
            "} );\n"
            "remove_action( 'wp_head', 'rsd_link' );")},
    "users-author": {
        "Apache": ("RewriteEngine On\n"
                   "RewriteCond %{QUERY_STRING} (^|&)author=\\d+ [NC]\n"
                   "RewriteRule ^ /? [R=301,L]"),
        "nginx": "if ($args ~* \"(^|&)author=\\d+\") {\n    return 301 /;\n}"},
    "users-rest": {
        "WordPress (code snippets plugin)": (
            "add_filter( 'rest_endpoints', function ( $endpoints ) {\n"
            "    if ( ! is_user_logged_in() ) {\n"
            "        unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\\d]+)'] );\n"
            "    }\n"
            "    return $endpoints;\n"
            "} );")},
    "headers-generator": {
        "WordPress (code snippets plugin)": "remove_action( 'wp_head', 'wp_generator' );"},
    "transport-wp-cron": {
        "wp-config.php": "define( 'DISABLE_WP_CRON', true );",
        "Server crontab (every five minutes)": (
            "*/5 * * * * curl -s https://<your site>/wp-cron.php?doing_wp_cron > /dev/null 2>&1")},
}


def _snippet_block(fid: str) -> str:
    """A collapsed block of paste-ready fixes for one finding, escaped."""
    snip = SNIPPETS.get(fid)
    if not snip:
        return ""
    parts = "".join(f"<p><strong>{escape(label)}</strong></p><pre>{escape(code)}</pre>"
                    for label, code in snip.items())
    return ("<details class='snippets'><summary>Paste-ready fix</summary>"
            "<p>Test on staging first: a header typo takes the site down for everyone.</p>"
            f"{parts}</details>")


def _evidence_table(finding: Finding) -> str:
    if not finding.evidence:
        return ""
    # Union of keys, not row 0's: evidence built from different sources can
    # legitimately carry different columns.
    shown = finding.evidence[:EVIDENCE_ROWS]
    headers = list(dict.fromkeys(k for r in shown for k in r))
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = ""
    for row in shown:
        cells = "".join(f"<td>{escape(str(row.get(h, '')))}</td>"
                        for h in headers)
        body += f"<tr>{cells}</tr>"
    more = ""
    if finding.count > len(shown):
        # --standalone readers have no run directory to be pointed at.
        where = ("kept with the run this report came from"
                 if EVIDENCE_ROWS >= EVIDENCE_ROWS_ALL else
                 "in the run directory")
        more = (f"<p class='more'>Showing {len(shown)} of "
                f"{finding.count}. The full list is in "
                f"<code>{escape(finding.source)}</code>, {where}.</p>")
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
    # The generator list comes off the first homepage fetch, which the CDN
    # may have served from cache. Show the live reading in the Platform row
    # so the summary and the finding headline agree.
    core_versions = headers.get("core_versions") or {}
    live_core = next((core_versions[k] for k in
                      ("generator (cache-busted)", "feed", "opml") if core_versions.get(k)), "")
    add("Platform", ", ".join(
        f"WordPress {live_core}"
        if live_core and g.lower().startswith("wordpress") else g
        for g in headers.get("generators", [])) or "not published (good)")
    add("Core version by source",
        "; ".join(f"{k}: {v}" for k, v in core_versions.items()))
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
    add("TLS", (f"{tls.get('protocol', '?')}, {tls.get('issuer', '?')}, "
                f"expires {tls.get('expires', '?')}" if "error" not in tls
                else f"fails verification: {tls['verify_error']}"
                if tls.get("verify_error") else f"not measured ({tls['error']})")
        if tls else "")
    if headers:
        seen_sec = security_plugins_seen(detected_plugins(ctx), headers.get("cookies", []))
        add("Security plugins visible", ", ".join(seen_sec) if seen_sec else
            "none visible (a plugin can be installed without loading anything on "
            "the front end, and a host's own protection does not show here)")
    if headers.get("hsts_preload"):
        add("HSTS preload list", {"preloaded": "on the list", "pending": "submitted, pending",
                                  "unknown": "not on the list"}.get(headers["hsts_preload"],
                                                                     headers["hsts_preload"]))
    if transport.get("tls_legacy"):
        add("Legacy TLS", ", ".join(f"{k} {v}" for k, v in transport["tls_legacy"].items()))
    add("Plain HTTP",
        f"HTTP {transport.get('http', {}).get('status', '?')}"
        + (f" to {transport['http']['location']}"
           if transport.get("http", {}).get("location") else ""))
    # A module that did not run measured nothing; a default here read as
    # "not answering" and "absent" for checks that never happened.
    if transport:
        add("XML-RPC", "answering"
            if transport.get("xmlrpc", {}).get("answering") else "not answering")
        add("security.txt", "present"
            if transport.get("security_txt", {}).get("present") else "absent")
        add("GraphQL", graphql_profile(transport.get("graphql")))
    if assets.get("third_party_resources"):
        hosts: Dict[str, int] = {}
        for r in assets["third_party_resources"]:
            hosts[r["host"]] = hosts.get(r["host"], 0) + 1
        add("External script and style hosts",
            ", ".join(f"{h} ({n})" for h, n in sorted(hosts.items(), key=lambda x: (-x[1], x[0]))))
    add("Application passwords",
        "enabled (the WordPress default)"
        if (rest.get("authentication") or {}).get("application-passwords")
        else "not advertised by the REST index")
    if dns:
        add("SPF", dns.get("spf") or "absent")
        add("DMARC", dns.get("dmarc")
            or (f"delegated to {dns['dmarc_delegated_to']}"
                if dns.get("dmarc_delegated_to") else "absent"))
        add("MX", ", ".join(dns.get("mx", []))
            or "none (this domain receives no mail)")
        if dns.get("caa"):
            add("CAA", f"{dns['caa_at']}: " + ", ".join(
                f"{r['tag']} {r['value']}" for r in dns["caa"]))
        if dns.get("bimi"):
            add("BIMI", dns["bimi"][:120])
        if "dnssec_validated" in dns:
            add("DNSSEC validated", {True: "yes", False: "no",
                                     None: "not measured"}[dns["dnssec_validated"]])

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
                                          "answered, unexpected content",
                                          "not checked")
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


# Every service other than the site that a run may contact, and all it is told.
THIRD_PARTY_SERVICES = (
    ("api.wordpress.org", "plugin and theme slugs, and the core version"),
    ("wpvulnerability.net", "plugin and theme slugs with their versions, and the PHP version"),
    ("dns.google", "domain names, when dig is not installed, and the domain for DNSSEC"),
    ("hstspreload.org", "the domain, only when the site sends Strict-Transport-Security"),
    ("rdap.org", "the site's IP address"),
    ("raw.githubusercontent.com", "nothing about the site: the tool checks its own VERSION file"),
)


def _methodology_block(ctx: RunContext) -> str:
    cal = ctx.data("calibration") or {}
    sig = cal.get("signature", {})
    control = cal.get("control", {})
    lines = []
    traffic = ctx.manifest["meta"].get("traffic") or {}
    if traffic.get("requests"):
        lines.append(
            f"<p><strong>Requests to the site:</strong> {traffic['requests']} over "
            f"{traffic.get('seconds', 0)} seconds, {traffic.get('refused', 0)} refused with "
            f"HTTP 429 or 503, with at least {REQUEST_DELAY:g}s between requests.</p>")
    lines.append(
        "<p><strong>Other services contacted, and what each was told:</strong></p><ul>"
        + "".join(f"<li>{escape(name)}: {escape(what)}</li>" for name, what in THIRD_PARTY_SERVICES)
        + "</ul>")

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

    exec_cal = ctx.data("exec_calibration") or {}
    if exec_cal.get("usable") and exec_cal.get("control_ran"):
        lines.append(
            "<p><strong>Configuration copies ending in .php were checked "
            "differently.</strong> The server runs such a file rather than "
            "sending it, so a real copy answers with an empty page. That "
            "counted only because a made-up .php name on this site did not "
            "answer the same way, and "
            f"<code>{escape(exec_cal.get('control_path', ''))}</code>, a core "
            "file that prints nothing when run, was still classified as "
            "present.</p>")
    elif exec_cal.get("note"):
        lines.append("<p class='warn'><strong>Configuration copies ending in "
                     f".php:</strong> {escape(exec_cal['note'])}.</p>")

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
    carry = ctx.manifest["meta"].get("documents_carry") or {}
    if carry.get("carried") or carry.get("removed") or carry.get("unmeasured"):
        rows += (
            "<tr><td>Public documents (discovery)</td><td>gap</td><td>"
            + escape(f"this run's discovery found {carry['discovered']} "
                     f"document(s) and missed {carry['carried']} that run "
                     f"{carry['previous_run']} had and that still answer 200; "
                     "they were re-checked and are included above. "
                     f"{carry['removed']} no longer resolve and "
                     f"{carry['unmeasured']} could not be requested. A "
                     "document neither run found is still invisible, so pair "
                     "the report with a search-engine sweep.")
            + "</td></tr>")
    for name, err in sorted((ctx.manifest["meta"].get("check_errors") or {}).items()):
        rows += (f"<tr><td>{escape(name)} (findings engine)</td>"
                 f"<td>error</td><td>{escape('this check crashed and produced no findings: ' + err)}</td></tr>")
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
        f"<tr><td style='white-space:nowrap'><code>{escape(m['key'])}</code></td>"
        f"<td>{escape(m['title'])}</td><td>{escape(m['about'])}</td></tr>"
        for m in MODULES)
    return (f"<p>Every module this tool runs, whether or not it produced a "
            f"finding.</p><div class='scroll'><table><thead><tr>"
            f"<th>Key</th><th>Area</th><th>What it looks at</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>")


REPORT_CSS = """
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  details.snippets { margin-top: 12px; }
  details.snippets summary { cursor: pointer; font-weight: 600; }
  details.snippets pre { background: #f0f2f5; padding: 10px 12px; border-radius: 6px;
                         overflow-x: auto; white-space: pre-wrap; font-size: 13px; }
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
           border-bottom: 1px solid #e4e7ea; overflow-wrap: break-word; }
  th { background: #f0f2f4; font-weight: 600; }
  table.kv th { width: 34%; background: #fafbfc; }
  /* 50 text lines (13px x 1.55), so a --standalone table of thousands of
     rows scrolls in its own box instead of stretching the page. */
  .scroll { overflow: auto; max-height: 1008px; margin: 12px 0 4px; }
  /* A collapsed border leaves a gap above a sticky header that rows show
     through; separate borders with no spacing close it. */
  .scroll table { border-collapse: separate; border-spacing: 0; }
  .scroll thead th { position: sticky; top: 0; }
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
    section.card, .tile { box-shadow: none; border: 1px solid #ccc; }
    .tile, tr { page-break-inside: avoid; }
    h2, h3 { page-break-after: avoid; }
    .scroll { overflow: visible; max-height: none; }
    a { color: #222; text-decoration: none; }
  }
"""


# Findings whose rows are measurements that change every run (counts,
# rates); they are compared by id alone.
DIFF_BY_ID_ONLY = {"transport-rate-limit", "integrity-sitemap-count", "integrity-core-ok",
                   "integrity-sitemap-lastmod"}


def _finding_keys(fid: str, evidence: List[Dict]) -> List[str]:
    """One key per evidence row: the finding id plus the row's first
    column, so a path finding with a new path counts as new."""
    if fid in DIFF_BY_ID_ONLY:
        return [fid]
    rows = [r for r in evidence if isinstance(r, dict) and r]
    return [f"{fid}|{next(iter(r.values()))}" for r in rows] or [fid]


def findings_diff(previous: List[Dict], current: List[Dict], module_status: Dict[str, str]) -> Dict:
    """What changed since the previous run, keyed per evidence row. A
    finding gone from a module that did not complete this time is
    "unmeasured", not resolved."""
    prev = {k: f for f in previous for k in _finding_keys(f["id"], f.get("evidence") or [])}
    cur = {k: f for f in current for k in _finding_keys(f["id"], f.get("evidence") or [])}
    def row(k, f):
        return {"id": f["id"], "severity": f["severity"], "title": f["title"],
                "item": k.split("|", 1)[1] if "|" in k else ""}
    gone = [(k, f) for k, f in prev.items() if k not in cur]
    def measured(f):
        module = Path(f.get("source") or "").stem
        return module_status.get(module, "ok") == "ok"
    return {"new": [row(k, f) for k, f in cur.items() if k not in prev],
            "resolved": [row(k, f) for k, f in gone if measured(f)],
            "unmeasured": [row(k, f) for k, f in gone if not measured(f)]}


def _since_last_run(ctx: RunContext, findings: List[Finding]) -> str:
    """The "Since the last run" card, and diff.json beside the report."""
    prev_name, prev = previous_run(ctx.run_dir, "findings.json", list)
    if not prev_name:
        return ""
    status = {k: v.get("status", "") for k, v in (ctx.manifest.get("modules") or {}).items()}
    cur = [{"id": f.fid, "severity": f.severity, "title": f.title, "source": f.source,
            "evidence": f.evidence} for f in findings]
    diff = findings_diff([f for f in prev if isinstance(f, dict) and "id" in f], cur, status)
    diff["previous_run"] = prev_name
    _, prev_vulns = previous_run(ctx.run_dir, "vulns.json", dict)
    vulns = ctx.data("vulns") or {}
    if prev_vulns and vulns:
        before, after = set(prev_vulns.get("plugins") or {}), set(vulns.get("plugins") or {})
        diff["plugins_added"], diff["plugins_removed"] = sorted(after - before), sorted(before - after)
        for part in ("core", "php"):
            old = (prev_vulns.get(part) or {}).get("detected", "")
            new = (vulns.get(part) or {}).get("detected", "")
            if old and new and old != new:
                diff[f"{part}_changed"] = f"{old} to {new}"
    (ctx.run_dir / "diff.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")
    lines = []
    for label, key in (("New", "new"), ("Gone since then", "resolved"),
                       ("Not measured this time", "unmeasured")):
        if diff[key]:
            items = "".join(f"<li>{escape(r['severity'])}: {escape(r['title'])}"
                            + (f" <code>{escape(str(r['item']))[:120]}</code>" if r["item"] else "")
                            + "</li>" for r in diff[key][:15])
            more = f"<li>and {len(diff[key]) - 15} more in diff.json</li>" if len(diff[key]) > 15 else ""
            lines.append(f"<h3>{label} ({len(diff[key])})</h3><ul>{items}{more}</ul>")
    for key, label in (("plugins_added", "Plugins added"), ("plugins_removed", "Plugins removed")):
        if diff.get(key):
            lines.append(f"<p><strong>{label}:</strong> {escape(', '.join(diff[key]))}</p>")
    for part, label in (("core", "WordPress core"), ("php", "PHP")):
        if diff.get(f"{part}_changed"):
            lines.append(f"<p><strong>{label}:</strong> {escape(diff[part + '_changed'])}</p>")
    body = "".join(lines) or "<p>No finding changed.</p>"
    return (f"<section class='card' id='since-last-run'><h2>Since the last run</h2>"
            f"<p>Compared with {escape(prev_name)}. A finding listed as not measured "
            f"was not checked this time, which is not the same as fixed.</p>{body}</section>")


# Effort per finding, cheapest first; matched on the longest id prefix.
EFFORT_ORDER = ["one setting", "header change", "file deletion", "plugin update", "developer task"]
EFFORT = {
    "headers-": "header change", "paths-": "file deletion", "paths-config-copy": "file deletion",
    "users-": "one setting", "users-rest": "developer task", "media-": "developer task",
    "docs-": "file deletion", "vulns-": "plugin update", "vulns-php": "one setting",
    "transport-xmlrpc": "one setting", "transport-registration": "one setting",
    "transport-http": "one setting", "transport-tls-legacy": "one setting",
    "transport-": "header change", "dns-": "one setting", "integrity-": "developer task",
    "leaks-secrets": "developer task", "leaks-": "one setting", "hygiene-": "one setting",
    "rest-": "developer task"}


def effort_of(fid: str) -> str:
    """The effort word for a finding id, from the longest matching prefix."""
    best = max((k for k in EFFORT if fid.startswith(k)), key=len, default="")
    return EFFORT.get(best, "developer task")


def this_week(findings: List[Finding], limit: int = 5) -> List[Finding]:
    """Up to five findings to do first: severity, then the cheapest fix.
    INFO is context, not a task."""
    tasks = [f for f in findings if f.severity != "INFO"]
    return sorted(tasks, key=lambda f: (SEVERITY_ORDER.index(f.severity),
                                        EFFORT_ORDER.index(effort_of(f.fid)), f.fid))[:limit]


def render_html(ctx: RunContext, findings: List[Finding]) -> Path:
    print_header("STAGE 3 - RENDER")
    site = ctx.site
    host = urllib.parse.urlparse(site).netloc or site
    # Privacy findings get their own section after the security ones, so a
    # tracker is never read as a vulnerability, and stay out of the tiles.
    privacy = [f for f in findings if f.fid.startswith("privacy-")]
    findings = [f for f in findings if not f.fid.startswith("privacy-")]
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
  {_snippet_block(finding.fid)}
</section>"""
    privacy_html, toc_privacy = "", ""
    if privacy:
        privacy_html = ("<section class='card' id='privacy'><h2>Privacy</h2><p>This "
                        "section is separate from the security findings above. It "
                        "reports what the pages do with visitor data: trackers, "
                        "cookies, consent wording, embeds and the privacy notice. "
                        "It is not a compliance verdict; which act applies depends "
                        "on who the visitors are, and a lawyer decides what each "
                        "item means. Nothing here is above low.</p></section>")
        for finding in privacy:
            anchor = f"f-{_slug(finding.fid)}"
            colour = SEVERITY_COLOURS[finding.severity]
            toc_privacy += (f"<li><a href='#{anchor}'><span class='pill' style='background:{colour}'>"
                            f"{escape(finding.severity[0])}</span>{escape(finding.title)}</a></li>")
            privacy_html += f"""
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
  {"<h2>Privacy</h2><ol>" + toc_privacy + "</ol>" if toc_privacy else ""}
  <h2>Reference</h2>
  <ol>{toc_appendix}</ol>
</nav>
<main>
  <div class='tiles'>{tiles}</div>
  {"<section class='card' id='this-week'><h2>Do these first</h2><ol>" + "".join(
      f"<li><a href='#f-{_slug(f.fid)}'>{escape(f.title)}</a> ({escape(effort_of(f.fid))})</li>"
      for f in this_week(findings)) + "</ol></section>" if this_week(findings) else ""}
  {_since_last_run(ctx, findings + privacy)}
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
  {privacy_html}
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
    } for f in findings + privacy], indent=2), encoding="utf-8")
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
    check("evidence is capped on the page",
          _evidence_table(big).count("<tr>") - 1, EVIDENCE_ROWS)
    check("evidence is whole in the finding (findings.json)",
          len(big.evidence), EVIDENCE_ROWS + 5)
    check("truncation is disclosed", "Showing" in _evidence_table(big), True)

    # 11b. --standalone lifts the cap. The flag rebinds the global, so this
    #      test does what main() does rather than calling Finding differently.
    saved = EVIDENCE_ROWS
    globals()["EVIDENCE_ROWS"] = EVIDENCE_ROWS_ALL
    try:
        whole = Finding("y2", "INFO", "t", "m", "r",
                        [{"n": i} for i in range(saved + 5)], "s")
        check("standalone keeps every row", len(whole.evidence), saved + 5)
        check("standalone under the cap shows no truncation note",
              "Showing" in _evidence_table(whole), False)
        over = Finding("y3", "INFO", "t", "m", "r",
                       [{"n": 1}], "s", count=EVIDENCE_ROWS_ALL + 1)
        check("standalone over the cap names no run directory",
              "run directory" in _evidence_table(over), False)
    finally:
        globals()["EVIDENCE_ROWS"] = saved

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
    check("a pre-RFC security.txt with Email: counts",
          security_txt_present(200, "Email: security@example.com\n"), True)
    check("an HTML 200 at security.txt does not",
          security_txt_present(200, "<html><body>Contact us</body></html>"), False)
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

    # 18b. A component whose version could not be read is still matchable
    #      against records that cover every release. The unfixed shape below
    #      is the common one: no lower bound, upper bound at the current
    #      release, no fix to update to. Reporting it as "not checked" is
    #      what this exists to stop.
    everywhere = {"vulnerability": [
        {"name": "unpatched, whole range",
         "operator": {"max_version": "1.7.1", "max_operator": "le",
                      "unfixed": "1"},
         "impact": {"cvss": {"score": "4.9"}},
         "source": [{"id": "CVE-2026-0002"}]},
        {"name": "old, long fixed",
         "operator": {"max_version": "1.2.4", "max_operator": "lt"},
         "impact": {}, "source": []},
        {"name": "only recent releases",
         "operator": {"min_version": "1.5", "min_operator": "ge",
                      "max_version": "1.7.1", "max_operator": "le"},
         "impact": {}, "source": []},
    ]}
    everywhere_rows = _every_release_rows(everywhere, "1.7.1")
    check("a whole-range record matches with no version detected",
          [r["name"] for r in everywhere_rows], ["unpatched, whole range"])
    check("no current release means no whole-range claim",
          _every_release_rows(everywhere, ""), [])
    check("an unfixed record never names its own range as the fix",
          fix_text(everywhere_rows[0]), "no fix published")
    check("a `< x` record names x as the fix",
          fix_text({"fixed_in": "1.2.4", "max_operator": "lt"}), "1.2.4")
    check("a `<= x` record does not name x as the fix",
          fix_text({"fixed_in": "1.7.1", "max_operator": "le"}),
          "a release later than 1.7.1")

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
    check("a probe that redirects to another page is not the file, even on a 404 site",
          path_is_exposed("/wp-config.php~", 200, "<?php define('DB_NAME')",
                          {"status": 404, "stable": True, "redirects_unknown_paths": False},
                          301, "https://example.test/reference/wp-config/"), False)
    check("a redirect to the same path with a slash still counts",
          path_is_exposed("/phpmyadmin/", 200, "<h1>Index of /phpmyadmin</h1>",
                          {"status": 404, "stable": True, "redirects_unknown_paths": False},
                          301, "/phpmyadmin"), True)
    check("an HTML document at a config-backup path is not the backup",
          path_is_exposed("/wp-config.php~", 200,
                          "<!DOCTYPE html><html><body>define('DB_NAME') docs "
                          "&lt;?php</body></html>", None, 200), False)
    check("a real config backup still is",
          path_is_exposed("/wp-config.php~", 200,
                          "<?php\ndefine('DB_NAME', 'wp');", None, 200), True)
    check("a page at /readme.html that is not WordPress's is not the readme",
          path_is_exposed("/readme.html", 200, "<h1>readme's profile</h1>",
                          None, 200), False)
    check("the real readme still is",
          path_is_exposed("/readme.html", 200, "<h1>WordPress</h1>", None, 200),
          True)
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
    jsd = '<h1>Hello</h1><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>'
    check("cloudflare js detections on a 200 is not a challenge",
          edge_identity({"cf-ray": "abc"}, jsd, 200)["challenged"], False)
    check("the same markup on a 403 is",
          edge_identity({"cf-ray": "abc"}, jsd, 403)["challenged"], True)
    check("cf-mitigated: challenge is a challenge on any status",
          edge_identity({"cf-ray": "abc", "cf-mitigated": "challenge"}, "", 200)["challenged"], True)
    sucuri = edge_identity({"server": "nginx"}, "<script>sucuri_cloudproxy_js='';</script>", 200)
    check("sucuri's js challenge is a challenge on a 200, and names Sucuri",
          (sucuri["challenged"], sucuri["edge"]), (True, ["Nginx", "Sucuri"]))

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
        globals()["fetch"] = lambda *a, **k: (200, {}, (
            "Stable tag: 1.57.2\n== Changelog ==\n= 1.57.3 ( 2026-09-17 ) =\n"
            "= 1.57.2.1 ( 2026-09-17 ) =\n= 1.57.2 ( 2026-08-27 ) =\n"))
        check("a changelog newer than the stable tag wins (Forminator 1.57.3)",
              _readme_stable_tag("https://x", "p"), "1.57.3")
        check("the overridden stable tag is kept for the disputed check",
              _readme_probe("https://x", "p"), ("1.57.3", 200, "1.57.2"))
        globals()["fetch"] = lambda *a, **k: (200, {}, (
            "Stable tag: 4.2.1\n== Changelog ==\n= 4.2.1 =\n= 4.2.0 =\n"))
        check("an older changelog never lowers the stable tag",
              _readme_stable_tag("https://x", "p"), "4.2.1")
        globals()["fetch"] = lambda *a, **k: (200, {}, "Stable tag: trunk\n")
        check("trunk is not a version", _readme_stable_tag("https://x", "p"), "")
        globals()["fetch"] = lambda *a, **k: (200, {}, "<html>soft 404</html>")
        check("an HTML body is not a readme", _readme_stable_tag("https://x", "p"), "")
        globals()["fetch"] = lambda *a, **k: (200, {}, "/*\nTheme Name: Foo\nTemplate: bar\nVersion: 1.2.3\n*/")
        style = _theme_style("https://x", "foo")
        check("theme style.css yields version and parent",
              (style["version"], style["parent"]), ("1.2.3", "bar"))
        globals()["fetch"] = lambda *a, **k: (403, {}, "<html>blocked</html>")
        check("a WAF block is reported as its status, not as an absent readme",
              _readme_probe("https://x", "p"), ("", 403, ""))
    finally:
        globals()["fetch"] = real_fetch2

    # 28. A withdrawn slug seen only as a REST namespace is a question, not a
    #     finding. Carbon Fields, closed in 2019 at the author's request, is
    #     still shipping on GitHub and is bundled rather than installed.
    def _closed_ctx(source, slug="carbon-fields"):
        vulns = {"plugins": {slug: {"source": source, "pages": 0,
                                    "detected_versions": [], "covered": True,
                                    "wporg": {"closed": True, "found": True,
                                              "closed_date": "2019-02-06",
                                              "closed_reason": "Author Request"}}},
                 "themes": {}, "core": {}}

        class _C:
            def data(self, key):
                return vulns if key == "vulns" else {}
        return _C()

    ns_only = [f for f in check_vulns(_closed_ctx("rest namespace"))
               if f.fid == "vulns-closed"]
    check("a namespace-only closure is medium, not high",
          ns_only[0].severity if ns_only else "", "MEDIUM")
    check("and the report says how it was seen",
          "REST namespace" in ns_only[0].evidence[0]["How it was seen"], True)
    installed = [f for f in check_vulns(_closed_ctx("assets"))
                 if f.fid == "vulns-closed"]
    check("a closure evidenced by asset URLs is still high",
          installed[0].severity if installed else "", "HIGH")

    # 28b. PHP from X-Powered-By, matched against the branch record. The
    #      record shape is wpvulnerability's /php/8.3.35/ as of 2026-10-22:
    #      php2shell is "< 8.3.36" and scored only under cvss3.
    check("PHP version read from X-Powered-By",
          _php_version({"x-powered-by": "PHP/8.3.35"}), "8.3.35")
    check("a Server header with no PHP gives nothing",
          _php_version({"server": "LiteSpeed"}), "")
    php2shell = {"name": "PHP 8.3", "date_end": "2027-12-31", "vulnerability": [
        {"name": "PHP 8.3 < 8.3.36",
         "source": [{"id": "CVE-2026-109618", "link": "https://x/"}],
         "operator": {"max_version": "8.3.36", "max_operator": "lt", "unfixed": 0},
         "impact": {"cvss3": {"score": "9.2", "vector": "CVSS:3.1/AV:N"}}}]}
    rows, _ = _vuln_rows(php2shell, "8.3.35")
    check("a cvss3-only record keeps its score", rows[0]["score"] if rows else 0, 9.2)
    check("8.3.36 is clear of php2shell", _vuln_rows(php2shell, "8.3.36")[0], [])

    def _php_ctx(sources, end="2027-12-31", version="8.3.35"):
        rows, _ = _vuln_rows(php2shell, version)
        vulns = {"plugins": {}, "themes": {}, "core": {},
                 "php": {"detected": version, "sources": sources,
                         "covered": True, "branch_end": end,
                         "vulnerabilities": rows, "undecidable": 0}}

        class _C:
            def data(self, key):
                return vulns if key == "vulns" else {}
        return _C()

    def _sev(ctx, fid):
        hits = [f.severity for f in check_vulns(ctx) if f.fid == fid]
        return hits[0] if hits else ""
    live = {"homepage (cache-busted)": "8.3.35"}
    check("php2shell on a live reading is critical",
          _sev(_php_ctx(live), "vulns-php"), "CRITICAL")
    check("a cached-only reading is capped",
          _sev(_php_ctx({"homepage": "8.3.35"}), "vulns-php"), "MEDIUM")
    check("the patched release raises nothing",
          _sev(_php_ctx({"homepage (cache-busted)": "8.3.36"}, version="8.3.36"),
               "vulns-php"), "")
    check("an end-of-life branch is high on its own",
          _sev(_php_ctx({"homepage (cache-busted)": "7.4.33"}, end="2022-11-28",
                        version="7.4.33"), "vulns-php-eol"), "HIGH")
    win = {"name": "PHP 7.4", "date_end": "2022-11-28", "vulnerability": [
        {"name": "PHP 7.4 <= 7.4.33 (unfixed)",
         "source": [{"id": "CVE-2024-4577", "description":
                     "when using Apache and PHP-CGI on Windows"}],
         "operator": {"max_version": "7.4.33", "max_operator": "le", "unfixed": 1},
         "impact": {"cvss3": {"score": "9.8"}}}]}
    win_rows, _ = _vuln_rows(win, "7.4.33")
    win_rows = [dict(r, windows_only=True) for r in win_rows]
    check("the Windows pattern matches CVE-2024-4577's wording",
          bool(WINDOWS_ONLY.search(win["vulnerability"][0]["source"][0]["description"])),
          True)
    check("and not 'some systems, including Windows'",
          bool(WINDOWS_ONLY.search("on some systems, including Windows, can")), False)

    def _win_ctx(windows_server):
        vulns = {"plugins": {}, "themes": {}, "core": {},
                 "php": {"detected": "7.4.33", "covered": True,
                         "sources": {"homepage (cache-busted)": "7.4.33"},
                         "branch_end": "2022-11-28", "vulnerabilities": win_rows,
                         "windows_server": windows_server, "undecidable": 0}}

        class _C:
            def data(self, key):
                return vulns if key == "vulns" else {}
        return _C()
    check("a Windows-only CVE does not make a Linux host critical",
          _sev(_win_ctx(False), "vulns-php"), "LOW")
    check("it does on a Windows server",
          _sev(_win_ctx(True), "vulns-php"), "CRITICAL")
    eol = [f for f in check_vulns(_win_ctx(False)) if f.fid == "vulns-php-eol"]
    check("the Windows note stays out of the end-of-life finding",
          "Windows" in (eol[0].meaning if eol else "Windows"), False)
    check("a supported branch is not end-of-life",
          _sev(_php_ctx(live), "vulns-php-eol"), "")
    check("8.3 past active support is security-only, INFO",
          _sev(_php_ctx({"homepage (cache-busted)": "8.3.36"}, version="8.3.36"),
               "vulns-php-security-only"), "INFO")
    check("and not end-of-life",
          _sev(_php_ctx({"homepage (cache-busted)": "8.3.36"}, version="8.3.36"),
               "vulns-php-eol"), "")
    check("7.4 is still end-of-life, not security-only",
          (_sev(_php_ctx({"homepage (cache-busted)": "7.4.33"}, end="2022-11-28",
                         version="7.4.33"), "vulns-php-eol"),
           _sev(_php_ctx({"homepage (cache-busted)": "7.4.33"}, end="2022-11-28",
                         version="7.4.33"), "vulns-php-security-only")), ("HIGH", ""))
    check("an unknown branch raises neither",
          [f.fid for f in check_vulns(_php_ctx({"homepage (cache-busted)": "9.0.1"},
                                               end="2031-12-31", version="9.0.1"))
           if f.fid in ("vulns-php-eol", "vulns-php-security-only")], [])

    # 29. SPF with no sender is correct for a domain that sends no mail and
    #     wrong for one with an MX. Only the second is a finding.
    def _dns_ctx(spf, mx):
        class _C:
            def data(self, key):
                return {"domain": "x.test", "spf": spf, "mx": mx,
                        "dmarc": "v=DMARC1;p=reject;rua=mailto:r@x.test"}
        return _C()

    check("no senders plus an MX is reported",
          [f.fid for f in check_dns(_dns_ctx("v=spf1 -all", ["1 mx.test."]))],
          ["dns-spf-senders"])
    check("no senders and no MX is the correct record, and silent",
          [f.fid for f in check_dns(_dns_ctx("v=spf1 -all", []))], [])
    check("a record that names a sender is not reported",
          [f.fid for f in check_dns(
              _dns_ctx("v=spf1 include:_spf.google.com ~all", ["1 mx.test."]))],
          [])

    # 30. The version a component is running is the highest one seen, not the
    #     lowest. A live plugin published four versions across its own scripts
    #     on one page; measuring from the lowest matched a record covering
    #     everything below a long-fixed release and printed a CVSS 9.8 for a
    #     plugin that was current. The same reading called a second plugin
    #     seven releases behind while its assets ran ahead of the directory.
    spread = ["1.0.0", "1.1.2", "1.21.0", "2.0.0.2"]
    check("the running version is the highest seen",
          running_version(spread), "2.0.0.2")
    check("an unorderable string does not become the version",
          running_version(["latest", "1.4"]), "1.4")
    check("no ordered version yields nothing", running_version(["latest"]), "")
    check("the core version stamped on a plugin file is not the plugin's",
          running_version(without_core(["2.3.1", "7.1.4"], {"7.1.4"})), "2.3.1")
    check("a plugin seen only at the core version has no version",
          running_version(without_core(["7.1.4"], {"7.1.4"})), "")
    ranges = {"vulnerability": [
        {"name": "old", "operator": {"max_version": "1.7.7", "max_operator": "lt"},
         "impact": {"cvss": {"score": "9.8"}}, "source": []},
        {"name": "real", "operator": {"max_version": "2.0.0.3", "max_operator": "lt"},
         "impact": {"cvss": {"score": "5.3"}}, "source": []},
    ]}
    hit, _ = _vuln_rows(ranges, running_version(spread))
    check("a stale ver= on one file does not match an old advisory",
          [r["name"] for r in hit], ["real"])
    real_fetch3 = fetch
    try:
        globals()["fetch"] = lambda *a, **k: (200, {}, json.dumps({
            "slug": "example-plugin", "name": "Example", "version": "3.54.15",
            "versions": {"3.54.6": "", "3.54.15": ""}}))
        ahead = _currency("https://example.test", ["3.55.1-0", "3.54.6"])
        check("assets ahead of the directory are not behind it",
              (ahead["outdated"], ahead.get("releases_behind", 0)), (False, 0))
        behind = _currency("https://example.test", ["3.54.6"])
        check("a genuinely old version is still counted",
              behind["outdated"], True)
    finally:
        globals()["fetch"] = real_fetch3

    # 31. A document an earlier run found and this run's discovery missed.
    #     Twice on one live site a re-run lost the 12 known orphans and the
    #     report read as a fix. Still 200 is carried forward, a 404 is
    #     reported as removed, and neither is silently dropped.
    import tempfile
    real_fetch4 = fetch
    with tempfile.TemporaryDirectory() as tmp:
        base = "https://x.test/wp-content/uploads/"
        prev_dir = Path(tmp) / "x_test_20260901_000000"
        cur_dir = Path(tmp) / "x_test_20260910_000000"
        other = Path(tmp) / "y_test_20260905_000000"   # another host
        for d in (prev_dir, cur_dir, other):
            d.mkdir()
        (prev_dir / "documents.json").write_text(json.dumps([
            {"url": base + "a.pdf", "status": 200},
            {"url": base + "2018/orphan.pdf", "status": 200},
            {"url": base + "2018/gone.pdf", "status": 200}]))
        (other / "documents.json").write_text(json.dumps(
            [{"url": base + "y.pdf", "status": 200}]))
        (cur_dir / "media.json").write_text(json.dumps(
            {"all_urls": [base + "a.pdf"], "documents": [{"url": base + "a.pdf"}]}))
        args = argparse.Namespace(url=[], site="https://x.test")
        try:
            globals()["fetch"] = lambda url, **k: (
                (404 if "gone" in url else 200),
                {"content-type": "application/pdf"}, "")
            ctx = RunContext(cur_dir, args)
            ctx.manifest["modules"]["media"] = {"status": "ok"}
            collect_documents(ctx)
            rows = {r["url"].rsplit("/", 1)[1]: r for r in ctx.data("documents")}
            check("carry: previous run's missed orphan is back, marked",
                  (rows["orphan.pdf"]["status"],
                   rows["orphan.pdf"].get("carried_from")),
                  (200, "x_test_20260901_000000"))
            check("carry: a URL no longer 200 is reported as removed",
                  rows["gone.pdf"].get("removed_since"), "x_test_20260901_000000")
            check("carry: another host's run is not inherited",
                  "y.pdf" in rows, False)
            check("carry: discovered, carried, removed counts",
                  {k: ctx.manifest["meta"]["documents_carry"][k]
                   for k in ("discovered", "carried", "removed")},
                  {"discovered": 1, "carried": 1, "removed": 1})
            fids = [f.fid for f in check_documents(ctx)]
            check("carry: orphan and removed findings both present",
                  ("docs-orphan" in fids, "docs-removed" in fids,
                   "docs-dead" in fids), (True, True, False))
            # The same documents with the media walk not complete: absence
            # from it proves nothing about the library.
            ctx.manifest["modules"]["media"] = {"status": "partial"}
            ctx._cache.clear()
            collect_documents(ctx)
            fids = [f.fid for f in check_documents(ctx)]
            check("carry: no orphan claim without a complete media walk",
                  ("docs-orphan" in fids, "docs-library-unknown" in fids,
                   {r["in_library"] for r in ctx.data("documents")}),
                  (False, True, {None}))
            # The carried row persists: a third run whose discovery misses
            # it again still inherits it from this run.
            nxt = Path(tmp) / "x_test_20260911_000000"
            nxt.mkdir()
            (nxt / "media.json").write_text((cur_dir / "media.json").read_text())
            ctx3 = RunContext(nxt, args)
            collect_documents(ctx3)
            rows3 = {r["url"].rsplit("/", 1)[1]: r for r in ctx3.data("documents")}
            check("carry: inherited again from the carrying run",
                  rows3["orphan.pdf"].get("carried_from"), "x_test_20260910_000000")
            check("carry: removed keeps the run it went missing after",
                  rows3["gone.pdf"].get("removed_since"), "x_test_20260901_000000")
            # No previous run: nothing carried, nothing crashes.
            lone = Path(tmp) / "z_test_20260910_000000"
            lone.mkdir()
            (lone / "media.json").write_text((cur_dir / "media.json").read_text())
            ctx4 = RunContext(lone, args)
            collect_documents(ctx4)
            check("carry: no previous run yields only discovered rows",
                  (len(ctx4.data("documents")),
                   ctx4.manifest["meta"]["documents_carry"]["previous_run"]),
                  (1, ""))
        finally:
            globals()["fetch"] = real_fetch4

    # 32. A rate-limit refusal is never the site's answer. Three live runs
    #     on 2026-09-23 read 429s as "closed, the safer state", learned a
    #     429 as the not-found shape, and exited 0 with checks unrun.
    g = globals()
    saved = {k: g[k] for k in ("calibrate_missing", "verify_calibration",
                               "fetch_json", "fetch", "fetch_no_redirect",
                               "_slowdown", "_consecutive_ok")}
    try:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = RunContext(Path(tmp), argparse.Namespace(
                url=[], site="https://x.test"))
            g["calibrate_missing"] = lambda site: {"status": 429}
            g["verify_calibration"] = lambda site, sig: {
                "trustworthy": True, "ran": True, "note": ""}
            check("429: calibration learned from refusals is an error",
                  collect_calibration(ctx)[0], "error")
            g["fetch_json"] = lambda url: (429, {}, None)
            g["fetch_no_redirect"] = lambda url: (404, {})
            g["fetch"] = lambda url, **kw: (404, {}, "")
            check("429: a refused media probe is an error, not closed",
                  collect_media(ctx)[0], "error")
            check("429: a refused users endpoint is partial, not ok",
                  collect_users(ctx)[0], "partial")
        g["_slowdown"], g["_consecutive_ok"] = 16.0, 0
        for _ in range(RATE_LIMIT_RECOVER):
            _served()
        check("429: the pace halves after a run of clean requests",
              g["_slowdown"], 8.0)
        real_rd = g["REQUEST_DELAY"]
        g["REQUEST_DELAY"], g["_slowdown"] = 2.0, 16.0
        check("429: the slowdown never waits more than 8 s", _delay(), 8.0)
        g["REQUEST_DELAY"] = real_rd
    finally:
        g.update(saved)
    # 33. Two sources for one bug, one missing the lower bound (the live
    #     Oxygen record, 2026-09-23). 4.9.8 is outside 6.0-6.1.1.
    loose = {"name": "Oxygen < 6.1.2", "operator": {
        "max_version": "6.1.2", "max_operator": "lt"}}
    tight = {"name": "Oxygen 6.0 - 6.1.1", "operator": {
        "min_version": "6.0", "min_operator": "ge",
        "max_version": "6.1.2", "max_operator": "lt"}}
    rows, undecided = _vuln_rows({"vulnerability": [loose, tight]}, "4.9.8")
    check("sibling bound: 4.x is not matched by a 6.x bug", len(rows), 0)
    check("sibling bound: the loose record is undecidable, not dropped",
          undecided, 1)
    rows, _ = _vuln_rows({"vulnerability": [loose, tight]}, "6.1.0")
    check("sibling bound: a version inside the range still matches",
          len(rows), 2)
    rows, _ = _vuln_rows({"vulnerability": [loose]}, "4.9.8")
    check("sibling bound: an unbounded record alone still matches",
          len(rows), 1)

    # 34. Config copies. A plain-text copy needs the config's content; a
    #     copy ending in .php is run, not sent, so an empty 200 is the hit,
    #     but only on a site where an unknown .php answers differently.
    check("config copy: a plain-text wp-config.old is readable",
          path_is_exposed("/wp-config.old", 200,
                          "<?php\ndefine('DB_PASSWORD', 'x');", None, 200), True)
    check("config copy: an HTML page at wp-config.bak is not the file",
          path_is_exposed("/wp-config.bak", 200,
                          "<!DOCTYPE html><html>DB_NAME</html>", None, 200), False)
    check("config copy: an empty 200 is a run copy",
          exec_copy_is_hit(200, 200, ""), True)
    check("config copy: whitespace only is still empty",
          exec_copy_is_hit(200, 200, "\n  \n"), True)
    check("config copy: a soft 404 has a body",
          exec_copy_is_hit(200, 200, "<h1>Page not found</h1>"), False)
    check("config copy: a WAF page served 200 has a body",
          exec_copy_is_hit(200, 200, "<title>Just a moment...</title>"), False)
    check("config copy: a redirect to an empty page is not the file",
          exec_copy_is_hit(200, 301, ""), False)
    check("config copy: a 403 is not a hit", exec_copy_is_hit(403, 403, ""), False)

    def fake_site(answer):
        """fetch/fetch_no_redirect pair answering answer(path) -> (status, body)."""
        def path_of(url):
            return urllib.parse.urlparse(url).path
        return ((lambda url, **kw: (answer(path_of(url))[0], {},
                                    answer(path_of(url))[1])),
                (lambda url, **kw: (answer(path_of(url))[0], {})))

    real_files = {"/wp-load.php": "", "/wp-content/index.php": "",
                  "/wp-includes/version.php": "",
                  "/wp-config_old.php": "", "/robots.txt": "User-agent: *"}
    denies_config = lambda p: ((403, "<h1>403 Forbidden</h1>") if p == "/wp-config.php.old"
                        else (200, real_files[p]) if p in real_files
                        else (404, "<h1>Not found</h1>"))
    empty_everywhere = lambda p: (200, "")
    soft_404 = lambda p: ((200, "") if p in real_files
                          else (200, "<h1>Nothing found</h1>"))
    no_control = lambda p: ((403, "denied") if p in EXEC_CONTROL_PATHS
                            else denies_config(p))
    control_has_body = lambda p: ((200, "Silence") if p == "/wp-load.php"
                                  else denies_config(p))
    g = globals()
    saved = {k: g[k] for k in ("fetch", "fetch_no_redirect")}
    try:
        def run(site_fn):
            g["fetch"], g["fetch_no_redirect"] = fake_site(site_fn)
            with tempfile.TemporaryDirectory() as tmp:
                ctx = RunContext(Path(tmp), argparse.Namespace(
                    url=[], site="https://x.test"))
                ctx.write("calibration", {"signature": {
                    "status": site_fn("/zz.zip")[0], "no_redirect_status":
                    site_fn("/zz.zip")[0], "redirects_unknown_paths": False,
                    "stable": True, "fingerprint":
                    body_fingerprint(site_fn("/zz.zip")[1], "zz.zip")},
                    "control": {}})
                status = collect_paths(ctx)[0]
                found = {f.fid: f for f in check_paths(ctx)}
                rows = {r["path"]: r for r in ctx.data("paths")}
                return status, found, rows

        status, found, rows = run(denies_config)
        check("config copy: the empty-200 copy is reported MEDIUM",
              (found.get("paths-config-copy") and
               found["paths-config-copy"].severity,
               len(found["paths-config-copy"].evidence)
               if "paths-config-copy" in found else 0), ("MEDIUM", 1))
        check("config copy: it is not also filed as an empty path",
              "paths-empty" in found, False)
        check("config copy: an absent copy reads not readable",
              rows["/wp-config-old.php"]["verdict"], "not readable")
        check("config copy: positive control proved, module ok",
              status, "ok")

        status, found, rows = run(empty_everywhere)
        check("config copy: a site with an empty 200 for every path reports nothing",
              "paths-config-copy" in found, False)
        check("config copy: and says the check did not run",
              (status, rows["/wp-config_old.php"]["verdict"]),
              ("partial", "not checked"))

        status, found, _ = run(soft_404)
        check("config copy: a soft-404 site still finds the real copy",
              "paths-config-copy" in found, True)

        status, found, _ = run(control_has_body)
        check("config copy: a failed positive control stands the rule down",
              ("paths-config-copy" in found, status), (False, "partial"))

        status, found, _ = run(no_control)
        check("config copy: no control answering still reports, as partial",
              ("paths-config-copy" in found, status), (True, "partial"))
    finally:
        g.update(saved)

    check("--delay is read as seconds",
          parse_args(["--delay", "2", "--selftest"]).delay, 2.0)

    # 35. The 2026-10-21 review: each shape below produced a wrong report.
    check("xml-rpc: the stock 405 refusal is answering",
          xmlrpc_answering(405, "XML-RPC server accepts POST requests only."), True)
    check("xml-rpc: a bare 405 is not", xmlrpc_answering(405, "Method Not Allowed"), False)
    check("xml-rpc: a block page is not", xmlrpc_answering(403, "<html>"), False)
    check("cookie: words in the value are not attributes",
          cookie_flags("session=secure-httponly-samesite; Path=/"),
          {"secure": False, "httponly": False, "samesite": False})
    check("cookie: real attributes, any case",
          cookie_flags("a=b; Expires=Wed, 21 Oct 2026 07:28:00 GMT; SECURE; "
                       "HttpOnly; SameSite=Lax"),
          {"secure": True, "httponly": True, "samesite": True})
    stamp = "Oct 21 12:00:00 2026 GMT"
    noon = ssl.cert_time_to_seconds(stamp)
    check("tls: lapsing later today is 0 days, not expired",
          (_tls_time_left(stamp, noon - 3600)["days_left"],
           _tls_time_left(stamp, noon - 3600)["seconds_left"] > 0), (0, True))
    check("tls: an hour past notAfter is expired",
          _tls_time_left(stamp, noon + 3600)["seconds_left"] < 0, True)
    check("scope: a sitemap child on another host is refused",
          _in_scope("http://127.0.0.1:9999/internal.xml", "https://x.test"), False)
    check("scope: the www. variant is the same site",
          _in_scope("https://www.x.test/page/", "https://x.test"), True)
    check("scope: a non-http URL is refused",
          _in_scope("file:///etc/passwd", "https://x.test"), False)
    check("resume: www. and scheme do not change the site",
          _site_key("http://WWW.x.test/") == _site_key("https://x.test"), True)
    check("resume: another host is another site",
          _site_key("https://a.test") == _site_key("https://b.test"), False)
    import contextlib
    import io
    for bad in (["--only", "vulnz", "--site", "x.test"],
                ["--delay", "nan", "--site", "x.test"]):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(bad)
            check(f"cli: {bad[0]} {bad[1]} is refused", "accepted", "refused")
        except SystemExit:
            pass
    try:
        normalise_site("https://x.test/blog?x=1")
        check("cli: a site with a query is refused", "accepted", "refused")
    except ValueError:
        pass
    check("version: beta < rc", version_key("2.0-beta1") < version_key("2.0-rc2"), True)
    check("version: rc1 < rc2", version_key("2.0-rc1") < version_key("2.0-rc2"), True)
    check("version: rc < release", version_key("2.0-rc2") < version_key("2.0"), True)
    check("version: build metadata is the release",
          version_key("2.0+build1") == version_key("2.0"), True)
    check("version: a fifth segment counts",
          version_key("1.0.0.0.1") < version_key("1.0.0.0.2"), True)
    check("version: 1.10 above 1.9, 6.6 equal to 6.6.0",
          (version_key("1.10") > version_key("1.9"),
           version_key("6.6") == version_key("6.6.0")), (True, True))
    check(".env: a challenge fragment is not an env file",
          content_matches("/.env", "<div>Please wait token=abc</div>"), False)
    check(".env: a real one is",
          content_matches("/.env", "# app\nAPP_ENV=production\nDB_PASSWORD=x\n"), True)
    check(".htpasswd: an error line is not a password file",
          content_matches("/.htpasswd", "Access denied: please retry"), False)
    check(".htpasswd: a real one is",
          content_matches("/.htpasswd", "admin:$apr1$abc123$Zx9QxQxQxQxQxQxQ\n"), True)
    check("config source: the text of wp-config is a leak",
          config_source_leaked(200, "<?php define('DB_NAME','x'); "
                                    "define('DB_PASSWORD','y');"), True)
    check("config source: a page naming DB_PASSWORD is not",
          config_source_leaked(200, "<p>Set DB_PASSWORD in wp-config</p>"), False)

    # A plugin and a theme sharing a slug both keep their findings, and a
    # core CVE lookup does not wait on the release list.
    with tempfile.TemporaryDirectory() as tmp:
        ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
        row = {"cve": "CVE-1", "name": "n", "score": 9.0, "severity": "CRITICAL",
               "affected_version": "1.0"}
        ctx.write("vulns", {"core": {}, "plugins": {"demo": {
            "vulnerabilities": [row], "detected_versions": ["1.0"],
            "covered": True, "wporg": {"found": True}}},
            "themes": {"demo": {"vulnerabilities": [], "detected_versions": ["1"],
                                "covered": True, "wporg": {"found": True}}}})
        found = {f.fid: f for f in check_vulns(ctx)}
        check("slug collision: the plugin's advisory survives the theme",
              any("CVE-1" in json.dumps(f.evidence) for f in found.values()), True)
    saved_api = {k: g[k] for k in ("_wporg", "_wpvuln")}
    try:
        g["_wporg"] = lambda url: None
        g["_wpvuln"] = lambda kind, slug: {"covered": True, "error": "",
                                          "record": {"vulnerability": []}}
        with tempfile.TemporaryDirectory() as tmp:
            ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
            ctx.write("headers", {"core_versions": {"generator": "6.0"}})
            collect_vulns(ctx)
            check("core: CVE lookup runs with the release list down",
                  ctx.data("vulns")["core"].get("covered"), True)
    finally:
        g.update(saved_api)

    # Carried documents: only 404/410 is removal; 429/403/503 are unmeasured.
    with tempfile.TemporaryDirectory() as tmp:
        prev = Path(tmp) / "x_test_20261001_000000"
        cur = Path(tmp) / "x_test_20261002_000000"
        prev.mkdir(); cur.mkdir()
        codes = {"a": 429, "b": 403, "c": 503, "d": 404, "e": 410}
        (prev / "documents.json").write_text(json.dumps(
            [{"url": f"https://x.test/{k}.pdf", "status": 200} for k in codes]))
        saved_fetch = g["fetch"]
        try:
            g["fetch"] = lambda url, **k: (
                codes[url.rsplit("/", 1)[1][0]], {"content-type": "application/pdf"}, "")
            ctx = RunContext(cur, argparse.Namespace(url=[], site="https://x.test"))
            collect_documents(ctx)
            carry = ctx.manifest["meta"]["documents_carry"]
            check("carry: only 404 and 410 count as removed",
                  (carry["removed"], carry["unmeasured"]), (2, 3))
            # A PDF URL that lands on an HTML page is not a document.
            g["fetch"] = lambda url, **k: (200, {"content-type": "text/html"}, "")
            (Path(tmp) / "z").mkdir()
            ctx2 = RunContext(Path(tmp) / "z", argparse.Namespace(
                url=["/staff-handbook.pdf"], site="https://x.test"))
            collect_documents(ctx2)
            check("documents: a redirect to an HTML page raises nothing",
                  [f.fid for f in check_documents(ctx2)], [])
        finally:
            g["fetch"] = saved_fetch

    # Sitemap cap is disclosed; a plugin path with no ?ver= is inventoried.
    sitemap = "<urlset>" + "".join(f"<loc>https://x.test/p{i}/</loc>"
                                   for i in range(120)) + \
              "<loc>http://127.0.0.1:9999/internal/</loc></urlset>"
    saved_fetch = g["fetch"]
    try:
        g["fetch"] = lambda url, **k: (
            (200, {}, sitemap) if "sitemap" in url else
            (404, {}, "") if "readme.txt" in url else
            (200, {}, "<script src='/wp-content/plugins/demo/app.js'></script>"))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
            status, _, note = collect_assets(ctx)
            data = ctx.data("assets")
            check("assets: sitemap total counted before the cap, off-site URL dropped",
                  (data["pages_checked"], data["pages_in_sitemap"],
                   "120 pages" in note), (ASSET_MAX_PAGES, 120, True))
            check("assets: a versionless plugin path is inventoried",
                  "demo" in data["plugins"], True)
    finally:
        g["fetch"] = saved_fetch

    # nuclei-derived checks: content shape, PHP-printed evidence, gating.
    wf = "/wp-content/wflogs/config.php"
    check("wflogs: source served as text is readable",
          path_is_exposed(wf, 200, "<?php exit('Access denied'); __halt_compiler(); ?>\na:1:{s:7:\"authKey\";}", None, 200), True)
    check("wflogs: PHP running the file is not",
          path_is_exposed(wf, 200, "Access denied", None, 200), False)
    fatal = ("<br />\n<b>Fatal error</b>: Uncaught Error: Call to undefined "
             "function _deprecated_file() in /home/u1/public_html/wp-includes/rss.php:19")
    check("fpd: a fatal error naming the path is reported",
          path_is_exposed(FPD_PATH, 200, fatal, None, 200), True)
    check("fpd: an empty 200 is display_errors off, not a finding",
          path_is_exposed(FPD_PATH, 200, "", None, 200), False)
    check("fpd: a 200 without a path is not a finding",
          path_is_exposed(FPD_PATH, 200, "Forbidden by policy", None, 200), False)
    check("wp-cli.yml: YAML keys pass, prose does not",
          (content_matches("/wp-cli.yml", "path: wp\nurl: https://x.test\n"),
           content_matches("/wp-cli.yml", "Request blocked")), (True, False))
    check("wp-env: JSON with wp-env keys passes, other JSON does not",
          (content_matches("/.wp-env.json", '{"core": null, "plugins": ["."]}'),
           content_matches("/.wp-env.json", '{"error": "denied"}')), (True, False))
    check("registration: link present is open, absent is closed",
          (registration_open(200, '<a href="https://x.test/wp-login.php?action=register">Register</a>'),
           registration_open(200, '<a href="https://x.test/wp-login.php?action=lostpassword">'),
           registration_open(404, 'action=register"')), (True, False, False))
    check("wpcom takeover: unclaimed page detected, live site not",
          (wpcom_unclaimed("<p>Do you want to register <em>x.wordpress.com</em>?</p>"),
           wpcom_unclaimed("<h1>My blog</h1>")), (True, False))
    check("wflogs: rules.php source carries the WFWAF guard",
          content_matches("/wp-content/wflogs/rules.php",
                          "<?php\nif (!defined('WFWAF_VERSION')) {\n\texit('Access denied');"), True)
    check("fpd: an error page echoing the request path is not a disclosure",
          path_is_exposed(FPD_PATH, 200, "Fatal error: the page /wp-includes/rss.php could not be served", None, 200), False)
    check("fpd: empty answer says so in the appendix",
          path_verdict(FPD_PATH, 200, "", False, 200), "answered, nothing printed")
    check("wp-cli.yml: a plain-text block page is not the config",
          content_matches("/wp-cli.yml", "Error: Request blocked by policy"), False)
    log = "/wp-content/uploads/EnableMediaReplace.log"
    check("plugin log: a log line passes, a block page does not",
          (content_matches(log, "[2026-10-01 10:00:01] Replaced file 12"),
           content_matches(log, "Access Denied [403]")), (True, False))
    check("registration: esc_url's &#038; form is still a link",
          registration_open(200, '<a href="/wp-login.php?lang=en&#038;action=register">'), True)
    check("wpcom takeover: a live site asking visitors to register is not unclaimed",
          wpcom_unclaimed("<h1>Camp 2026</h1><p>Do you want to register for camp?</p>"), False)
    saved = {k: g[k] for k in ("fetch", "fetch_no_redirect", "_dns_cname", "_dns_txt", "_dns_mx")}
    try:
        g["_dns_txt"] = lambda name: []
        g["_dns_mx"] = lambda name: []
        g["fetch"] = lambda url, **k: (404, {}, "<p>Do you want to register <em>gone.wordpress.com</em>?</p>")
        for cname, want in (("gone.wordpress.com", ["dns-wpcom-takeover"]), ("x.example.net", [])):
            g["_dns_cname"] = lambda name, c=cname: c if name == "x.test" else ""
            with tempfile.TemporaryDirectory() as tmp:
                ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
                collect_dns(ctx)
                check(f"wpcom takeover: CNAME {cname}",
                      [f.fid for f in check_dns(ctx) if f.fid == "dns-wpcom-takeover"], want)
        opml = '<?xml version="1.0"?>\n<opml version="1.0"><head><!-- generator="WordPress/6.8.3" -->'
        g["fetch"] = lambda url, **k: ((200, {}, opml) if "opml" in url else
                                       (200, {}, '<meta name="generator" content="WordPress 6.8.3">'))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
            collect_headers(ctx)
            check("opml: the generator comment is a core version source",
                  ctx.data("headers")["core_versions"].get("opml"), "6.8.3")
    finally:
        g.update(saved)
    saved = {k: g[k] for k in ("fetch", "fetch_no_redirect")}
    asked: List[str] = []
    try:
        g["fetch"] = lambda url, **k: (asked.append(url), (404, {}, ""))[1]
        g["fetch_no_redirect"] = lambda url, **k: (404, {})
        with tempfile.TemporaryDirectory() as tmp:
            ctx = RunContext(Path(tmp), argparse.Namespace(url=[], site="https://x.test"))
            ctx.write("headers", {"homepage_plugins": ["wordfence"]})
            ctx.write("rest", {"namespace_plugins": {"gravityforms": {}}})
            ctx.write("assets", {"plugins": {"wp-statistics": {}}})
            collect_paths(ctx)
            check("plugin paths: only advertised plugins are probed",
                  (any("/wflogs/config.php" in u for u in asked),
                   any("/gravityforms/debug.log" in u for u in asked),
                   any("/wp-statistics/debug.log" in u for u in asked),
                   any("/newsletter/" in u for u in asked)), (True, True, True, False))
    finally:
        g.update(saved)

    # Exit-code and resume guards in main().
    with tempfile.TemporaryDirectory() as tmp:
        with contextlib.redirect_stdout(io.StringIO()):
            check("render-only: an empty run directory is refused",
                  main(["--run-dir", tmp, "--render-only", "--no-open"]), 2)
            (Path(tmp) / "manifest.json").write_text(json.dumps(
                {"modules": {}, "meta": {"site": "https://old.test"}}))
            check("resume: another --site on a saved run is refused",
                  main(["--run-dir", tmp, "--site", "new.test", "--no-open"]), 2)
            def crashing(ctx):
                raise RuntimeError("synthetic")
            CHECKS.append(crashing)
            try:
                check("exit: a crashed check makes the run incomplete, not clean",
                      main(["--run-dir", tmp, "--render-only", "--no-open"]), 3)
            finally:
                CHECKS.remove(crashing)

    # 36. CSP quality. osh.co.za sent upgrade-insecure-requests alone and the
    #     tool counted that as a policy.
    a = csp_assessment("upgrade-insecure-requests")
    check("csp: upgrade-insecure-requests alone restricts no script",
          (a["present"], a["has_script_source"]), (True, False))
    a = csp_assessment("default-src 'self'")
    check("csp: default-src covers script-src but not object-src 'none'",
          (a["has_script_source"], a["object_src_none"]), (True, False))
    check("csp: default-src 'none' is object-src 'none' by fallback",
          csp_assessment("default-src 'none'")["object_src_none"], True)
    a = csp_assessment("script-src 'self' 'unsafe-inline'; object-src 'none'; "
                       "base-uri 'self'; frame-ancestors 'self'")
    check("csp: strict on the four, unsafe-inline flagged",
          (a["has_script_source"], a["object_src_none"], a["has_base_uri"],
           a["has_frame_ancestors"], a["unsafe_inline"]), (True,) * 5)
    check("csp: odd case and spacing parse",
          csp_assessment("  Default-Src 'self' ;object-src   'NONE'")["object_src_none"],
          True)
    a = csp_assessment("script-src 'self' 'unsafe-inline', script-src 'self'")
    check("csp: one strict policy of two blocks inline script",
          a["unsafe_inline"], False)
    check("csp: a meta tag cannot supply frame-ancestors",
          csp_assessment("", ("script-src 'self'; frame-ancestors 'none'",))
          ["has_frame_ancestors"], False)
    check("csp: meta tag read in either attribute order",
          meta_csp('<meta content="default-src &#039;self&#039;" '
                   'http-equiv="Content-Security-Policy">'), ["default-src 'self'"])
    msg = email.message.Message()
    msg["Content-Security-Policy"] = "default-src 'self'"
    msg["Content-Security-Policy"] = "object-src 'none'"
    a = csp_assessment(_headers(msg)["content-security-policy"])
    check("csp: two headers are both assessed",
          (a["has_script_source"], a["object_src_none"]), (True, True))

    # 37. Template placeholders are not plugins. WPScan reported one called "*".
    check("slugs: placeholders dropped, the real plugin kept",
          wp_slugs("plugins", '/wp-content/plugins/*/ /wp-content/plugins/%7Bslug%7D/x.js '
                   '/wp-content/plugins/${plugin}/ /wp-content/plugins/contact-form-7/a.js '
                   '/wp-content/plugins/MyPlugin/b.js'),
          ["contact-form-7"])
    check("slugs: underscores and dots are allowed",
          (valid_slug("js_composer"), valid_slug("wp-rocket.pro")), (True, True))

    # 38. XML-RPC advertised by header and link tag.
    pb = pingback_advertised({"x-pingback": "https://x.test/xmlrpc.php"},
                             '<link rel="pingback" href="https://x.test/xmlrpc.php">')
    check("pingback: header and link both read",
          [r["Status"] for r in xmlrpc_adverts({"pingback": pb})],
          ["advertised by the X-Pingback header", "advertised by link rel=pingback"])
    check("pingback: rel=alternate is not an advert",
          pingback_advertised({}, '<link rel="alternate" href="https://x.test/feed/">'),
          {"header": "", "link": ""})
    check("pingback: a run before 1.13.0 has no rows", xmlrpc_adverts({}), [])

    # 39. GraphQL. A themed 200 must not read as an endpoint.
    check("graphql: WPGraphQL's RootQuery", graphql_answering(200, {"data": {"__typename": "RootQuery"}}), True)
    check("graphql: the missing-query error",
          graphql_answering(200, {"errors": [{"message": "Must provide query string."}]}), True)
    check("graphql: a REST error object is not", graphql_answering(200, {"code": "rest_no_route"}), False)
    check("graphql: HTML is not", graphql_answering(200, None), False)
    check("graphql: a 404 is not", graphql_answering(404, {"data": {"__typename": "X"}}), False)
    check("graphql: an unrelated error is not",
          graphql_answering(200, {"errors": [{"message": "Forbidden"}]}), False)

    check("graphql: profile says not measured on 429s",
          graphql_profile([{"status": 429}, {"status": 0}]), "not measured (HTTP 429, HTTP 0)")
    check("graphql: profile says absent with statuses",
          graphql_profile([{"status": 200, "answering": False}, {"status": 404}]),
          "absent (HTTP 200, HTTP 404)")

    # 40. Subresource Integrity: only cross-origin scripts and stylesheets.
    page = ('<script src="/wp-includes/js/a.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/x@1.2.3/x.js" integrity="sha384-a"></script>'
            '<script src="https://www.googletagmanager.com/gtm.js?id=G"></script>'
            '<link rel="preload" as="script" href="https://cdn.other.test/p.js">'
            '<link rel="stylesheet" href="//fonts.googleapis.com/css?family=A">'
            '<script>var x=1;</script>'
            '<script type="module" src="https://esm.test/m.js"></script>'
            '<script src="https://www.example.com/own.js"></script>')
    res = third_party_resources(page, "https://example.com")
    check("sri: cross-origin scripts and stylesheets only",
          [(r["host"], r["type"], r["integrity"]) for r in res],
          [("cdn.jsdelivr.net", "script", True),
           ("www.googletagmanager.com", "script", False),
           ("fonts.googleapis.com", "stylesheet", False),
           ("esm.test", "script", False)])
    check("sri: a versioned CDN file is pinnable, GTM is not",
          [r["pinnable"] for r in res][:2], [True, False])

    # 41. More author routes.
    check("users: feed creators, CDATA stripped, empty dropped, deduplicated",
          feed_creators("<dc:creator><![CDATA[Paul Ogier]]></dc:creator>"
                        "<dc:creator><![CDATA[Paul Ogier]]></dc:creator>"
                        "<dc:creator><![CDATA[]]></dc:creator>"), ["Paul Ogier"])
    check("users: a homepage served at /feed/ is not a feed",
          (is_feed(200, "<!DOCTYPE html><html>"), is_feed(200, '<?xml version="1.0"?><rss version="2.0">')),
          (False, True))
    check("users: author sitemap slugs",
          author_sitemap_slugs("<url><loc>https://x.test/author/jane-doe/</loc></url>"
                               "<url><loc>https://x.test/author/%7Bslug%7D/</loc></url>"),
          ["jane-doe"])
    check("users: homepage author link, ?author= ignored",
          homepage_author_slugs('<a href="https://x.test/author/paul/">P</a>'
                                '<a href="https://x.test/?author=3">Q</a>'), ["paul"])

    def _usr_ctx(users, headers):
        class _C:
            def data(self, key):
                return {"users": users, "headers": headers}.get(key, {})
        return _C()
    rows = [r for f in check_users(_usr_ctx(
        {"author_redirect": [{"n": 1, "slug": "paul"}], "sitemap": [],
         "yoast_sitemap": ["paul", "jane"]}, {"author_links": ["jane", "sam"]}))
        if f.fid == "users-author" for r in f.evidence]
    check("users: one row per slug across routes",
          [(r["Route"], r["Author slug"]) for r in rows],
          [("?author=1", "paul"), ("author-sitemap.xml", "jane"),
           ("homepage author link", "sam")])
    nm = [f for f in check_users(_usr_ctx({"oembed": "Paul", "feed_creators": ["Jane"]}, {}))
          if f.fid == "users-names"]
    check("users: feed and oEmbed names in one finding",
          (nm[0].title, len(nm[0].evidence)) if nm else None,
          ("Display names are published by oEmbed and the feed", 2))

    # 42. WPScan's single-file probes, and PHP switched off.
    soft = {"status": 200, "no_redirect_status": 200, "stable": True,
            "fingerprint": body_fingerprint("<html><h1>Oops</h1></html>")}
    for path, real in (
            ("/installer-log.txt", "DUPLICATOR INSTALL-LOG\nSTEP 1"),
            ("/searchreplacedb2.php", "<html><title>Search and replace DB</title>by interconnect/it</html>"),
            ("/emergency.php", "<!DOCTYPE html><title>Emergency Password Reset</title>New password"),
            ("/wp-content/uploads/dump.sql", "-- MySQL dump 10.13\nCREATE TABLE x"),
            ("/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip", "PK\x03\x04"),
            ("/wp-content/backup-db/", "<html><title>Index of /wp-content/backup-db</title>")):
        check(f"probe: {path} real body readable",
              path_is_exposed(path, 200, real, soft, 200), True)
        check(f"probe: {path} themed 404 not",
              path_is_exposed(path, 200, "<html><h1>Oops</h1></html>", soft, 200), False)
    check("probe: emergency.php needs both words",
          path_is_exposed("/emergency.php", 200, "<html>Forgot password?</html>", soft, 200), False)
    check("probe: an empty 200 on installer-log.txt is the empty bucket",
          path_verdict("/installer-log.txt", 200, "",
                       path_is_exposed("/installer-log.txt", 200, "", soft, 200), 200), "empty")
    check("php off: version.php source is a hit",
          php_source_served(200, "<?php\n$wp_version = '6.8';"), True)
    check("php off: an empty 200 is not", php_source_served(200, ""), False)
    pd_row = {"path": "/wp-includes/version.php", "url": "x", "severity": "CRITICAL",
              "why": "PHP source served", "rule": "php-disabled", "status": 200,
              "no_redirect_status": 200, "location": "", "bytes": 40,
              "content_type": "", "exposed": True, "verdict": "readable", "error": ""}

    class _PdCtx:
        missing_signature = {"stable": True}
        site = "https://x.test"

        def data(self, key):
            return [pd_row] if key == "paths" else {}
    check("php off: surfaces in the CRITICAL band",
          [f.fid for f in check_paths(_PdCtx())], ["paths-critical"])

    # 43. CAA and DNSSEC.
    check("caa: issuers parsed, CNAME line skipped",
          caa_records(['www.x.cdn.test.', '0 issue "letsencrypt.org"',
                       '0 issue "pki.goog; cansignhttpexchanges=yes"']),
          [{"tag": "issue", "value": "letsencrypt.org"},
           {"tag": "issue", "value": "pki.goog"}])
    check("dnssec: AD true", dnssec_validated({"Status": 0, "AD": True}), True)
    check("dnssec: AD false", dnssec_validated({"Status": 0, "AD": False}), False)
    check("dnssec: a failed lookup is not a no", dnssec_validated(None), None)
    check("dnssec: SERVFAIL is not a no", dnssec_validated({"Status": 2, "AD": False}), None)

    def _dns_ctx(dns, tls_issuer=""):
        class _C:
            def data(self, key):
                return {"dns": dns, "transport": {"tls": {"issuer": tls_issuer}}}.get(key, {})
        return _C()
    caa_f = [f for f in check_dns(_dns_ctx({"domain": "x.test", "host": "www.x.test",
                                           "caa": [], "caa_measured": True},
                                          "Let's Encrypt")) if f.fid == "dns-caa"]
    check("caa: absent is LOW and names the issuer's identifier",
          (caa_f[0].severity, "letsencrypt.org" in caa_f[0].remediation) if caa_f else None,
          ("LOW", True))
    check("caa: an inherited parent record raises nothing",
          [f.fid for f in check_dns(_dns_ctx({"domain": "x.test", "host": "www.x.test",
                                             "caa": [{"tag": "issue", "value": "pki.goog"}],
                                             "caa_at": "x.test", "caa_measured": True}))
           if f.fid == "dns-caa"], [])
    check("caa: unmeasured raises nothing",
          [f.fid for f in check_dns(_dns_ctx({"domain": "x.test", "caa": [],
                                             "caa_measured": False}))
           if f.fid == "dns-caa"], [])

    # 44. Legacy TLS classification, from the messages OpenSSL 4.1 gave.
    check("tls: protocol alert is refused",
          classify_tls_failure("SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version"),
          "refused")
    check("tls: server answering another version is refused",
          classify_tls_failure("SSLError: [SSL: UNSUPPORTED_PROTOCOL] unsupported protocol"), "refused")
    check("tls: a reset is refused",
          classify_tls_failure("ConnectionResetError: [Errno 54] Connection reset by peer"), "refused")
    check("tls: no protocols offered locally is not measured",
          classify_tls_failure("SSLError: [SSL: NO_PROTOCOLS_AVAILABLE] no protocols available"),
          "not measured")
    check("tls: a timeout is not measured", classify_tls_failure("TimeoutError: timed out"),
          "not measured")

    # 45. Placeholder and host-default account names.
    check("accounts: admin and a host account flagged once each",
          [r["Name"] for r in suspicious_accounts(
              {"rest": [{"slug": "admin", "name": "Admin"}, {"slug": "jane", "name": "Jane"}],
               "author_redirect": [{"n": 1, "slug": "admin"}],
               "feed_creators": ["Kinsta"]}, {})], ["admin", "Kinsta"])
    check("accounts: a name containing admin is not flagged",
          suspicious_accounts({"rest": [{"slug": "siteadmin-jane", "name": "Jane Admin"}]}, {}), [])

    # 46. Cloaking.
    page_html = ("<html><title>Home</title><a href='https://x.test/a'>a</a>"
                 "<a href='https://other.test/'>o</a><p>%s</p></html>")
    def _sh(body, status=200, loc="", ch=False):
        return page_shape("https://x.test", status, loc, body, ch)
    b0 = _sh(page_html % "nonce-a1b2c3d4e5f6")
    check("cloak: same page three times is nothing",
          cloaking_verdict(b0, b0, b0)[0], "")
    check("cloak: a changed nonce is nothing",
          cloaking_verdict(b0, b0, _sh(page_html % "nonce-9f8e7d6c5b4a"))[0], "")
    check("cloak: crawler-only redirect to another host is HIGH",
          cloaking_verdict(b0, b0, _sh("", 301, "https://pills.test/"))[0], "HIGH")
    spam = page_html.replace("</html>", "".join(
        f"<a href='https://spam{i}.test/'>s</a>" for i in range(40)) + "</html>")
    check("cloak: 40 extra outbound links is HIGH",
          cloaking_verdict(b0, b0, _sh(spam % "n"))[0], "HIGH")
    check("cloak: a challenge is unmeasured",
          cloaking_verdict(b0, b0, _sh("<html>Just a moment</html>", 403, "", True))[0],
          "unmeasured")
    check("cloak: an edge refusing the crawler string is unmeasured, not HIGH",
          cloaking_verdict(b0, b0, _sh("<html><title>403 Forbidden</title></html>", 403))[0],
          "unmeasured")
    check("cloak: body-only difference with two agreeing controls is MEDIUM",
          cloaking_verdict(b0, b0, _sh(page_html % "x" + "<p>Buy now</p>"), b0)[0], "MEDIUM")
    check("cloak: one chance-matching control is not enough for MEDIUM",
          cloaking_verdict(b0, b0, _sh(page_html % "x" + "<p>Buy now</p>"))[0], "")
    check("cloak: a page that varies on its own raises no MEDIUM",
          cloaking_verdict(b0, _sh(page_html.replace("Home", "Home") % "x" + "<p>rotating</p>"),
                           _sh(page_html % "y" + "<p>other</p>"))[0], "")

    # 47. Injected content and a signed-in page served publicly.
    site = "https://x.test"
    def _kinds(body):
        return [(h["kind"], h["severity"]) for h in injected_content(body, site)]
    check("inject: hidden iframe to another site",
          _kinds('<iframe src="https://evil.test/x" width="0" height="0"></iframe>'),
          [("hidden iframe", "HIGH")])
    check("inject: GTM's noscript iframe is normal",
          _kinds('<iframe src="https://www.googletagmanager.com/ns.html?id=G" height="0" '
                 'width="0" style="display:none;visibility:hidden"></iframe>'), [])
    check("inject: off-screen links to another site",
          _kinds('<div style="position:absolute;left:-9999px"><a href="https://pills.test/">x</a></div>'),
          [("link in a hidden element", "MEDIUM")])
    check("inject: a hidden mobile menu of own links is normal",
          _kinds('<nav><div class="m" style="display:none"><a href="https://x.test/about/">About</a>'
                 '<a href="/contact/">Contact</a></div></nav>'), [])
    check("inject: a consent banner hidden until shown, own links, is normal",
          _kinds('<div id="cc" style="display: none"><p>We use cookies</p>'
                 '<a href="https://www.x.test/privacy/">Privacy</a></div>'), [])
    enc = "".join(f"\\x{b:02x}" for b in b"document.location='https://evil.test/go'")
    check("inject: hex-encoded script resolving to a URL is HIGH",
          _kinds(f'<script>eval("{enc}")</script>'), [("encoded inline script", "HIGH")])
    import base64 as _b64
    check("inject: atob on a long literal resolving to a URL is HIGH",
          _kinds('<script>eval(atob("' + _b64.b64encode(
              b"var s=document.createElement('script');s.src='https://evil.test/a.js';" * 3).decode()
                 + '"))</script>'), [("encoded inline script", "HIGH")])
    check("inject: a big readable bundle is not encoded",
          _kinds("<script>" + "var settings={a:1,b:'two'};function f(x){return x+1}" * 200 + "</script>"), [])
    check("inject: a long base64 image is not a script",
          _kinds('<img src="data:image/png;base64,' + "A" * 600 + '">'), [])
    check("inject: meta refresh to another site",
          _kinds('<meta http-equiv="refresh" content="0;url=https://evil.test/">'),
          [("meta refresh", "MEDIUM")])
    check("inject: 'specialises' and a loans blog post are not spam",
          _kinds('<a href="https://osh.test/c/">OSH specialises in DMARC</a>'
                 '<a href="https://in.test/x">Practice Specialist</a>'
                 '<a href="https://b.test/practice-startup-loans-for-doctors/">loans</a>'), [])
    check("inject: WordPress's oEmbed iframe is normal",
          _kinds('<iframe class="wp-embedded-content" sandbox="allow-scripts" '
                 'style="position: absolute; visibility: hidden;" src="https://ifsw.test/x/embed/#?secret=Ab12"></iframe>'), [])
    check("inject: a copied class on a non-embed frame is still reported",
          _kinds('<iframe class="wp-embedded-content" width="0" height="0" src="https://evil.test/x"></iframe>'),
          [("hidden iframe", "HIGH")])
    check("inject: spam-word link to another site",
          _kinds('<footer><a href="https://cheap.test/buy">cheap viagra online</a></footer>'),
          [("spam-word link", "MEDIUM")])
    t0 = time.time()
    injected_content("<script>" * 20000 + "<div style='display:none" * 2000, site)
    check("inject: a hostile page does not stall the scan", time.time() - t0 < 5, True)
    check("inject: inline scripts skip src tags, not data-src",
          _inline_scripts('<script src="a.js"></script><script>x=1</script>'
                          '<script data-src="lazy.js">y</script><SCRIPT>z</Script >'),
          ["x=1", "y", "z"])
    check("inject: 300 padding scripts do not hide the last one",
          len(_inline_scripts("<script>a</script>" * 300 + "<script>b</script>")), 301)
    check("signed-in: admin bar and logged-in class",
          signed_in_view('<body class="home logged-in admin-bar"><div id="wpadminbar" class="nojq">'),
          ["the admin bar (id=wpadminbar)", "body class logged-in"])
    check("signed-in: a theme's admin-bar CSS does not count",
          signed_in_view("<style>.admin-bar .site-header{top:32px} #wpadminbar{}</style><body class='home'>"),
          [])

    # 48. Core checksums.
    import hashlib as _h
    js = "/*! jQuery */!function(){}();"
    good_md5 = _h.md5(js.encode()).hexdigest()
    check("core: identical bytes match", core_checksum_result(good_md5, 200, js, False), "match")
    check("core: changed bytes mismatch",
          core_checksum_result(good_md5, 200, js + "eval(atob('x'))", False), "mismatch")
    check("core: a themed 404 is unreadable, not a mismatch",
          core_checksum_result(good_md5, 200, "<!DOCTYPE html><html>404</html>", False), "unreadable")
    check("core: a challenge is unreadable", core_checksum_result(good_md5, 403, "", True), "unreadable")

    class _CoreCtx:
        def data(self, key):
            return {"integrity": {"core": {"version": "6.8.3", "locale": "en_US", "files": [
                        {"path": "wp-includes/js/jquery/jquery.min.js", "result": "mismatch"}]}},
                    "headers": {"edge": ["Cloudflare"]}}.get(key, {})
    core_f = [f for f in check_integrity(_CoreCtx()) if f.fid == "integrity-core"]
    check("core: a mismatch names the edge in front as a possible cause",
          "Cloudflare" in core_f[0].meaning if core_f else False, True)

    # 49. Sitemap anomalies.
    smx = ("<urlset><url><loc>https://x.test/about/</loc><lastmod>2026-11-01T10:00:00Z</lastmod></url>"
           "<url><loc>https://x.test/cheap-viagra-online/</loc><lastmod>2026-11-01T10:00:30Z</lastmod></url>"
           "</urlset>")
    st = sitemap_stats([smx])
    check("sitemap: count, spam slug and busiest minute",
          (st["count"], st["spam"], st["lastmod_count"]),
          (2, ["https://x.test/cheap-viagra-online/"], 2))

    def _sm_ctx(sm):
        class _C:
            def data(self, key):
                return {"integrity": {"sitemap": sm}}.get(key, {})
        return _C()
    jump = [f.fid for f in check_integrity(_sm_ctx(
        {"read": True, "count": 900, "spam": [], "previous_count": 40,
         "previous_run": "x_20261101_000000"}))]
    check("sitemap: a jump from 40 to 900 is MEDIUM", jump, ["integrity-sitemap"])
    check("sitemap: normal growth raises nothing",
          [f.fid for f in check_integrity(_sm_ctx(
              {"read": True, "count": 60, "spam": [], "previous_count": 40,
               "previous_run": "x"}))], [])
    check("sitemap: a first run records the count as INFO",
          [f.fid for f in check_integrity(_sm_ctx({"read": True, "count": 60, "spam": []}))],
          ["integrity-sitemap-count"])

    # 50. Developer files: each real body passes, a themed 404 does not.
    for path, real in (
            ("/.idea/workspace.xml", '<?xml version="1.0"?><project version="4">'),
            ("/.vscode/settings.json", '{"sftp.host": "1.2.3.4"}'),
            ("/Dockerfile", "FROM php:8.3-apache\nCOPY . /var/www/html"),
            ("/docker-compose.yml", "services:\n  db:\n    image: mysql"),
            ("/.ftpconfig", '{"host": "ftp.x.test", "password": "hunter2"}'),
            ("/sftp-config.json", '{"host": "x", "password": "y"}'),
            ("/.remote-sync.json", '{"hostname": "x", "password": "y"}'),
            ("/web.config", '<?xml version="1.0"?><configuration><system.webServer>'),
            ("/php.ini", "memory_limit = 256M\nupload_max_filesize = 64M"),
            ("/.bash_history", "cd public_html\nwp plugin list\nmysql -u root -p"),
            ("/.gitignore", "/wp-config.php\n*.log\nnode_modules/"),
            ("/composer.lock", '{"content-hash": "abc", "packages": []}'),
            ("/package-lock.json", '{"name": "x", "lockfileVersion": 3}'),
            ("/yarn.lock", "# yarn lockfile v1\n"),
            ("/wp-config.php.swp", "b0VIM 8.2\x00\x00"),
            ("/.htaccess", "<IfModule mod_rewrite.c>\nRewriteEngine On"),
            ("/wp-content/themes/t/style.css.map", '{"version":3,"sources":["a.scss"],"mappings":"AAAA"}')):
        check(f"devfile: {path} real body readable", path_is_exposed(path, 200, real, soft, 200), True)
        check(f"devfile: {path} themed 404 not",
              path_is_exposed(path, 200, "<html><h1>Oops</h1></html>", soft, 200), False)
    check("devfile: a one-word 200 is not a .gitignore",
          path_is_exposed("/.gitignore", 200, "OK", soft, 200), False)

    # 51. The database repair page.
    rp = "<title>WordPress &rsaquo; Database Repair</title>"
    check("repair: enabled page is exposed",
          path_is_exposed(REPAIR_PATH, 200, rp + '<a class="button" href="repair.php?repair=1">Repair Database</a>',
                          soft, 200), True)
    check("repair: the not-defined page is not",
          path_is_exposed(REPAIR_PATH, 200, rp + "please add the following line to your "
                          "<code>wp-config.php</code> file. define('WP_ALLOW_REPAIR', true);", soft, 200),
          False)
    check("repair: a themed page is not",
          path_is_exposed(REPAIR_PATH, 200, "<html><h1>Oops</h1></html>", soft, 200), False)

    # 52. Secrets in page source, masked; debug output.
    def _vendors(text):
        return [h["vendor"] for h in secret_hits(text)]
    for vendor, sample in (
            ("Stripe live secret key", "sk_live_" + "a1B2" * 7),
            ("Private key", "-----BEGIN RSA PRIVATE KEY-----"),
            ("AWS access key ID", "AKIA" + "ABCDEFGHIJKLMNOP"),
            ("SendGrid API key", "SG." + "a" * 22 + "." + "b" * 43),
            ("Mailgun API key", "key-" + "0123456789abcdef" * 2),
            ("Slack token", "xoxb-1234567890-abcdef"),
            ("Google OAuth client secret", "GOCSPX-" + "a1" * 14),
            ("Twilio account SID with a token nearby",
             "AC" + "0123456789abcdef" * 2 + "', token: '" + "fedcba9876543210" * 2),
            ("Credential assigned in code", 'var cfg = {"api_key": "a8f3k29dls03kd8s"}')):
        check(f"secrets: {vendor}", _vendors(sample), [vendor])
    check("secrets: a Maps key is INFO",
          [h["severity"] for h in secret_hits("AIza" + "B" * 35)], ["INFO"])
    for name, text in (("GA4 id", "gtag('config', 'G-V1VM4YXCY4')"),
                       ("hex nonce", '"nonce":"9f8e7d6c5b4a3f2e"'),
                       ("base64 image", "data:image/png;base64," + "QUJD" * 100),
                       ("prose", "Enter your password to continue, at least 16 characters long")):
        check(f"secrets: {name} is not a secret", _vendors(text), [])
    check("secrets: the full value is never kept",
          secret_hits("sk_live_" + "a1B2" * 7)[0]["masked"], "sk_l...B2")
    check("debug: a PHP warning with a path",
          debug_hits("<b>Warning</b>:  Undefined variable $x in <b>/home/u1/public_html/wp-content/themes/t/f.php</b> on line <b>3</b>"),
          [{"kind": "PHP warning", "detail": "/home/u1/public_html/wp-content/themes/t/f.php"}])
    check("debug: unminified core script",
          [h["kind"] for h in debug_hits('<script src="/wp-includes/js/dist/hooks.js?ver=6.8"></script>')],
          ["unminified core script"])
    check("debug: the minified script is normal",
          debug_hits('<script src="/wp-includes/js/dist/hooks.min.js?ver=6.8"></script>'), [])

    # 53. HSTS quality.
    check("hsts: github's header parses",
          hsts_assessment("max-age=31536000; includeSubdomains; preload"),
          {"max_age": 31536000, "include_subdomains": True, "preload": True})
    check("hsts: a short max-age with no subdomains is two gaps",
          [r["Directive"] for f in check_headers(type("C", (), {"data": lambda self, k: {
              "status": 200, "challenged": False, "missing": [],
              "headers": {"strict-transport-security": "max-age=300"}} if k == "headers" else {}})())
           if f.fid == "headers-hsts-weak" for r in f.evidence],
          ["max-age", "includeSubDomains"])

    # 54. Mail extras.
    zone = {"a.test": ["v=spf1 include:b.test include:c.test -all"],
            "b.test": ["v=spf1 ip4:1.2.3.4 a mx -all"], "c.test": ["v=spf1 include:a.test -all"]}
    check("spf: lookups counted through includes",
          spf_lookup_count("v=spf1 include:b.test mx -all", lambda n: zone.get(n, [])), (4, False))
    check("spf: an include loop is caught",
          spf_lookup_count(zone["a.test"][0], lambda n: zone.get(n, []), {"a.test"})[1], True)
    deep = {f"d{i}.test": [f"v=spf1 include:d{i+1}.test a -all"] for i in range(15)}
    check("spf: twelve-deep chain is over ten",
          spf_lookup_count("v=spf1 include:d0.test -all", lambda n: deep.get(n, []))[0] > 10, True)

    def _mail_ctx(dns):
        class _C:
            def data(self, key):
                return {"dns": dict({"domain": "x.test", "mx": []}, **dns)}.get(key, {})
        return _C()
    check("spf: +all and ?all are permissive, -all is not",
          [bool([f for f in check_dns(_mail_ctx({"spf": f"v=spf1 mx {a}all"})) if f.fid == "dns-spf-permissive"])
           for a in ("+", "?", "-", "~")], [True, True, False, False])
    check("dmarc: no rua is LOW",
          [f.severity for f in check_dns(_mail_ctx({"dmarc": "v=DMARC1; p=reject"}))
           if f.fid == "dns-dmarc-no-rua"], ["LOW"])

    # 55. Rate limiting observed, from the run's own request tally.
    class _TrafficCtx:
        manifest = {"meta": {"traffic": {"requests": 120, "refused": 0, "seconds": 60}}}

        def data(self, key):
            return {"host": "x.test"} if key == "transport" else {}
    rl = [f for f in check_transport(_TrafficCtx()) if f.fid == "transport-rate-limit"]
    check("rate: none observed is stated with the rate",
          (rl[0].title, "120 a minute" in rl[0].meaning) if rl else None,
          ("No rate limiting was observed across 120 requests", True))
    global _site_host
    saved_host, saved_traffic = _site_host, dict(_traffic)
    _site_host = "x.test"
    _count("https://www.x.test/a", 200)
    _count("https://api.wordpress.org/x", 200)
    _count("https://x.test/b", 429)
    check("rate: only the audited host is counted", _traffic["requests"] - saved_traffic["requests"], 2)
    _site_host = saved_host
    _traffic.update(saved_traffic)

    check("dig: an option-shaped name is refused", _dig("-f/etc/passwd", "TXT"), [])
    check("dns name: a normal include target passes",
          bool(DNS_NAME_RE.fullmatch("_spf.google.com")), True)
    wide = {f"w{i}.test": [" ".join(["v=spf1"] + [f"include:w{i}-{j}.test" for j in range(50)])]
            for i in range(1)}
    calls = []
    spf_lookup_count(wide["w0.test"][0], lambda n: calls.append(n) or wide.get(n, []))
    check("spf: a wide chain stops resolving past the cap", len(calls) <= 22, True)

    # 56. Security plugins seen from outside.
    check("security plugins: by slug and by Wordfence's cookie",
          security_plugins_seen({"wp-2fa", "contact-form-7"}, [{"name": "wfwaf-authcookie-abc"}]),
          ["WP 2FA", "Wordfence"])

    # 57. Plugin hygiene from wordpress.org payloads.
    check("hygiene: plugin job from tags",
          (plugin_job(["SEO", "xml sitemap"]), plugin_job(["contact form", "email"]), plugin_job(["gallery"])),
          ("SEO", "forms", ""))
    check("hygiene: a cache plugin that also tags seo is a cache plugin",
          plugin_job(["caching", "Optimize", "pagespeed", "performance", "seo"]), "caching")

    def _hyg_ctx(plugins):
        class _C:
            def data(self, key):
                return {"vulns": {"plugins": plugins, "themes": {}, "core": {}}}.get(key, {})
        return _C()
    hyg = [f.fid for f in check_vulns(_hyg_ctx({
        "yoast": {"wporg": {"found": True, "tags": ["seo"], "active_installs": 5000000, "days_since_release": 10}},
        "aioseo": {"wporg": {"found": True, "tags": ["seo"], "active_installs": 3000000, "days_since_release": 10}},
        "tiny": {"wporg": {"found": True, "tags": ["gallery"], "active_installs": 200, "days_since_release": 800}}}))
        if f.fid.startswith("hygiene")]
    check("hygiene: two SEO plugins and one quiet plugin", sorted(hyg),
          ["hygiene-duplicates", "hygiene-low-installs"])

    # 58. Both hosts, the login page, the canonical host.
    check("hosts: DNS failure is not a finding",
          other_host_state(0, "URLError: <urlopen error [Errno 8] nodename nor servname provided>", "", "x"),
          "no DNS")
    check("hosts: a certificate failure is reported",
          other_host_state(0, "URLError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "", "x"),
          "certificate error")
    check("hosts: a redirect is the right answer", other_host_state(301, "", "https://x.test/", "x.test"),
          "redirects")
    check("canonical: hosts read from both tags",
          canonical_hosts('<link rel="canonical" href="https://staging.x.test/">'
                          '<meta property="og:url" content="https://x.test/">'),
          {"canonical": "staging.x.test", "og:url": "x.test"})

    # 59. Attachment pages.
    check("attachments: a link equal to the file is off, no request made",
          attachment_page_probe([{"link": "https://x.test/f.pdf", "source_url": "https://x.test/f.pdf"}],
                                "https://x.test"),
          {"link": "https://x.test/f.pdf", "status": 0, "enabled": False})
    check("attachments: a link to another host is never requested",
          attachment_page_probe([{"link": "http://127.0.0.1/admin", "source_url": "https://x.test/f.pdf"}],
                                "https://x.test"), {})

    # 60. Discussion hygiene.
    disc = {"posts": [{"date": "2023-01-01T00:00:00", "comment_status": "open", "ping_status": "open"},
                      {"date": "2026-10-01T00:00:00", "comment_status": "open", "ping_status": "closed"}],
            "comments": [{"author_name": "https://cheap.test", "links": 0},
                         {"author_name": "Jane", "links": 3}, {"author_name": "Sam", "links": 0}]}
    check("discussion: old open posts, pingback pair, spammy comments",
          [r["Detail"] for r in discussion_rows(disc, True, "2026-11-04")],
          ["1 of 2 sampled posts", "the pingback pair used to bounce traffic at other sites",
           "2 of the newest 3"])
    check("discussion: closed everywhere raises nothing",
          discussion_rows({"posts": [{"date": "2020-01-01", "comment_status": "closed",
                                      "ping_status": "closed"}], "comments": []}, True, "2026-11-04"), [])

    # 61. Customising a parent theme.
    check("child theme: custom.css in the theme folder counts",
          custom_css_signal('<link href="/wp-content/themes/astra/custom.css">', ["astra"]),
          "wp-content/themes/astra/custom.css")
    check("child theme: WordPress's own inline CSS does not",
          custom_css_signal('<style id="wp-custom-css">' + "a{}" * 1000 + "</style>", ["astra"]), "")

    # 62. Privacy module.
    gtag = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC1234"></script>'
    check("privacy: gtag unconditional",
          trackers_seen(gtag), [{"vendor": "Google Analytics", "category": "analytics",
                                 "loading": "unconditional script tag"}])
    check("privacy: gtag gated by a consent tool",
          [t["loading"] for t in trackers_seen(gtag.replace("<script ", '<script type="text/plain" '
                                                            'data-cookiecategory="analytics" '))],
          ["gated by a consent tool"])
    check("privacy: GTM only",
          [t["vendor"] for t in trackers_seen('<script>(function(w,d){})(window,document,"script",'
                                              '"https://www.googletagmanager.com/gtm.js?id=")</script>')],
          ["Google Tag Manager"])
    check("privacy: Meta pixel inline",
          [t["vendor"] for t in trackers_seen("<script>fbq('init', '123');</script>")], ["Meta Pixel"])
    check("privacy: no trackers", trackers_seen("<script>var a=1;</script>"), [])
    check("privacy: consent tools by slug and marker",
          consent_tools_seen('<div id="cmplz-cookiebanner-container">', {"cookie-law-info"}),
          ["CookieYes", "Complianz"])

    def _priv_ctx(d):
        class _C:
            def data(self, key):
                return {"privacy": dict({"pages": ["https://x.test/"]}, **d)}.get(key, {})
        return _C()
    gated_run = check_privacy(_priv_ctx({"consent_tools": ["Complianz"],
                                         "policy": {"url": "https://x.test/privacy/",
                                                    "mentions": {"a cookies section": True}},
                                         "trackers": {
        "Google Analytics": {"vendor": "Google Analytics", "category": "analytics",
                             "loading": "gated by a consent tool", "pages": 3}}}))
    check("privacy: a consent tool with gated trackers raises nothing above INFO",
          sorted({f.severity for f in gated_run}), ["INFO"])
    ungated_run = check_privacy(_priv_ctx({"consent_tools": [], "trackers": {
        "Meta Pixel": {"vendor": "Meta Pixel", "category": "advertising",
                       "loading": "unconditional script tag", "pages": 3}}}))
    check("privacy: ungated trackers with no consent tool are LOW",
          [f.severity for f in ungated_run if f.fid == "privacy-trackers"], ["LOW"])
    check("privacy: cookie purposes",
          (cookie_purpose("_ga_XYZ"), cookie_purpose("wordpress_test_cookie")),
          (("Google Analytics", False), ("WordPress login check", True)))
    check("privacy: WordPress's privacy link found by rel",
          find_policy_link('<a class="privacy-policy-link" href="/privacy/" rel="privacy-policy">P</a>',
                           "https://x.test"), "https://x.test/privacy/")
    pm = policy_mentions("Contact privacy@x.test. Our Information Officer ... PAIA manual. "
                         "Last updated 2026.", "2026-11-04")
    check("privacy: policy mentions", (pm["a contact for privacy requests"],
                                       pm["an Information Officer (POPIA)"],
                                       pm["a PAIA manual (South Africa)"],
                                       pm["a data protection officer (GDPR)"],
                                       pm["a last-updated date within two years"]),
          (True, True, True, False, True))
    check("privacy: pre-ticked newsletter box",
          [r["Issue"] for r in forms_consent_rows(
              '<form><input type="email" name="email"><input type="checkbox" name="news" checked> '
              'Subscribe to our newsletter</form>', "p", False)],
          ["a marketing checkbox is ticked in advance"])
    check("privacy: email form with consent wording is fine",
          forms_consent_rows('<form><input type="email" name="e">I agree to the privacy policy</form>',
                             "p", False), [])
    check("privacy: embeds",
          embeds_seen('<iframe src="https://www.youtube.com/embed/x"></iframe>'
                      '<link href="https://fonts.googleapis.com/css2?family=Inter">'
                      '<iframe src="https://www.youtube-nocookie.com/embed/y"></iframe>'),
          ["YouTube without privacy mode", "Google Fonts"])
    check("privacy: Universal Analytics and two GA4 properties",
          len(legacy_tags("ga('create', 'UA-12345-1'); gtag('config','G-AAAAAAA1'); "
                          "gtag('config','G-BBBBBBB2')")), 2)

    # 63. Diff against the previous run.
    prev_f = [{"id": "paths-high", "severity": "HIGH", "title": "p", "source": "paths.json",
               "evidence": [{"Path": "/a.zip"}, {"Path": "/b.sql"}]},
              {"id": "users-rest", "severity": "HIGH", "title": "u", "source": "users.json",
               "evidence": [{"ID": 1}]}]
    cur_f = [{"id": "paths-high", "severity": "HIGH", "title": "p", "source": "paths.json",
              "evidence": [{"Path": "/a.zip"}, {"Path": "/c.env"}]}]
    d = findings_diff(prev_f, cur_f, {"paths": "ok", "users": "partial"})
    check("diff: a new path is new, a gone path is resolved",
          ([r["item"] for r in d["new"]], [r["item"] for r in d["resolved"]]), (["/c.env"], ["/b.sql"]))
    check("diff: gone from a module that did not complete is unmeasured, not resolved",
          [r["id"] for r in d["unmeasured"]], ["users-rest"])

    # 64. "Do these first": severity, then the cheapest fix.
    mk = lambda fid, sev: Finding(fid, sev, fid, "m", "r", [], "x.json")
    picked = [f.fid for f in this_week([
        mk("vulns-plugins", "HIGH"), mk("users-rest", "HIGH"), mk("transport-xmlrpc", "MEDIUM"),
        mk("headers-medium", "MEDIUM"), mk("headers-generator", "INFO"), mk("paths-low", "LOW"),
        mk("dns-caa", "LOW"), mk("hygiene-comments", "LOW")])]
    check("this week: severity first, cheapest next, no INFO, five at most",
          picked, ["vulns-plugins", "users-rest", "transport-xmlrpc", "headers-medium", "dns-caa"])

    # 65. Every snippet belongs to a finding id the code can raise.
    src = Path(__file__).read_text(encoding="utf-8")
    known = set(re.findall(r'"([a-z]+-[a-z0-9-]+)", "(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)"', src))
    known |= {f"headers-{sev.lower()}" for sev in SEVERITY_ORDER}
    check("snippets: every key is a real finding id", sorted(set(SNIPPETS) - known), [])
    check("snippets: rendered escaped and collapsed",
          ("<details" in _snippet_block("headers-generator"),
           "&#x27;wp_head&#x27;" in _snippet_block("headers-generator")), (True, True))

    # 66. Batch mode.
    check("batch: sites file with comments and blanks",
          batch_sites("# clients\nhttps://a.test\n\nb.test  # second\n"), ["https://a.test", "b.test"])
    check("batch: the worst exit code wins",
          max([0, 3, 1], key=lambda c: _EXIT_RANK.get(c, 3)), 1)

    def _hdr_ctx(hdrs, body=""):
        csp_m = meta_csp(body)
        d = {"status": 200, "challenged": False,
             "missing": [h for h, _, _ in SECURITY_HEADERS if h not in hdrs
                         and not (h == "content-security-policy" and csp_m)],
             "csp": csp_assessment(hdrs.get("content-security-policy", ""),
                                   tuple(csp_m)),
             "csp_report_only": bool(hdrs.get("content-security-policy-report-only"))
                                and "content-security-policy" not in hdrs}

        class _C:
            def data(self, key):
                return d if key == "headers" else {}
        return _C()

    def _csp_rows(ctx):
        return [r for f in check_headers(ctx) if f.fid == "headers-medium"
                for r in f.evidence if r["Header"] == "content-security-policy"]
    weak_ctx = _hdr_ctx({"content-security-policy": "upgrade-insecure-requests"})
    check("csp: a policy with no script source is listed as not sent",
          "restricts nothing" in (_csp_rows(weak_ctx) or [{"Without it": ""}])[0]
          ["Without it"], True)
    check("csp: and the weak finding is raised",
          [f.severity for f in check_headers(weak_ctx) if f.fid == "headers-csp-weak"],
          ["LOW"])
    ro = _hdr_ctx({"content-security-policy-report-only": "default-src 'self'"})
    check("csp: report-only is missing, and says so",
          "blocks nothing" in (_csp_rows(ro) or [{"Without it": ""}])[0]["Without it"],
          True)
    strict = _hdr_ctx({"content-security-policy":
                       "script-src 'self'; object-src 'none'; base-uri 'self'; "
                       "frame-ancestors 'self'"})
    check("csp: a strict policy raises nothing",
          [f.fid for f in check_headers(strict) if "csp" in f.fid
           or _csp_rows(strict)], [])

    # A forced --only re-collect once relabelled six partial path probes
    # "left out" and re-ran calibration through a VPN that could not reach it.
    with tempfile.TemporaryDirectory() as tmp:
        ctx = RunContext(Path(tmp), argparse.Namespace(
            url=[], site="https://x.test", only="privacy", force=True))
        ctx.write("calibration", {"signature": {}})
        ctx.set_module("calibration", "ok", 1)
        ctx.set_module("paths", "partial", 9, "2 path(s) got no answer")
        ctx.set_module("users", "not applicable", 0)
        ran = []
        collect(ctx, [{"key": k, "required": k == "calibration",
                       "fn": (lambda c, k=k: ran.append(k) or ("ok", 1, ""))}
                      for k in ("calibration", "privacy")])
        check("only+force: redoes only the named module", ran, ["privacy"])
        check("only+force: a partial module keeps its status",
              ctx.module_status("paths"), "partial")
        check("only+force: not applicable stays not applicable",
              ctx.module_status("users"), "not applicable")
        check("a module records the tool that wrote it",
              (ctx.manifest["modules"]["privacy"]["tool"],
               len(ctx.manifest["modules"]["privacy"]["tool_sha"])), (SCRIPT_VERSION, 12))

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

def _saved_site(run_dir: Path) -> str:
    """The site a run directory's manifest was recorded for, or ""."""
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        return (manifest.get("meta") or {}).get("site", "") or ""
    except (OSError, ValueError, AttributeError):
        return ""


def _site_key(site: str) -> str:
    """Host, port and path of a site, ignoring scheme, case, www. and the
    trailing slash, which normalise_site() may have changed on the first run."""
    parsed = urllib.parse.urlparse(site if "://" in site else "https://" + site)
    host = re.sub(r"^www\.", "", parsed.netloc.lower())
    return (host + parsed.path).rstrip("/")


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
    # Endpoints are built by appending to the site string, so a query or a
    # fragment would swallow them: ?x=1/wp-json/.
    if parsed.query or parsed.fragment or "@" in parsed.netloc:
        raise ValueError("give the site without a query, fragment or "
                         "user:password, e.g. https://www.example.com")

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
    parser.add_argument("--delay", type=float, default=REQUEST_DELAY,
                        help=f"Seconds between requests (default "
                        f"{REQUEST_DELAY}). Raise it for a host that bans "
                        "by volume without sending 429s first; 2 caps it at "
                        "30 requests a minute")
    parser.add_argument("--standalone", action="store_true",
                        help="Put every evidence row in the report instead "
                             "of the first "
                             f"{EVIDENCE_ROWS}. For a report sent on its own, "
                             "as a link or a file, where the reader has no "
                             "run directory to read the JSON in")
    parser.add_argument("--sites", type=Path, default=None,
                        help="Audit every site in a file, one per line (# for "
                             "comments), one at a time, then write summary.html "
                             "and summary.json in the output directory")
    parser.add_argument("--format", choices=("html", "json"), default="html",
                        help="json also prints findings.json to stdout for a "
                             "pipeline; console messages then go to stderr")
    parser.add_argument("--selftest", action="store_true",
                        help="Run the logic tests and exit; no network")
    args = parser.parse_args(argv)
    if args.render_only and not args.run_dir:
        # Without this the branch renders a fresh, empty directory: zero
        # findings, no coverage table, exit 0. That is the one report which
        # says nothing was checked and reads as clean.
        parser.error("--render-only needs --run-dir")
    if not (args.selftest or args.list or args.site or args.run_dir or args.sites):
        parser.error("--site is required (or --run-dir to resume)")
    # A typo here used to run calibration and headers alone and exit 0.
    known = {m["key"] for m in MODULES}
    for flag in ("only", "skip"):
        unknown = {k.strip() for k in (getattr(args, flag) or "").split(",")
                   if k.strip()} - known
        if unknown:
            parser.error(f"--{flag}: unknown module(s) {', '.join(sorted(unknown))}"
                         f"; --list shows the keys")
    if not 0 <= args.delay < float("inf"):
        parser.error("--delay must be a finite number of seconds, 0 or more")
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


# Exit codes ranked for a batch: the worst run decides.
_EXIT_RANK = {0: 0, 3: 1, 1: 2, 2: 3, 130: 4}


def batch_sites(text: str) -> List[str]:
    """Sites from a --sites file: one per line, # starts a comment."""
    return [l.split("#", 1)[0].strip() for l in text.splitlines()
            if l.split("#", 1)[0].strip()]


def run_batch(args, argv: List[str]) -> int:
    """Run each site in turn with its own run directory, then summarise.
    Sequential on purpose: the tool is deliberately slow."""
    try:
        sites = batch_sites(args.sites.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Cannot read --sites: {exc}")
        return 2
    base, skip = [], False
    for a in argv:
        if skip:
            skip = False
        elif a == "--sites":
            skip = True
        elif not a.startswith("--sites="):
            base.append(a)
    out_root = args.output_dir or OUTPUT_DIRECTORY
    rows, worst = [], 0
    for site in sites:
        if shutdown_requested:
            break
        before = set(out_root.glob("*")) if out_root.exists() else set()
        code = main(base + ["--site", site, "--no-open"])
        worst = max(worst, code, key=lambda c: _EXIT_RANK.get(c, 3))
        new_dirs = sorted((d for d in out_root.glob("*") if d.is_dir() and d not in before),
                          key=lambda d: d.name)
        row = {"site": site, "exit": code, "report": "", "counts": {}, "worst": "",
               "core": "", "php": "", "incomplete": []}
        if new_dirs:
            rd = new_dirs[-1]
            try:
                found = json.loads((rd / "findings.json").read_text(encoding="utf-8"))
                manifest = json.loads((rd / "manifest.json").read_text(encoding="utf-8"))
                vulns = json.loads((rd / "vulns.json").read_text(encoding="utf-8")) \
                    if (rd / "vulns.json").is_file() else {}
            except (OSError, json.JSONDecodeError):
                found, manifest, vulns = [], {}, {}
            security = [f for f in found if not f["id"].startswith("privacy-")]
            row.update(report=f"{rd.name}/exposure_report.html",
                       counts={s: sum(1 for f in security if f["severity"] == s) for s in SEVERITY_ORDER},
                       worst=security[0]["title"] if security else "",
                       core=(vulns.get("core") or {}).get("detected", ""),
                       php=(vulns.get("php") or {}).get("detected", ""),
                       incomplete=sorted(k for k, v in (manifest.get("modules") or {}).items()
                                         if v.get("status") == "error"))
        rows.append(row)
    (out_root / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    body = "".join(
        f"<tr><td><a href='{escape(r['report'])}'>{escape(r['site'])}</a></td>"
        + "".join(f"<td>{r['counts'].get(s, '')}</td>" for s in SEVERITY_ORDER)
        + f"<td>{escape(r['core'])}</td><td>{escape(r['php'])}</td><td>{escape(r['worst'])}</td>"
        f"<td>{escape(', '.join(r['incomplete']) or 'complete')}</td></tr>" for r in rows)
    head = "".join(f"<th>{s.title()}</th>" for s in SEVERITY_ORDER)
    (out_root / "summary.html").write_text(
        f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>wp_audit summary</title>"
        f"<style>{REPORT_CSS}</style></head><body><main style='max-width:1180px;margin:24px auto'>"
        f"<section class='card'><h2>{len(rows)} site(s)</h2><div class='scroll'><table><tr><th>Site</th>"
        f"{head}<th>Core</th><th>PHP</th><th>Worst finding</th><th>Run</th></tr>{body}</table></div>"
        f"</section></main></body></html>", encoding="utf-8")
    print_success(f"Batch summary written: {out_root / 'summary.html'}")
    return worst


def main(argv=None):
    _force_utf8_console()
    if not _enable_windows_ansi() or not sys.stdout.isatty():
        Colours.strip_colours()
    signal.signal(signal.SIGINT, signal_handler)

    args = parse_args(argv)
    if args.format == "json":
        sys.stdout = sys.stderr  # stdout carries only the JSON
    # A host firewall that drops the IP gives no 429, so the adaptive
    # back-off never fires; the only lever is a slower pace from the start.
    globals()["REQUEST_DELAY"] = max(args.delay, 0.0)
    # Finding.__init__ reads this at call time, so rebinding it here covers
    # every finding without threading a flag through the check functions.
    if args.standalone:
        globals()["EVIDENCE_ROWS"] = EVIDENCE_ROWS_ALL
    if args.no_colour:
        Colours.strip_colours()
    if args.selftest:
        return selftest()
    if args.list:
        list_modules()
        return 0
    if args.sites:
        return run_batch(args, list(sys.argv[1:] if argv is None else argv))

    scheme_note = ""
    if args.run_dir:
        run_dir = args.run_dir
        if not run_dir.is_dir():
            print(f"Run directory not found: {run_dir}")
            return 2
        saved_site = _saved_site(run_dir)
        if args.render_only and not saved_site:
            # An empty directory rendered "every module ran" and exited 0.
            print(f"No run recorded in {run_dir}: manifest.json is missing "
                  "or names no site")
            return 2
        # The saved evidence belongs to the saved site. Accepting another
        # --site relabelled it as the new one.
        if args.site and saved_site and \
                _site_key(args.site) != _site_key(saved_site):
            print(f"{run_dir} is a run for {saved_site}, not {args.site}. "
                  "Leave --site off to resume it, or start a new run.")
            return 2
        args.site = saved_site or args.site
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
        global _site_host
        _site_host = re.sub(r"^www\.", "", (urllib.parse.urlparse(ctx.site).hostname or "").lower())
        _traffic.update(requests=0, refused=0)  # per site, also within a batch
        t0 = time.time()
        collect(ctx, selected_modules(args))
        ctx.manifest["meta"]["traffic"] = dict(_traffic, seconds=round(time.time() - t0))
        ctx.save()

    findings = run_checks(ctx)
    report_path = render_html(ctx, findings)
    if args.format == "json":
        sys.__stdout__.write((ctx.run_dir / "findings.json").read_text(encoding="utf-8") + "\n")
        sys.__stdout__.flush()

    if shutdown_requested:
        print_warning("Run was interrupted; the report covers the modules "
                      f"collected so far. Resume with --run-dir {run_dir}")
        open_report(report_path, args)
        return 130

    worst = next((f.severity for f in findings
                  if f.severity in ("CRITICAL", "HIGH")), None)
    # A module in error measured nothing, so "no critical or high findings"
    # would be a statement about checks that never ran (one live site:
    # calibration and REST both refused, exit 0).
    unmeasured = sorted(k for k, v in ctx.manifest["modules"].items()
                        if v.get("status") == "error")
    # A crashed check dropped every finding it would have made.
    unmeasured += sorted(ctx.manifest["meta"].get("check_errors") or {})
    if worst:
        print_warning(f"Highest severity found: {worst}. "
                      "Open exposure_report.html for the detail.")
    elif unmeasured:
        print_warning("No critical or high findings, but these modules or "
                      f"checks measured nothing: {', '.join(unmeasured)}. The run "
                      "is incomplete, not clean.")
    else:
        print_success("No critical or high findings. Read the Coverage and "
                      "Methodology sections before calling the site clean.")
    open_report(report_path, args)
    return 1 if worst else 3 if unmeasured else 0


if __name__ == "__main__":
    sys.exit(main())
