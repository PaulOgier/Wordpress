# WordPress Exposure Audit

`wp_audit.py` checks a WordPress site from the outside and writes a
self-contained HTML report you can hand to whoever owns the site.

Every request is a GET or a HEAD. Nothing is submitted, guessed or written.
Stdlib only, no packages to install, one file.

```sh
python3 wp_audit.py --site https://www.example.com
```

The report opens in your browser when the run finishes. Print it for a PDF.

---

## Why this exists

Most "is my WordPress site safe" tools answer with a list of paths that
returned HTTP 200. That list is wrong on a large share of real sites, and
wrong in both directions.

A site that redirects every unknown path to its homepage answers `/backup.sql`
with a real page, and a checker that follows redirects reports a downloadable
database. An early version of this tool did exactly that: **five CRITICAL
findings on a tidy site, all five false.** A site that serves a themed 404 with
a 200 status does the same thing more quietly. Meanwhile the findings that
actually matter, like a pension scheme's fee disclosure sitting in an upload
folder from years ago that the WordPress admin screens can no longer see,
appear in no scan at all because nothing links to them.

So this tool spends most of its effort on telling those two cases apart, and
the report says out loud how it did it. The sections below on calibration and
coverage are the point of the thing, not boilerplate.

## What you get

A run directory containing:

| File | What it holds |
|---|---|
| `exposure_report.html` | The report. Self-contained, no assets, prints cleanly. |
| `findings.json` | Every finding with its full evidence list, for scripting. |
| `manifest.json` | Which modules ran, their status and any reason they did not. |
| `paths.json`, `users.json`, `media.json`, … | Raw collected data, one file per module. |
| `run.log` | Console output, ANSI stripped. |

The HTML report has a sticky contents rail down the left, a severity tile row,
one anchored card per finding, and five reference sections: the site profile,
every path checked including the clean ones, coverage gaps, what the tool
checks, and the methodology.

Exit code is `1` when anything CRITICAL or HIGH was found, `0` otherwise, `130`
if you stopped it with Ctrl-C. That makes it usable as a gate in a scheduled
job.

## Safety posture

**GET and HEAD only.** No POST, no form submission, no password guessing, no
injection payloads, no load testing, nothing behind a login. A full run is a
few hundred ordinary page fetches with a 150ms gap between them, which is safe
against production and inside the terms of hosts that forbid load testing.

**This is not a penetration test.** It cannot find injection flaws, broken
access control behind a login, or anything a read-only request will not reveal.
A clean report is not a clean bill of health, and the report says so in its own
words rather than leaving you to infer it.

**Run it only against a site you own or have written permission to test.**
Unauthorised scanning of third-party systems is illegal in most jurisdictions.
Real penetration testing needs written authorisation from the site owner *and*
the host.

**This tool exists to lock sites down, not to break into them.** It is
published so that the person responsible for a site can see what an outsider
sees and fix it. If a run turns up a real exposure on a site that is not
yours, the right thing to do is tell the site, plainly and privately, what
you found and where: a `security.txt` address if they publish one, otherwise
the site's own contact page. Tell them soon, and do not download or publish
what you found while you wait for a reply.

One deliberate omission: where an endpoint accepts POST and its authentication
is unknown, the tool reports the endpoint and says the authentication is
unknown. It does not find out. Finding out means submitting.

## What it checks

Ten modules. `--list` prints this with descriptions.

| Key | Area |
|---|---|
| `calibration` | How the site answers a path that cannot exist, plus a control proving the result still lets real files through |
| `headers` | Whether this is WordPress at all, what sits in front of it (CDN, WAF, managed host), security response headers, cookie flags, mixed content, the core version from three independent sources, the theme and its version from `style.css` |
| `paths` | Fifty-odd backup archives, database dumps, credential files, logs, developer artefacts, form-upload directories and directory listings, plus backup names derived from the site's own domain and the paths its `robots.txt` asks crawlers to avoid |
| `rest` | `/wp-json/` (or `/?rest_route=/` where pretty permalinks are off) plugin inventory, any route accepting a write method, and `readme.txt` versions for plugins known only from their namespace |
| `users` | The four routes that publish account names |
| `media` | The whole media library, walked and reconciled against the reported total |
| `documents` | Each document resolved, filenames triaged |
| `assets` | Plugin versions from cache-busted asset URLs across the sitemap, cross-checked against each plugin's `readme.txt` |
| `vulns` | Every detected plugin, theme and core version looked up for currency, withdrawal from the directory and published CVEs |
| `transport` | HTTP-to-HTTPS, TLS, CORS, XML-RPC, `wp-cron.php`, `security.txt` |
| `dns` | SPF and DMARC for the website domain, including the DMARC policy a subdomain inherits |

The WordPress-specific modules (`rest`, `users`, `media`, `documents`,
`assets`, `vulns`) are marked **not applicable** rather than run when no
WordPress marker is found, and the report says so in its first line. The
platform-neutral checks still run on any site: headers, cookies, mixed
content, TLS, HTTP redirect, CORS, mail DNS, `security.txt`, and the generic
half of the path list (`.env`, `.git`, backups, `phpinfo.php` and the rest).
What it does not do on any site is send a payload, so cross-site scripting,
injection and anything behind a login are out of scope by design.

### The things it gets right that a naive check does not

**Author names leak from four routes, not one.** `/wp-json/wp/v2/users` is the
one people close. `?author=N` redirects to `/author/<slug>/`; the users sitemap
and oEmbed's `author_name` publish display names. All four are read. oEmbed is
reported only when `author_name` differs from `provider_name`, since most sites
return the site name there and disclose nothing.

The report calls that field an **author slug**, not a login. It is WordPress's
`user_nicename`, which is seeded from the login at registration but is editable
independently and is commonly set from the display name by importers. Proving
it equals the login needs a login-error oracle, which is a POST. The tool will
not claim what it did not measure.

**The REST index is a better plugin inventory than the page HTML.** A plugin
appears in the HTML only if it loads an asset on the page you fetched; any
plugin with an API registers a namespace regardless. On one live site the
homepage named 4 plugins and `/wp-json/` revealed 10.

**A plugin's version must be read from more than one page, and with the cache
defeated.** Asset URLs carry the version, but an edge cache serves whatever was
cached when the page was built. Every page here is requested with a throwaway
query string and the cache header is recorded beside the number. And one page
is not the site: reading a single page on one live site reported a form plugin
as present on one page when it was on 41, understating the public surface of a
vulnerable plugin by a factor of forty.

**Two sources are used for vulnerabilities, and they are trusted for
different things.** `api.wordpress.org` is first-party and authoritative for
what the plugin directory ships today: the current release, the last release
date, the core version the author declares tested, and whether the plugin has
been **closed** — pulled from the directory, which is frequently a security
removal and which WordPress never warns the administrator about.
`wpvulnerability.net` supplies the published CVEs and their CVSS scores. Both
are unauthenticated, so the tool still needs nothing installed and no key.

**A vulnerability database says the same thing about a plugin it cleared and a
plugin it has never heard of.** Both come back HTTP 200 with a null
vulnerability list; only the record's name field separates them. Read the
obvious way, every premium, custom-built and renamed plugin on the site earns a
green tick, and so does every typo in a slug. The tool tracks coverage per
component and the report carries a **Coverage gaps** finding naming everything
it could not check. A component listed there has not been cleared; it has not
been examined.

**A withdrawn plugin is served as HTTP 404.** wordpress.org answers a plugin
it has closed with a 404 whose body says `error: "closed"`, which is the same
status it gives a plugin that never existed. Reading only 200 responses throws
away the single most useful signal the API has: on a live site it reported two
plugins closed for cause as merely "not in the directory (premium, custom, or
renamed)". The body decides, not the status.

**Version ranges are compared numerically, not as strings.** A string
comparison puts 1.10 below 1.9 and clears a plugin sitting inside the affected
range. A prerelease sorts below the release it precedes, so a `< 6.6.0` range
still catches `6.6.0-beta1`. A range the tool cannot interpret is counted and
disclosed rather than silently dropped, because an undecided record read as a
pass is the same bug as the one above wearing a different hat.

**wordpress.org's release list for a plugin is not always complete.** It
returned 11 versions topping out at 1.7 for a plugin then shipping 8.0.4, which
turned "two major versions behind" into "0 releases behind". The tool gives a
release count only when the list demonstrably reaches the current release, and
otherwise says plainly that the plugin is behind without inventing a number.

**A short REST page is not the last page.** WordPress filters items out of a
page *after* slicing it, so page 1 of a 1,250-item library can legitimately
return 69 rows while later pages are full. Stopping on a short page is the
obvious optimisation and it produced a report naming 2 public documents where
there were 35. Only an empty list, or the HTTP 400 WordPress returns past the
last page, marks the end.

**And the complete walk still need not reach the whole library.** On one live
site `X-WP-Total` said 1,250 and thirteen full pages returned 875. The report
states that gap rather than quietly reporting the smaller number, because
"absent from the walk" is a far weaker claim than "absent from the library".

**The media library is not the filesystem.** Files uploaded by an older
install, or deleted from the library while the file stayed on disk, appear in
neither the REST response nor wp-admin, so the Media screen cannot delete them.
They stay downloadable and search engines keep them indexed. The tool finds
these only when you feed it a URL with `--url`; the authoritative inventory is
a directory walk on the server, which this tool deliberately does not do. The
report names the command.

**A cron endpoint answering is not a finding either.** `wp-cron.php` responds
on every WordPress site by default and returns an empty body, so a 200 there
discloses nothing at all — no file contents and certainly no PHP source. It was
briefly listed among "paths readable that should not be", where a 0-byte 200
read to a client as though source code had been served. It is now reported as
context beside XML-RPC, with what it actually costs: anyone can trigger it as
often as they like and each call does real work.

**An installer answering is not a finding.** `/wp-admin/install.php` responds
on every WordPress site. It matters only if it still offers to install;
"Already Installed" is the safe response and reporting it sends a client a
false positive.

**A themed 404 can return 200.** Checking status alone reports every missing
path as reachable. A directory is treated as listed only when the body says
`Index of /`, because an empty 200 from an `index.php` exposes nothing.

## Calibration, and why the report talks about it

Before probing anything, the tool requests three filenames that cannot exist
and records how the site answers: the status, whether it redirects, and a
fingerprint of the body.

The fingerprint strips the requested path out of the body, replaces digits and
hex tokens with a placeholder, and collapses whitespace. That matters because
comparing raw response lengths, which is the obvious approach, fails twice: a
404 page carrying a nonce never matches itself, and a 404 page that echoes the
requested filename never matches a probe of a different length. Both shapes
exist in the wild and both make the whole calibration useless.

Then it runs a **positive control**. It requests `/robots.txt`, a file that
exists on essentially every site, and confirms that the same filtering still
classifies it as present. A site with no `robots.txt` gets two more tries,
core jQuery and `wp-login.php`, and if none of them answers the report says
the control could not run. Without this, a calibration that suppressed
everything would produce an empty report that reads as a clean result. The
report states the outcome of the control either way, including "not run".

Where a file has a known shape, the body has to have it. A 200 at
`/backup.sql` with no SQL in it, or at `/wp-admin/install.php` with a bot
challenge instead of the install form, is recorded as "answered, unexpected
content" and never as readable. A 200 with an empty body is reported, but as
its own INFO finding rather than in the severity table: nothing was read.

If the site's not-found answer cannot be pinned down, path findings are
reported as **unverified** with instructions for a human to settle them, rather
than reported as real or silently dropped. Both of those are ways of lying
about what was measured.

Two related traps have their own guard at startup. Passing an `http://`
address for a site that redirects to HTTPS is catastrophic and silent: every
real file 301s exactly like a missing one, all of them are discarded, and the
run exits 0 saying nothing is reachable. The scheme is upgraded and the
report says it happened. The same applies to `example.com` when the site
lives at `www.example.com`; the `www` host is adopted and the report says
so. A root that redirects to a different host altogether is refused with a
message naming the host to run against, because one run audited a
redirect-only hostname and described another site's homepage as its
`wp-cron.php`.

## Severity

Severity describes what an attacker gains, not how hard the fix is.

- **CRITICAL** — someone can take the site over today. A readable backup
  archive or database dump is here, because it contains `wp-config.php` and
  every password hash.
- **HIGH** — material help towards that: account names to guess against,
  server configuration, or documents that are both invisible to the admin
  screens and named like something worth protecting.
- **MEDIUM** and **LOW** — hardening. Worth doing, not worth an evening.
- **INFO** — context you should know rather than something to fix.

These ratings are the author's and are not benchmarked against any standard.
Two are deliberately lower than most scanners put them, and the report says why
in the finding itself. Missing HSTS is MEDIUM rather than HIGH on a site that
already redirects HTTP to HTTPS, because exploiting it needs an attacker
already on the network path at a first visit. Missing `X-Frame-Options` is LOW
on a site with no logged-in state-changing screens, and it is the legacy
control anyway; a CSP `frame-ancestors` rule is the modern one.

Filename matching is the other place severity is split deliberately. A flagged
filename on its own is MEDIUM, because a name is not evidence of contents and
some of that list will be marketing material that is public on purpose. A
flagged filename on a document that is *also* absent from the media library is
HIGH, because nobody inside WordPress can see it to review it.

## Usage

```
--site URL           Site to audit. https:// is assumed if you omit a scheme.
--output-dir PATH    Root folder for run directories (default ./wp_audit_runs)
--run-dir PATH       Resume an existing run; completed modules are skipped
--only KEYS          Comma-separated module keys to run
--skip KEYS          Comma-separated module keys to skip
--url PATH           An extra document to check, for a file found some other
                     way such as through a search engine. Repeatable, and
                     remembered across resumes.
--force              Re-collect modules that already completed
--render-only        Re-run checks and render from an existing --run-dir
--list               Print the module registry and exit
--no-open            Do not open the report in a browser (headless, cron)
--no-colour          Plain console output
--selftest           Run the logic tests and exit; no network
```

### Worked examples

```sh
# The ordinary run.
python3 wp_audit.py --site https://www.example.com

# A large media library, or a site you would rather not walk fully.
python3 wp_audit.py --site https://www.example.com --skip media,documents

# Add files a search engine knows about but the media library does not.
# Search first:  site:example.com/wp-content/uploads filetype:pdf
python3 wp_audit.py --site https://www.example.com \
    --url /wp-content/uploads/2015/06/staff-handbook.pdf \
    --url /wp-content/uploads/2017/11/rate-card.pdf

# Resume after an interruption. Completed modules are not re-fetched.
python3 wp_audit.py --run-dir wp_audit_runs/www_example_com_20260903_190000

# Change a finding's wording and re-render without touching the network.
python3 wp_audit.py --run-dir wp_audit_runs/www_example_com_20260903_190000 \
    --render-only

# Scheduled, gated on severity.
python3 wp_audit.py --site https://www.example.com --no-open --no-colour \
    || echo "critical or high findings; see the report"
```

### How a run behaves

Modules run in order and each writes its own JSON as it completes, so an
interrupted run keeps everything it collected. Ctrl-C stops after the current
request rather than mid-write; a second Ctrl-C aborts immediately. Re-running
with `--run-dir` skips whatever already finished.

A module that raises does not end the run. It is recorded as `error` with the
exception, and it appears in the report's Coverage gaps table so absence from
the findings is never mistaken for a clean result.

Calibration is the one module that can stop another. If its control check
fails, the paths module is skipped rather than run against a signature that
would suppress real findings, and the report says so.

Typical timings on a small site: 3 to 5 minutes, most of it in `paths` (43
requests, each made twice so the redirect is visible) and `assets` (up to 80
sitemap pages).

## Things the report states rather than hides

- Which modules did not run, and why, including "not applicable" when the
  site is not WordPress.
- What sits in front of the site (Cloudflare, Sucuri, Akamai, CloudFront,
  Kinsta, WP Engine and others), since a 403 may be the edge and a version
  read through a cache may lag.
- Every path that was checked, including the ones that came back clean, so
  "checked and clean" can be told from "not checked"; a probe that got no
  answer or was rate-limited is marked as such, never as clean.
- The core version from each source that disclosed it (generator tag, the
  same tag on a cache-busted request, the feed, `wp-includes` asset URLs),
  and whether they agree. A core vulnerability finding keeps its CVSS
  severity only when two sources agree; otherwise it is capped and says why.
- How the site answers a path that cannot exist, and whether the control proved
  the calibration still lets real files through.
- Whether the media walk reached the whole library, and by how much it fell
  short if not.
- Whether any page was served from cache during the version sweep, which would
  make its version number stale.
- Which components could not be checked against the vulnerability data, and
  why, so a missing vulnerability finding is not read as a clean one.
- Where its vulnerability data came from, since that data is a third-party
  aggregate with no published freshness guarantee.
- That the scheme was upgraded from `http://`, if it was.
- That the whole exercise is read-only and external, in the report's own words,
  so nobody reads a quiet result as a clean bill of health.

## Tests

```sh
python3 wp_audit.py --selftest
```

Seventy-odd assertions against synthetic responses, no network. They cover the
shapes that have each produced a wrong report: the redirecting site, the soft
404 that echoes the requested path, the unstable 404 that cannot be
calibrated, the installer that answers on every site, the WAF challenge page
served with a 200, the empty directory, the real but empty file, the response
that sets several cookies, the REST index larger than a page, the plugin that
ships its own assets under several version strings, the HTML escaping of
evidence rows, version ordering across 1.9 and 1.10, every vulnerability-range
operator the feed actually uses, and the vulnerability record whose "no data"
must not read as "no vulnerabilities".

They prove the decision logic, not the network behaviour. A response shape none
of them models is a real gap, and the useful contribution is a new assertion
rather than a fix to one that already passes.

## Requirements

Python 3.9 or newer. Nothing to install.

`dig` is used for the DNS module when it is on PATH, with a DNS-over-HTTPS
fallback to `dns.google` when it is not, so the module works either way.

## Licence

Apache 2.0, full text in `LICENSE`. Free for commercial use, modifiable and
redistributable, closed-source derivatives allowed. Keep the attribution block
at the top of `wp_audit.py` intact if you redistribute it: that is the one real
obligation the licence puts on you (clause 4(c)), and it is what lets users
find the original author. "OSH", "Outsource House" and "Taming.Tech" are
trademarks and are not licensed for use in your own product names (clause 6).

No warranty. You assume all risk.

Paul Ogier, [Outsource House](https://osh.co.za). Training at
[Taming.Tech](https://taming.tech).
