# Abuse Scanner

The abuse scanner is a project which will monitor a mailbox and periodically
scan it for reported (abusive) skylinks.

## Architecture

The scanner used a MongoDB database in which it persists 3 types of entities:
- emails: used to persist the email and some state variables
- locks: used for distributed locking
- reports: NCMEC reports

The database name is `abuse-scanner`
  
The scanner is comprised of 4 main modules:
- the `fetcher`: downloads the emails from the mailbox
- the `parser`: parses abusive skylinks and tags from the email body
- the `blocker`: blocks the skylinks using the blocker API
- the `finalizer`: finalizes the emails
- the `reporter`: reports csam abuse to NCMEC

The modules communicate through a shared database and a series of `boolean`s
that define whether a certain module has handled the email in question, e.g.
`parsed`, `blocked` and `finalized`.

## NCMEC

All emails that are tagged with the `csam` are emails from which we want to
report the skylinks to [NCMEC](https://report.cybertip.org/ispws/documentation/)

In order for this to happen, the `ABUSE_NCMEC_REPORTING_ENABLED` has to be set
to `true` and all `NCMEC` related environment variables have to be filled in
accordingly.

## Environment

- `ABUSE_LOG_LEVEL`
- `ABUSE_MAILADDRESS`
- `ABUSE_MAILBOX`
- `ABUSE_NCMEC_REPORTING_ENABLED`
- `ABUSE_PORTAL_URL`, e.g. `https://siasky.net`
- `ABUSE_SPONSOR`
- `SKYNET_ACCOUNTS_HOST`, e.g `accounts`
- `SKYNET_ACCOUNTS_PORT`, e.g `3000`
- `BLOCKER_HOST`
- `BLOCKER_PORT`
- `EMAIL_SERVER`
- `EMAIL_USERNAME`
- `EMAIL_PASSWORD`
- `NCMEC_USERNAME`
- `NCMEC_PASSWORD`
- `NCMEC_REPORTER_FIRSTNAME`
- `NCMEC_REPORTER_LASTNAME`
- `NCMEC_REPORTER_EMAIL`
- `NCMEC_DEBUG`
- `SERVER_DOMAIN`
- `SKYNET_DB_HOST`
- `SKYNET_DB_PORT`
- `SKYNET_DB_USER`
- `SKYNET_DB_PASS`
