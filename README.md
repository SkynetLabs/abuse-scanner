# Abuse Scanner

The abuse scanner is a project which will monitor a mailbox and periodically
scan it for reported (abusive) skylinks.

## Architecture

The scanner used a MongoDB database in which it persists two types of entities:
- emails: used to persist the email and some state variables
- locks: used for distributed locking

The database name is `abuse-scanner`
  
The scanner is comprised of 4 main modules:
- the `fetcher`: downloads the emails from the mailbox
- the `parser`: parses abusive skylinks and tags from the email body
- the `blocker`: blocks the skylinks using the blocker API
- the `finalizer`: finalizes the emails

The modules communicate through a shared database and a series of `boolean`s
that define whether a certain module has handled the email in question, e.g.
`parsed`, `blocked` and `finalized`.

## Environment

- ABUSE_LOG_LEVEL=
- ABUSE_MAILBOX=
- ABUSE_SPONSOR=
- BLOCKER_HOST=
- BLOCKER_PORT=
- BLOCKER_AUTH_HEADER=
- EMAIL_SERVER=
- EMAIL_USERNAME=
- EMAIL_PASSWORD=
- SERVER_DOMAIN=
- SKYNET_DB_HOST=
- SKYNET_DB_PORT
- SKYNET_DB_USER=
- SKYNET_DB_PASS=
