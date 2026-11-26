# Security policy

## Supported versions
Only the latest commit on `main` is maintained. This is a portfolio project, not a released product.

## Reporting a vulnerability
Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's Security tab) if it is shown, or contact the maintainer through the GitHub profile `@faroukkhaled`. I will answer when I can. There is no bug bounty and no guaranteed response time.

## What counts
`ir-threat-hunting` parses event files, builds HTML reports and keeps a SQLite case store. Crashes, report HTML injection and SQL handling bugs are in scope.

Findings about the detection rules themselves (missed attacks, false positives) are normal bugs: open a regular issue.

## Safe use
All sample data is synthetic or from public datasets. Do not put real credentials, customer data or production logs in issues or pull requests.
