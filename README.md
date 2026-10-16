# FIDO Metadata Explorer

[Open Web Application](https://adricasti.github.io/fido-metadata/)

This is a static web page application to show in a user-friendly way the same information that you can get from `https://mds3.fidoalliance.org/` and that your authentication backend should be using to validate FIDO2 authenticators.

## Metadata auto-update

This repository includes a GitHub Actions workflow that updates `mds_metadata.json` and `convenience-metadata.json` automatically:

- Schedule: every month on the 10th day (06:00 UTC).
- Manual trigger: available via **Actions** -> **Update FIDO Metadata** -> **Run workflow**.

How it works:

1. Downloads the JWT from `https://mds3.fidoalliance.org`.
2. Decodes only the JWT payload (the middle section).
3. Writes the payload as formatted JSON into `mds_metadata.json`.
4. Downloads the convenience metadata dictionary from `https://c-mds.fidoalliance.org` and writes it to `convenience-metadata.json`.
5. Commits and pushes only when either file changed.

The payload extraction and convenience metadata refresh are handled by `scripts/update-mds-metadata.js`, so no manual header/signature cleanup is needed.