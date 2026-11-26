# Firebase Hosting mirror

Firebase Hosting is an **additional, independent** static source for the same
validated list. It does not replace GitHub or Cloudflare, and it is not active
in the Android build until a real deployment and real-device network tests pass.

## Current status

| Item | Status |
| --- | --- |
| Builder and tests | implemented |
| Generated deployment directory | validated locally, git-ignored |
| Firebase project id | **not verified** (`ajx-vpn-servers` is a candidate) |
| Live deployment | **not performed** |
| Android activation | **not performed** |
| Turkmenistan Wi-Fi / mobile data test | **not performed** |

`https://ajx-vpn-servers.web.app/` currently returns Firebase's
`Site Not Found` page. That proves that no Hosting site is deployed there; it
does **not** prove that the project id is available. Only the Firebase Console
or CLI while authenticated can answer that question.

## Files produced

```text
firebase-hosting/
  .firebaserc
  firebase.json
  index.html
  manifest.json
  servers.txt
  servers.json
  manifest.sig     # only when the publisher signed the manifest
```

`servers.txt` remains the primary format v2 file, `servers.json` the
compatibility fallback, and `manifest.json` the integrity document. The builder
refuses to publish unless the manifest hashes, record counts, both list formats
and the metadata agree on the exact committed dataset.

`firebase.json` serves the deployment directory itself and ignores its own
configuration. The list and manifest files use
`Cache-Control: public, max-age=0, must-revalidate`. `index.html` uses a
five-minute cache. The builder validates these rules and refuses rewrites or
redirects, so a missing path cannot be replaced by an HTML error page.

## Account-level setup (owner action required)

1. Sign in to <https://console.firebase.google.com/> with the Google account
   that should own the project.
2. Create a project on the **Spark (free)** plan. Do not enable Blaze, Cloud
   Functions, Cloud Run or billing.
3. Verify the project id in **Project settings**. If `ajx-vpn-servers` is taken,
   choose a globally unique id, then update `PROJECT_ID` and `FIREBASE_HOST` in
   `scripts/build_firebase_hosting.py` and rebuild.
4. Enable **Hosting** for the project. The default site is
   `<project-id>.web.app`; do not purchase a custom domain.
5. Create a service account for deployment:
   - Google Cloud Console -> IAM & Admin -> Service Accounts.
   - Grant only **Firebase Hosting Admin** (`roles/firebasehosting.admin`).
   - Create one JSON key, copy its contents directly into the GitHub secret
     described below, then delete the local key file.
6. In the GitHub repository, open **Settings -> Secrets and variables ->
   Actions** and add:
   - `FIREBASE_SERVICE_ACCOUNT`: the complete service-account JSON.
   - `FIREBASE_PROJECT_ID`: the verified project id.
7. Run **Actions -> Deploy server list to Firebase Hosting -> Run workflow** on
   `main`.

Never paste a key, token or password into an issue, a commit, a report or a chat
message. The workflow never prints the service-account secret.

## Local deployment (alternative to the workflow)

```bash
python -m unittest discover -s scripts -p "test_*.py" -v
python scripts/build_firebase_hosting.py --root . --output firebase-hosting
npx --yes firebase-tools@latest login
npx --yes firebase-tools@latest deploy --only hosting \
  --project <PROJECT_ID> --config firebase-hosting/firebase.json
```

The local CLI and the GitHub Action both deploy only static Hosting assets. No
server-side code, database, function or paid resource is used.

## Live verification required after deployment

The workflow checks all of the following and fails if any check does not hold:

- DNS resolves and is not loopback;
- `/servers.txt`, `/servers.json`, `/manifest.json` and `/index.html` return
  HTTP 200;
- downloaded bytes equal the validated local dataset;
- every manifest size and SHA-256 matches, including the manifest itself;
- both list formats contain the same records, the same count and all 21 TXT
  columns;
- the response contains no HTML error page;
- `Content-Type`, `Cache-Control`, `X-Content-Type-Options` and CORS headers are
  correct;
- `/firebase.json` and `/.firebaserc` are **not** publicly reachable;
- at least one validator (`ETag` or `Last-Modified`) is present, and a
  conditional request returns HTTP 304.

The actual header and validator behaviour of Firebase Hosting is recorded from
the live response; it is not assumed to match Cloudflare or GitHub.

## Android activation gate

Do not enable Firebase in the Android build until:

1. the live deployment passes every check above;
2. the URLs open with the VPN **off** on Turkmenistan Wi-Fi;
3. the URLs open with the VPN **off** on mobile data;
4. the phone uses no custom DNS, proxy, router or carrier workaround;
5. the source order and fallback tests still pass with the new URL.

Until then, `github.servers.independentMirror.txt.url` and
`github.servers.independentMirror.json.url` stay blank and
`github.servers.preferIndependentMirror` stays `false`. When enabled later,
GitHub remains the manifest authority; a mirror can serve bytes but cannot
redefine integrity.
