# ots.jakvab.se — One-Time Secret

Zero-knowledge engångsdelning av hemligheter. Krypteras i webbläsaren (AES-256-GCM);
nyckeln ligger i URL-fragmentet och når aldrig servern. Servern lagrar bara chiffertext
(krypterad även i vila) och raderar atomiskt vid läsning.

## Struktur
```
ots/
├── index.html        # skapa-vy
├── s.html            # visa-vy (engångsläsning)
├── css/style.css
├── js/crypto.js      # Web Crypto-hjälpare (AES-GCM)
├── js/app.js         # create + reveal-logik
├── favicon.svg
└── infra/
    ├── ots-lambda.mjs  # backend (Node 20, DynamoDB)
    └── deploy.sh       # S3 sync + CloudFront-invalidation
```

## Krypto
- Skapa: AES-256-GCM-nyckel + 96-bit IV i webbläsaren. `base64(IV‖ciphertext)` skickas till servern.
  Nyckeln (base64url) läggs i länkens `#`-fragment: `https://ots.jakvab.se/s.html?id=<id>#<nyckel>`.
- Visa: nyckeln läses från `location.hash`, chiffertexten hämtas (och bränns) via API:t, dekrypteras lokalt.

## API (samma origin via CloudFront `/api/*`)
- `POST /api/secrets` — `{ ct, ttlSeconds∈{3600,86400,604800}, maxViews∈1..5, turnstileToken }` → `{ id }`
- `POST /api/secrets/{id}/reveal` — atomisk engångsläsning → `{ ct, viewsLeft }` eller `404`
- `GET  /api/secrets/{id}/meta` — `{ exists, viewsLeft }` utan att bränna, eller `404`

## Backend
- DynamoDB `ots-secrets` (PK `id`, TTL-attribut `ttl`, SSE-KMS, on-demand).
- Lambda `ots-api` (eu-north-1), env: `TABLE`, `TURNSTILE_SECRET`, `ALLOW_ORIGIN`.
- API Gateway HTTP API `$default` → Lambda. Bakom CloudFront `/api/*` (samma origin, ingen CORS).

## Deploy
```bash
BUCKET=ots-jakvab-<ACCOUNT_ID> DISTRIBUTION_ID=<dist-id> ./infra/deploy.sh
```
Bumpa `?v=N` på css/js i `index.html`/`s.html` vid ändring (immutable cache).

## Säkerhet
Öppen källkod är säkert: säkerheten beror inte på hemlig kod. Turnstile site-key är publik;
secrets (Turnstile) ligger i Lambda-env, aldrig i repot. Nyckeln finns aldrig på servern.
