# Optional Stripe Support for Hobbit-NG

Hobbit-NG is free and open source. Donations are optional and do not unlock, restrict, prioritize, or otherwise change any product capability.

## Recommended model

Use a Stripe-hosted **Payment Link** rather than embedding card collection into Hobbit-NG. This keeps payment handling outside the security application and means Hobbit-NG does not need Stripe secret keys, webhook secrets, card fields, or a Stripe SDK at runtime.

Recommended configuration:

- Product name: `Support Hobbit-NG Open Source`
- Payment type: one-time
- Currency: USD
- Amount: customer chooses amount
- Suggested amount: $10
- Minimum: $1
- Optional maximum: $1,000
- Payment Link submit type: Donate
- Completion text: make clear the donation is optional and does not unlock features

Do not describe contributions as tax-deductible unless you have separately confirmed that status with the appropriate legal/tax structure.

## Sandbox first

Create and test the Payment Link in Stripe sandbox/test mode before enabling a live link. Test links normally contain a Stripe test path and must not be presented to users as a real donation destination.

## Go live

After creating the live Payment Link in your live Stripe account, set only the public hosted URL:

```bash
export HOBBIT_DONATION_URL="https://donate.stripe.com/<your-live-link>"
```

Or provide the same environment variable to Docker/Kubernetes at deployment time.

Hobbit-NG validates that the configured URL is HTTPS and hosted under `stripe.com`. If the variable is missing or invalid, donation support is treated as unconfigured and no prompt appears.

## CLI behavior

Show support information at any time:

```bash
python hobbit.py --support
```

After a successful **interactive** scan, when a valid donation URL is configured, Hobbit-NG can show:

```text
Hobbit-NG is free and open source. If it helps you, an optional donation can support continued development, testing, documentation, and maintenance.
Support Hobbit-NG? [d] Donate / [Enter] Skip:
```

- `d`, `donate`, `y`, or `yes` prints the Stripe donation URL.
- Enter or any other response skips the request.
- `--no-support-prompt` suppresses the prompt for that run.
- CI, cron, Celery workers, redirected stdin/stdout, and other non-interactive environments never receive the prompt.
- No capability is ever gated by donation status.

## API behavior

`GET /support` returns public support metadata such as whether a valid Stripe Payment Link is configured. It does not expose API keys or payment records and does not require authentication because the information is intended to be public.

## Secrets

Do **not** commit:

- Stripe secret keys (`sk_...`)
- restricted keys (`rk_...`)
- webhook signing secrets (`whsec_...`)
- customer/payment data

This integration needs none of those values. Only the public Payment Link is configured.

## GitHub Sponsors/FUNDING

Once a live donation URL exists, you can optionally add it as a custom GitHub funding link in `.github/FUNDING.yml`. Do not put a sandbox/test Payment Link there.
