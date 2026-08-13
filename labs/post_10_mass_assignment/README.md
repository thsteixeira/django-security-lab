# Lab 10 — Mass Assignment (over-posting)

Companion lab for the blog post
**[Mass Assignment: How Over-Posting Rewrites Fields Your Form Never Showed](https://thiagoteixeira.tech/blog/mass-assignment-how-over-posting-rewrites-fields-your-form-never-showed-and-how-explicit-field-lists-stop-it/)**
(Series II).

| | |
|---|---|
| **OWASP** | A08:2021 — Software & Data Integrity Failures (CWE-915) |
| **CWE** | CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **ASVS** | V5.1.2 — the application is protected against mass parameter assignment |
| **Detection** | SAST — the standard tools **miss** the class (Bandit 0, Semgrep community **and** registry 0), so the **custom rule** [`rules/mass_assignment.yaml`](../../rules/mass_assignment.yaml) — **shared with Lab 07** — flags `fields='__all__'`, asserted in the hermetic CI job |

This is the DRF sibling of **Lab 07 (privilege escalation)**. Same sink —
`fields = '__all__'` — but where Lab 07 over-posts a *permission* field (`role`)
to escalate, Lab 10 over-posts *ordinary business* fields (`price`, `paid`,
`owner`) to break the integrity of a record. That difference is why the two
labs sit under different OWASP categories (A01 vs A08) while sharing one rule.

## The two views

A customer order API. The only field a customer may legitimately change is
`quantity`; `price` comes from the catalogue, `paid` from the payment webhook,
`status` from fulfilment, and `owner` is the account the order belongs to.

| View | File | What it does |
|---|---|---|
| Vulnerable | [`views_vulnerable.py`](views_vulnerable.py) | `OrderSerializer(Meta.fields = '__all__')` on a `ModelViewSet` — every column is writable |
| Secure | [`views_secure.py`](views_secure.py) | `CustomerOrderSerializer(fields=[...], read_only_fields=[...])` — only `quantity` is writable; over-posts are dropped |
| Flag gate | [`views_receipt.py`](views_receipt.py) | `receipt/<pk>/` returns the flag **only** for an order in the forged *free-and-paid* state |

The vulnerable serializer binds `price`, `paid`, `status`, and `owner` straight
from the request body, so a PATCH with those keys rewrites them. The flag lives
behind a state the legitimate flow can never produce — an order that is **both
paid and free** — so capturing it *is* the integrity violation. The secure
serializer lists only the fields the customer may touch and marks the rest
`read_only`; DRF strips the over-posted keys from `validated_data` before
`save()`, so the request still returns `200` but the tampered values never land.

## Run it

From the repository root (the folder with `docker-compose.yml`):

```bash
docker compose up -d          # Postgres + Django on http://127.0.0.1:8000 (background)
docker compose exec web python manage.py seed_labs   # plants a pending order + the flag
```

`seed_labs` prints the seeded order's primary key — use it in the URLs below.
On Windows PowerShell `curl` is an alias for `Invoke-WebRequest` — use `curl.exe`,
or Git Bash.

## Test the pair from the command line

Assume the seeded order is `pk=1` (substitute the pk `seed_labs` printed).

**1. Over-post the order state** — the customer PATCHes fields the form never
rendered, forging a free-and-paid order:

```bash
curl -s -X PATCH http://127.0.0.1:8000/mass-assignment/vulnerable/orders/1/ \
  -H "Content-Type: application/json" \
  --data-binary '{"quantity": 1, "price": "0.00", "paid": true, "status": "shipped"}'
# {"id":1,"quantity":1,"price":"0.00","paid":true,"status":"shipped","owner":1}
```

Now claim the receipt — the forged state opens the gate:

```bash
curl -s http://127.0.0.1:8000/mass-assignment/receipt/1/
# {"receipt":"FLAG{mass_assignment_over_posted_order_state}", ...}
```

**2. The fix holds** — the same over-post against the secure view is silently
dropped; the request still succeeds, but only `quantity` changes:

```bash
curl -s -X PATCH http://127.0.0.1:8000/mass-assignment/secure/orders/1/ \
  -H "Content-Type: application/json" \
  --data-binary '{"quantity": 2, "price": "0.00", "paid": true, "status": "shipped"}'
# {"id":1,"quantity":2,"price":"49.90","paid":false,"status":"pending","owner":1}
# 200 OK — quantity written, price/paid/status/owner untouched

curl -s http://127.0.0.1:8000/mass-assignment/receipt/1/
# {"receipt":null,"detail":"Nothing forged: this order is not both paid and free.", ...}
```

Or prove all of it in one command (from the repo root):

```bash
docker compose run --rm web python manage.py test labs.post_10_mass_assignment
```

## The fix

Never let a serializer or form bind columns the client has no business writing.
Name the writable fields explicitly, and mark the rest read-only:

```python
class CustomerOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["id", "quantity", "price", "paid", "status", "owner"]
        read_only_fields = ["id", "price", "paid", "status", "owner"]
```

`fields` controls what the serializer *knows about*; `read_only_fields` controls
what it will *write*. Prefer an allowlist (`fields`) to a denylist (`exclude`):
a new column added to `Order` next quarter is invisible to the allowlist until
someone deliberately adds it, whereas `exclude` would silently start accepting
it. And set ownership/state fields server-side — `order.owner = request.user`,
not from the payload.

## Isolation

This lab teaches mass assignment and nothing else. The API is intentionally open
(`AllowAny`, no auth/CSRF) so a single `curl` PATCH reproduces the bug — the
vulnerability is the *field binding*, not the access control, so adding auth
would only obscure the lesson. `owner` is a real FK so the write-side ownership
reassignment (the twin of the IDOR read in Post 6) is demonstrable, but the
flag is gated on the *state* forgery (paid-and-free) rather than on ownership,
to keep this clear of Lab 06's territory. No raw SQL; DRF renders JSON, so
there is no output-escaping surface.

## Scanning it

Mass assignment is a textbook class, yet the standard SAST tools miss **this**
sink — and the post's own draft got the reason wrong, which is the lesson. Full
evidence and reproduction under [`scans/`](scans/) and
[`scans/README.md`](scans/README.md).

```bash
bandit -r labs/post_10_mass_assignment/
semgrep scan --config p/django --config p/python --config p/owasp-top-ten \
  labs/post_10_mass_assignment/views_vulnerable.py
semgrep scan --config rules/mass_assignment.yaml labs/post_10_mass_assignment/views_vulnerable.py
```

- **Bandit** → **0** on the views/serializers (only `B106` noise on the test
  password). A serializer field list is not a dangerous *call*, so no plugin
  looks at it.
- **Semgrep community** (`p/django`, `p/python`, `p/owasp-top-ten`) → **0** on
  the `fields='__all__'` serializer. The registry tier (`r/python.django`,
  `r/python`) → **0** too. Despite what the post's draft claimed, **no shipped
  Semgrep rule catches this** — the tools that do are Django linters (Ruff
  `DJ007`), and even those are `ModelForm`-scoped.
- **The custom rule** ([`rules/mass_assignment.yaml`](../../rules/mass_assignment.yaml),
  **shared with Lab 07**) fires on the vulnerable serializer (line 25) and is
  **silent** on the secure one. It keys on `fields = "__all__"` inside a
  `class Meta`, so it is framework-agnostic. Its limit (the `exclude` denylist
  variant is out of scope) is a documented `todoruleid` in `rules/mass_assignment.py`.

Bandit and Semgrep are pinned but **not bundled in the lab image**. Install them
on the host — `pip install bandit==1.9.4 semgrep==1.170.0` — and run them there;
SAST reads the source directly. All commands run from the repository root.
