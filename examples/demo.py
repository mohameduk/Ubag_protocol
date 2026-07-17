"""
UBAG Web Layer — end-to-end demo (Python).

    cd ubag-python
    pip install -e ".[fastapi]"
    python ../examples/demo.py

Spins up a UBAG-protected FastAPI site in-process (no ports, no network) and walks
one autonomous agent through the entire handshake:

    challenged → identity verified → site policy approves → credentialed → JSON-LD

Then shows the JWKS any other site would use to verify this issuer's credentials,
and that a human browser passes through untouched.
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.testclient import TestClient

from ubag import AgentCredential, UBAGMiddleware, generate_issuer_keypair

# The site is its own credential issuer (generate once, persist in real life).
ISSUER_PRIVATE, _ = generate_issuer_keypair()
agent = AgentCredential.generate(owner="demo@agent.dev")

app = FastAPI()


@app.get("/")
def home():
    return HTMLResponse("<h1>Acme Widgets</h1><p>We sell premium widgets.</p>")


app.add_middleware(
    UBAGMiddleware,
    issuer_key=ISSUER_PRIVATE,
    server_secret="demo-only-separate-server-secret",
    authorize_agent=lambda identity, request: identity["agent_id"] == agent.agent_id,
    site_meta={"name": "Acme Widgets", "type": "Store",
               "description": "We sell premium widgets"},
)

client = TestClient(app)
AGENT_UA = {"User-Agent": "python-httpx/0.27 ubag-demo-agent"}


def step(title: str) -> None:
    print("\n" + "=" * 66 + f"\n{title}\n" + "=" * 66)


# 0 — discovery
step("0. Agent discovers the site via /.well-known/ubag.json")
print(client.get("/.well-known/ubag.json").json())

# 1 — cold request is challenged
step("1. Unknown agent requests /  ->  Branch C (challenge)")
r = client.get("/", headers=AGENT_UA)
print("status:", r.status_code, "| branch:", r.headers.get("X-UBAG-Branch"))
challenge = r.json()["ubag_challenge"]
print("nonce:", challenge["nonce"][:24], "...  algo:", challenge["algo"])

# 2 — agent signs the nonce with its Ed25519 private key
step("2. Agent signs the nonce with its Ed25519 private key")
print("agent id:", agent.agent_id)
solution = agent.solve_challenge(challenge)
print("signature:", solution["signature"][:24], "...")

# 3 — post the solution, issuer mints a credential
step("3. POST /ubag/verify  ->  identity verified, policy approves, credential issued")
r = client.post("/ubag/verify", json=solution)
credential = r.json()["credential"]
agent.set_credential(credential)
print("status:", r.status_code, r.json()["status"], "| credential:", credential[:32], "...")

# 4 — re-request WITH the credential, get clean JSON-LD
step("4. Agent requests /  WITH credential  ->  Branch B (JSON-LD)")
r = client.get("/", headers={**AGENT_UA, **agent.headers("GET", "http://testserver/")})
print("status:", r.status_code, "| branch:", r.headers.get("X-UBAG-Branch"))
print(r.json())

# 5 — any other site verifies this issuer's credentials via JWKS, no shared secret
step("5. /.well-known/jwks.json  ->  public key for sites that trust this issuer")
print(client.get("/.well-known/jwks.json").json())

# 6 — a human browser is untouched
step("6. A human browser  ->  Branch A (served the normal page)")
r = client.get("/", headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html"})
print("status:", r.status_code, "| body:", r.text[:48])

print("\nDone: challenged -> identity verified -> policy approved -> credentialed -> JSON-LD.\n")
