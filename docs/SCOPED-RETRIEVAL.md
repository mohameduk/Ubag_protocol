# Scoped retrieval

**Status:** implemented, measured, open. Free to use, free to implement, no
dependency on any vendor including us.

An agent that wants a product's price is sent the whole product page, because
the page has no way to answer a narrower question. Everything else on that page
is boilerplate the agent pays to read and then discards.

Scoped retrieval is a query parameter that lets a page answer the question it
was actually asked.

```
GET /boutique/manteau-3391?ubag.fields=offers.price,offers.availability
```

```json
{
  "@context": "https://schema.org",
  "ubag:protocol": "S-UX/2.0",
  "url": "https://shop.example.com/boutique/manteau-3391",
  "name": "Manteau 3391",
  "offers.price": "689.00",
  "offers.availability": "https://schema.org/InStock"
}
```

## What it costs today, and what it costs scoped

Measured on 63 ground-truth questions against a live gateway, with real API
calls and token counts taken from each provider's own `usage` field. Answers
were scored against fixed ground truth, not judged by a model.

| provider | model | today | scoped | reduction | accuracy |
|---|---|---|---|---|---|
| OpenAI | gpt-4o-mini | 2,695 tok | 215 tok | **12.5x** | 41/63 both |
| Google | gemini-2.5-flash | 2,895 tok | 238 tok | **12.1x** | 43/63 both |

Two providers, two tokenizers, the same result, with **no loss of accuracy**.
The absolute scores differ between models and the fixture's questions are
deliberately strict; what matters is that both paths score identically within
each provider.

On real third-party pages the gap is wider still, because real pages are
heavier. Measured 2026-08-22 in a browser: an allrecipes page is 1.48 MB of
HTML that renders 19,082 characters of text, and its raw HTML alone exceeds a
200k context window.

## Why this is free

The value of an agent identity grows with the number of sites that answer one.
A retrieval saving reachable only through a single vendor is worth nothing to
an agent builder, and nothing to a standard.

Implement it yourself. Use our SDK if it saves you time. Neither requires
anything from us.

## Parameters

All three are opt-in. A request with no `ubag.*` parameter returns exactly what
the resource returned before, so adding support cannot break an existing
client.

| parameter | returns |
|---|---|
| `?ubag.fields=a,b.c` | only those typed fields |
| `?ubag.manifest=1` | what this resource can answer, without answering |
| `?ubag=compact` | full facts, duplication removed |

`ubag.*` parameters are yours to consume and must not be forwarded to an
origin: at best they are ignored, at worst they poison a cache key.

### Field paths

Dotted paths into the publisher's own structured data. Lists collapse by
default, so `offers.price` finds `offers[0].price` without the caller knowing
the shape.

Where a specific element matters, index it: `openingHoursSpecification[1].opens`.
Indices are relative to each JSON-LD block, so a caller never needs to know how
many `<script type="application/ld+json">` tags a page carries.

### Two rules that are not optional

**No model runs on the server side.** Resolution is deterministic lookup over
the publisher's structured data. An endpoint that interpreted natural language
would move the caller's inference cost onto the publisher, which is the cost
this exists to remove. The agent translates its own question into field paths.

**Misses are reported, never guessed.** Anything unresolvable comes back under
`ubag:unresolved`:

```json
{"name": "Manteau 3391", "ubag:unresolved": ["startDate"],
 "ubag:full_payload": "?ubag=full"}
```

An agent must be able to tell *"this resource says nothing about startDate"*
from *"startDate is empty"*. A retrieval layer that blurs those two returns
confident wrong answers, and the caller has no way to detect it.

### Always name the subject

Every scoped response carries `name` whether or not it was requested.

`{"offers.price": "862.00"}` is correct and unusable: an agent that asked what
a *named product* costs cannot tell whether this price belongs to it. Handed
exactly that payload, a model answered `NOT PRESENT` rather than risk
attributing a price to the wrong item. That instinct is right and the omission
was ours. A URL identifies; it does not describe.

The anchor costs about sixteen tokens and took scoped accuracy from 34/63 to
41/63, level with reading the whole page.

## Where it does not help

Be honest about this with your own users, because they will find it otherwise.

**Pages whose answer is the prose.** Asked to summarise an article, a scoped
payload is worthless. Wikipedia exposes 729 characters of JSON-LD and 14
fields, none of them the article body.

**Pages with no structured data.** Our control page resolves 0 of 8 questions
and says so. That is the designed floor, not a bug.

**Training corpora.** A pretraining run's cost is compute over running prose.
Scoped payloads deliberately discard prose, so they make a corpus worse rather
than cheaper. There is no training saving here and claiming one will not
survive contact with an ML engineer.

## Client

```python
from ubag import Agent

agent = Agent.generate()
answer = agent.fields("https://shop.example.com/p/3391",
                      ["offers.price", "offers.availability"])
```

`Agent` completes the challenge-response, holds the passport, refreshes it
before expiry, and attaches a proof of possession to every request.

## Server

```python
from ubag import shape_payload, split_ubag_query

control, upstream_query = split_ubag_query(request.url.query)
payload = your_existing_jsonld(path, upstream_query)
body, mode = shape_payload(payload, control)
```

`shape_payload` returns the untouched payload when no `ubag.*` parameter is
present, so wiring it in changes nothing until a caller opts in.

## Proof of possession

A passport carries `cnf.jkt` (RFC 7800), which is a promise: whoever presents
this token can prove possession of the key with that thumbprint. **Verify it.**

A passport that is accepted without proof is a bearer token. Anyone who
captures one from a log, a proxy, an error report or a compromised host becomes
that agent until it expires, and your audit trail will name the wrong party for
everything they do.

Headers, over `UBAG-POP-V2`, binding the proof to this exact request:

```
X-UBAG-PoP          signature over the canonical message
X-UBAG-PoP-TS       unix seconds
X-UBAG-PoP-JTI      unique per request
X-UBAG-PoP-Version  2
```

```
UBAG-POP-V2\n{METHOD}\n{host}\n{target}\n{sha256(token)}\n{ts}\n{jti}
```

The public key does **not** travel with the proof. The verifier received
`agent_public` during `/ubag/verify` and stores it against the agent ref, so it
looks the key up by the `cnf.jkt` thumbprint. That keeps the wire smaller and
removes a whole class of confusion, at the cost of the verifier having to keep
the key it was already given.

`cnf.jkt` is what binds them: a key that does not hash to the thumbprint in the
token is rejected before any signature is checked.

Reject a proof outside a narrow time window, and record the `jti` to reject
replays. A proof that fails any check must **not** consume its `jti`, or an
attacker can burn a legitimate agent's nonces by racing it with deliberately
broken signatures.
