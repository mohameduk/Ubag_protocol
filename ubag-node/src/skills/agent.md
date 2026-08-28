---
name: ubag-agent
description: Reading websites as an autonomous agent through UBAG scoped retrieval. Read before writing code that fetches a web page to extract a fact from it.
ubag_skill_version: {{ubag_version}}
---

# UBAG, agent side

If this agent fetches a web page in order to extract one fact from it, ask the
page for the fact instead.

A page fetched normally returns everything: navigation, cookie banner, footer,
related articles. The agent then pays input tokens on all of it to find the one
number it came for. Measured live in this project against two providers on 63
ground-truth questions:

```
fetch and extract the page   2,695 input tokens   41/63 correct
ask for the fields             215 input tokens   41/63 correct
```

12.5x on gpt-4o-mini, 12.1x on gemini-2.5-flash, accuracy unchanged. `?ubag=lean`
is a further 2.1x smaller than the enveloped form and carries identical facts.

Those figures come from one measured run in this repo. Treat them as the reason
to use the layer, not as a guarantee for a site nobody has tested.

## The three calls

```python
from ubag import Agent

agent = Agent.generate()
answer = agent.fields("https://shop.example.com/p/3391",
                      ["offers.price", "offers.availability"])
```

```js
const { Agent } = require('ubag-web');

const agent = Agent.generate();
const answer = await agent.fields('https://shop.example.com/p/3391',
                                  ['offers.price', 'offers.availability']);
```

| call | returns |
|---|---|
| `fields(url, [...])` | only those typed fields, plus the subject they belong to |
| `manifest(url)` | what the resource can answer, without answering. Cacheable per URL |
| `full(url)` | the whole payload, for when the answer really is the whole page |

Identification, the challenge-response, credential storage and the
proof-of-possession headers are all handled inside these calls. Call
`identify(url)` directly only to fail fast against a site that does not speak
UBAG.

## Read `ubag:unresolved` correctly

This is the one that causes wrong answers if you get it wrong.

A field the resource cannot answer comes back listed under `ubag:unresolved`. It
is **not** absent from the response, and it does **not** mean the value is empty,
zero, false or none.

```
"this resource says nothing about price"   is not   "the price is nothing"
```

If a requested field appears in `ubag:unresolved`, the correct downstream
behaviour is to report that the resource does not state it, or to fall back to
`full(url)`. Never render an unresolved field as a negative or empty value.

## Persist the identity

`Agent.generate()` makes a fresh Ed25519 keypair. The private key never leaves
the process, and the resulting `agent_id` is how sites recognise this agent
across visits.

```python
saved = agent.export()      # store this
agent = Agent.load(saved)   # reuse it, so agent_id stays stable
```

Regenerating on every run gives the agent a new identity each time, which
defeats any allowlist a site has put it on.

## Two failures, and they mean different things

- `ChallengeFailed`: the site did not issue a credential. It may not speak UBAG.
- `NotIdentified`: the site answered as though no credential were presented.

`NotIdentified` matters more than it looks. An unauthorized response can be
readable JSON with no error and no fields, which is a challenge that looks like
an answer. The client raises rather than handing that back as data. Do not catch
it and return the body.

## Calling it by hand

If you are not using the SDK, the same surface is plain query parameters on the
resource's own URL:

```
?ubag.fields=offers.price,offers.availability
?ubag.manifest=1
?ubag.fields=price&ubag.profile=auto
?ubag=lean
```

`ubag.profile=auto` expands each requested leaf to the entity holding it, so a
price arrives with its currency and a street line arrives as a whole address.
Ask for a price alone and you may get a number you cannot transact on.

Limits: 32 fields per request, and any single value over 2,000 characters is
treated as a document rather than a fact and is not indexed.

## Field names

Names are matched case-insensitively, and a bare leaf finds its dotted path, so
`price` resolves `offers.price`. Ask `manifest(url)` first when you do not know
what a resource carries. It is cheap enough to fetch speculatively and the
result is cacheable per URL, so discovery is paid once and reused across every
later question about that page.
