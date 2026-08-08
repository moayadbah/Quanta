# Presenter notes

A four-minute walkthrough. Six steps. Start it, talk over it, and click a term whenever
someone asks what one means.

```bash
uv run quanta serve
```

Open `http://localhost:8000`. Arrow keys move between steps. The **العربية** button in the
top bar switches the whole walkthrough to Arabic; technical terms stay in English.

**Underlined words are clickable.** Each opens *what it is*, *why we chose it*, and the
section or ADR that decided it. That is the answer to "what is a CDG?" or "why hybrid?" —
click instead of improvising.

---

## The argument, in one line

Existing tools tell you *where* cryptography is. Nobody tells you *how hard it is to
change*. That question is about the shape of the codebase, so we answer it with a graph.

---

## Step 1 — The problem (~30s)

> "Ask three consultants how long post-quantum migration takes. You get two years to ten —
> for the same company."

Point at the two cards. **Same 27 cryptographic calls. Ten times the cost.** An inventory
cannot tell them apart, because the difference is not in the count.

Land the line: **migration cost is a property of the codebase, not of the algorithm.**

## Step 2 — Where tools stop (~25s)

The list types itself out, then a question mark. Scanners produce this and stop.

> "This is useful. It is also where every existing tool stops. It never says whether one
> wrapper hides the cryptography or fifty files call it directly."

## Step 3 — What we build (~50s)

The graph assembles: modules, then functions, then cryptographic calls, then edges.

Then the two columns. **Say the reused column out loud.** It pre-empts the question
everyone is waiting to ask:

> "We parse with LibCST and run graph algorithms with NetworkX. Those are existing
> libraries. The graph, its rules, the call resolver and the score are ours. No existing
> tool produces this artifact."

Then the honest number: **290 callees resolved out of 2,435 on PyJWT.** We publish what we
miss. If asked why not CodeQL, click **call resolver**.

## Step 4 — The measurement (~70s) — the centrepiece

> "Ask the graph one question. What is the smallest set of nodes that separates the
> cryptography from the rest of the program?"

That is the **minimum node cut**, and it turns an architectural question into a computable
one. Press **Remove the cut** and let it play: the ringed nodes fade and the cryptography
detaches.

Now the three tabs. **The same program, written three ways. Six cryptographic calls in all
three.** Only the architecture changes.

| | Cut | Modules touching crypto | Score |
|---|---|---|---|
| Scattered | 6 | 6 | **20.5** |
| Behind a wrapper | 3 | 1 | **23.8** |
| Wrapper + configuration | 3 | 1 | **43.8** |

The strongest version of the claim, if you have time for one more sentence:

> "The tool looked at the first version and recommended two things: add a wrapper, and move
> the algorithm into configuration. We did both. The score doubled."

**Do not oversell the middle step.** The wrapper halves the cut and gains only three
points, because `1 / (1 + cut)` compresses. That is on screen, in the amber note. Saying it
first is stronger than being asked about it.

## Step 5 — Does it work? (~45s)

> "We replace old key exchange with X-Wing, a hybrid KEM. It stays safe if either half
> stays safe."

Then the three hashes:

> "We checked our implementation against the test vectors published in IETF draft-10. They
> caught a mistake in our own design document — one field in the wrong place. Our round-trip
> test still passed, because we generate both sides of it. Only somebody else's vectors
> could find that."

This is the beat that answers "is this real engineering?". Let the red row sit for a moment.

## Step 6 — Try it (~30s)

Skip to the tool. Either paste a repository, or click a saved example for an instant run.

> "Your code is only read. We never run it, never install it, and delete the copy when we
> finish."

Open **Steps taken** on the result. Nine steps, each one expandable to the evidence behind
it — including "network calls so far: 0" *before* we resolve the host, which is the whole
SSRF control.

---

## Likely questions

**"Isn't this just a wrapper around existing tools?"**
Step 3, both columns. LibCST parses and NetworkX computes; the graph, the detection rules,
the resolver, the score and the benchmark are ours. Minimum node cut is a solved algorithm —
deciding that it answers "is there an insulation layer?" is the contribution.

**"Why not CodeQL?"** Click **call resolver** (ADR-009). It costs a query language, a
database build step and a proprietary CLI, for a three-person undergraduate team. The price
is less depth, which we measure and publish. Below 0.60 recall we revisit it.

**"Where is the research contribution?"** Click **the labelled benchmark**. Twelve
repositories, every site classified by two people independently with a third adjudicating,
frozen before any engine is written. No dataset like it exists.

**"Is the score meaningful?"** Step 4 is the evidence: hold the cryptography constant, change
only the architecture, and the number moves in the direction the recommendations predicted.
Weights were fixed and git-tagged before any result was observed — click **pre-registered
weights**.

**"What are its limits?"** Say them before you are asked. One-hop call resolution is
labelled low confidence. Propagation depth saturates on small repositories and contributes
nothing in this demo. It measures source-edit difficulty only — not certificates, not
protocols, not hardware. And it is not a security review.

---

## If something breaks

- **No network?** The saved examples run entirely offline, and steps 1–5 need no network
  at all.
- **A live analysis fails?** Every error surfaces as a clean code, e.g. `HOST_NOT_ALLOWED`.
  That is worth showing on purpose: paste `https://127.0.0.1/o/r` and let it refuse.
- **Numbers differ from this file?** The walkthrough computes them live from the analyzer.
  Trust the screen, and re-run `uv run pytest tests/unit/test_demo_variants.py`.
