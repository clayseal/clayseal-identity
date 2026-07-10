<!--
DRAFT comment for NousResearch/hermes-agent#527. Not posted. Review, edit to
taste, and post from your own GitHub account if the framing fits.
-->

The tier model (Owner → Admin → User → Guest) covers *who* is talking to the
gateway. There's a second axis worth designing alongside it: *what the agent
itself is allowed to do* once a request is in — which tools, on which
resources. Tiers gate the door; they don't scope the work a tool call performs.

We've been building capability-scoped authorization for exactly this and it
might be useful as one backing implementation for the "User"/"Guest" tiers,
where you want real limits rather than all-or-nothing:

- Each tier maps to a **capability set** (`tool:search_web`, `tool:read_docs`,
  `file:read` under `docs/*`, …) rather than a flat allow/block.
- The capability token can be **attenuated per task** — narrowed further for a
  single risky operation and never widened back — so a prompt-injected request
  to step outside the tier is refused by the check, not by the model's judgement.
- Tokens are verified **offline** at the tool boundary, so this doesn't add a
  network hop per call.

It's MIT and language-agnostic (Python service + a JS verifier), so it could sit
behind whatever tier abstraction you land on rather than dictating it. Happy to
prototype a `clayseal`-backed permission provider against the tier interface
once the shape here settles, or just share notes if you're rolling your own.
Not trying to steer the design — the tier proposal stands on its own; this is
the "and here's how to enforce it with teeth" half.

Repo, if useful: https://github.com/clayseal/clayseal-identity
