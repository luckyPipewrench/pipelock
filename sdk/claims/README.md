# AARP claim dictionary

`aarp-v0.1-claims.json` is the public, machine-readable vocabulary for the
AARP verifier result. It is intentionally literal: each entry states what the
claim proves, what it does not prove, whether the current build emits it, and
which fixture or test pins the meaning.

The dictionary includes:

- emitted verified claims from the current AARP appraiser;
- reserved verified-claim names for transparency, deployment, and authority
  axes that are not populated yet;
- every emitted and reserved `does_not_assert` limitation;
- active `overclaim_risks` codes.

Reserved entries freeze vocabulary only. They are not evidence that the current
verifier can populate that axis.
