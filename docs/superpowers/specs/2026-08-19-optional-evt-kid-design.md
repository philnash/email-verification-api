# Optional EVT `kid` compatibility design

## Context

The Email Verification Protocol draft currently requires an EVT protected
header to contain `kid`. However, the example token and rough implementation in
the sibling `email-verification-impl` project omit `kid` and make it optional.
The library needs to verify both forms while the browser implementation and
draft converge.

This is a compatibility workaround, not a change to the preferred protocol
shape. Tokens that provide `kid` continue to receive strict key-ID matching.

## Parsing and public types

`EvtHeaderSchema` will accept an optional, nonempty `kid`:

- an omitted `kid` is valid;
- an empty or non-string `kid` remains invalid;
- `alg` and `typ: "evt+jwt"` remain required.

The inferred `EvtHeader` type therefore exposes `kid?: string`. No new public
configuration option is added.

## Issuer-key selection

Key selection remains centralized in the issuer-signature stage:

- when `kid` is present, only a JWK with the same `kid` can match;
- when `kid` is absent, any JWK compatible with the protected `alg`, key type,
  curve, `use`, and `key_ops` can match;
- more than ten matching candidates fails with `JWKS_INVALID` before any key is
  accepted;
- every matching candidate is imported before signature verification, so
  malformed key material cannot be silently skipped;
- if no candidate verifies, verification fails with `EVT_SIGNATURE_INVALID`.

The existing matching predicate will take `string | undefined`. This keeps the
workaround isolated: returning to strict draft behavior later requires making
`kid` required in `EvtHeaderSchema` and changing the predicate input back to
`string`, without changing the pipeline or public API.

## Tests

Tests will be written before production changes and will prove:

- parsing accepts an EVT without `kid`;
- direct and selectively disclosed tokens without `kid` verify end to end;
- a token with `kid` still selects only the exact matching key;
- a token without `kid` can verify against one compatible key or a bounded set
  of compatible keys;
- more than ten compatible keys without `kid` fails before verification;
- incompatible keys do not consume the candidate limit;
- empty and non-string `kid` values remain malformed.

The fixture will support generating tokens with or without `kid`, while its
existing default remains unchanged to avoid weakening coverage of strict key-ID
selection.

## Documentation

The README will note the temporary interoperability behavior: draft-01 requires
`kid`, but the library accepts its omission for observed implementation
compatibility. It will explain that missing `kid` causes bounded compatible-key
selection rather than unbounded JWKS scanning.
