import {
  decodeJwt,
  decodeSdJwt,
  splitSdJwt,
  unpack,
  type Disclosure,
} from "@sd-jwt/core";
import * as z from "zod";
import { hashFunction } from "./hash.js";
import { err, errorCause, ok, type Result } from "./result.js";
import {
  DisclosureTupleSchema,
  EvtHeaderSchema,
  EvtRawClaimsSchema,
  KbClaimsSchema,
  KbHeaderSchema,
  ParsedTokenSchema,
  type ParsedToken,
} from "./schemas.js";

const TokenInputSchema = z.string().min(1);
const CompactPartSchema = z.base64url().min(1);

class DisclosureError extends Error {}

export async function parseToken(input: unknown): Promise<Result<ParsedToken>> {
  try {
    const tokenResult = TokenInputSchema.safeParse(input);
    if (!tokenResult.success) {
      return malformedToken(
        "The token must be a non-empty string.",
        tokenResult.error,
      );
    }

    const token = tokenResult.data;
    const compactParts = parseCompactParts(token);
    if (!compactParts.ok) return compactParts;

    const { evtCompact, kbCompact, encodedDisclosures, presentation } =
      compactParts.value;
    const evt = decodeJwt(evtCompact);
    const kb = decodeJwt(kbCompact);
    const evtHeader = EvtHeaderSchema.parse(evt.header);
    const rawClaims = EvtRawClaimsSchema.parse(evt.payload);
    const kbHeader = KbHeaderSchema.parse(kb.header);
    const kbClaims = KbClaimsSchema.parse(kb.payload);

    const disclosedClaims = await resolveDisclosures(token, rawClaims);
    const parsedResult = ParsedTokenSchema.safeParse({
      token,
      evt: {
        compact: evtCompact,
        header: evtHeader,
        rawClaims,
        claims: disclosedClaims,
        signature: evt.signature,
      },
      kb: {
        compact: kbCompact,
        header: kbHeader,
        claims: kbClaims,
        signature: kb.signature,
      },
      disclosures: encodedDisclosures,
      presentation,
    });

    if (!parsedResult.success) {
      return malformedToken(
        "The token claims do not match the Email Verification token schema.",
        parsedResult.error,
      );
    }

    return ok(parsedResult.data);
  } catch (cause) {
    if (cause instanceof DisclosureError) {
      return invalidDisclosure(cause.message, cause);
    }
    return malformedToken("The token is malformed.", cause);
  }
}

interface CompactParts {
  evtCompact: string;
  kbCompact: string;
  encodedDisclosures: string[];
  presentation: string;
}

function parseCompactParts(token: string): Result<CompactParts> {
  if (!token.includes("~")) {
    return malformedToken("The token must include a KB-JWT.");
  }

  const { jwt, disclosures, kbJwt } = splitSdJwt(token);
  if (kbJwt === undefined) {
    return malformedToken("The token must include a KB-JWT.");
  }
  if (disclosures.some((disclosure) => disclosure.length === 0)) {
    return malformedToken("The token contains an empty disclosure.");
  }
  if (!isCompactJwt(jwt) || !isCompactJwt(kbJwt)) {
    return malformedToken("The EVT and KB-JWT must be compact JWTs.");
  }

  const lastSeparator = token.lastIndexOf("~");
  return ok({
    evtCompact: jwt,
    kbCompact: kbJwt,
    encodedDisclosures: disclosures,
    presentation: token.slice(0, lastSeparator + 1),
  });
}

function isCompactJwt(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 3 &&
    parts.every((part) => CompactPartSchema.safeParse(part).success)
  );
}

async function resolveDisclosures(
  token: string,
  rawClaims: z.infer<typeof EvtRawClaimsSchema>,
): Promise<unknown> {
  try {
    const decoded = await decodeSdJwt(token, hashFunction);
    for (const disclosure of decoded.disclosures) {
      DisclosureTupleSchema.parse(disclosure.decode());
    }
    const { unpackedObj, disclosureKeymap } = await unpack(
      rawClaims,
      decoded.disclosures,
      hashFunction,
    );

    await ensureEveryDisclosureIsReferenced(
      decoded.disclosures,
      disclosureKeymap,
      rawClaims._sd_alg ?? "sha-256",
    );
    if (rawClaims.email !== undefined && "email" in disclosureKeymap) {
      throw new DisclosureError(
        "The email claim cannot be both direct and selectively disclosed.",
      );
    }
    return unpackedObj;
  } catch (cause) {
    if (cause instanceof DisclosureError) throw cause;
    throw new DisclosureError(errorCause(cause));
  }
}

async function ensureEveryDisclosureIsReferenced(
  disclosures: Disclosure[],
  disclosureKeymap: Record<string, string>,
  algorithm: string,
) {
  const referencedDigests = new Set(Object.values(disclosureKeymap));
  const suppliedDigests = await Promise.all(
    disclosures.map((disclosure) =>
      disclosure.digest({ hasher: hashFunction, alg: algorithm }),
    ),
  );

  if (new Set(suppliedDigests).size !== suppliedDigests.length) {
    throw new DisclosureError("The token contains a duplicate disclosure.");
  }
  if (suppliedDigests.some((digest) => !referencedDigests.has(digest))) {
    throw new DisclosureError(
      "Every supplied disclosure must be referenced by the EVT.",
    );
  }
}

function malformedToken(message: string, cause?: unknown): Result<never> {
  return err({
    stage: "parse",
    code: "TOKEN_MALFORMED",
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}

function invalidDisclosure(message: string, cause?: unknown): Result<never> {
  return err({
    stage: "parse",
    code: "DISCLOSURE_INVALID",
    message,
    ...(cause === undefined ? {} : { cause: errorCause(cause) }),
  });
}
