import { resolveTxt as defaultResolveTxt } from "node:dns/promises";
import * as z from "zod";

const base64url = z.base64url().min(1);
const nonempty = z.string().min(1);
const epochSeconds = z.number().int().nonnegative();

export const DisclosureTupleSchema = z.union([
  z.tuple([z.string(), z.unknown()]),
  z.tuple([z.string(), z.string(), z.unknown()]),
]);

const CommonPublicJwkProperties = {
  alg: nonempty.optional(),
  kid: nonempty.optional(),
  use: nonempty.optional(),
  key_ops: z.array(nonempty).optional(),
  ext: z.boolean().optional(),
  x5c: z.array(nonempty).optional(),
  x5t: base64url.optional(),
  "x5t#S256": base64url.optional(),
  x5u: z.url().optional(),
};

const privateJwkParameters = [
  "d",
  "dp",
  "dq",
  "k",
  "oth",
  "p",
  "priv",
  "q",
  "qi",
];

export const PublicJwkSchema = z
  .discriminatedUnion("kty", [
    z.looseObject({
      ...CommonPublicJwkProperties,
      kty: z.literal("RSA"),
      e: base64url,
      n: base64url,
    }),
    z.looseObject({
      ...CommonPublicJwkProperties,
      kty: z.literal("EC"),
      crv: nonempty,
      x: base64url,
      y: base64url,
    }),
    z.looseObject({
      ...CommonPublicJwkProperties,
      kty: z.literal("OKP"),
      crv: nonempty,
      x: base64url,
    }),
  ])
  .superRefine((jwk, context) => {
    for (const parameter of privateJwkParameters) {
      if (parameter in jwk) {
        context.addIssue({
          code: "custom",
          message: `A public JWK must not contain the private parameter ${parameter}.`,
          path: [parameter],
        });
      }
    }
  });

export const EvtHeaderSchema = z.looseObject({
  alg: nonempty.refine((value) => value !== "none"),
  kid: nonempty,
  typ: z.literal("evt+jwt"),
});

const ConfirmationSchema = z.object({ jwk: PublicJwkSchema });

export const EvtRawClaimsSchema = z.looseObject({
  iss: nonempty,
  iat: epochSeconds,
  cnf: ConfirmationSchema,
  email: z.email().optional(),
  email_verified: z.boolean(),
  _sd: z.array(base64url).optional(),
  _sd_alg: nonempty.optional(),
});

export const EvtClaimsSchema = z.looseObject({
  iss: nonempty,
  iat: epochSeconds,
  cnf: ConfirmationSchema,
  email: z.email(),
  email_verified: z.boolean(),
});

export const KbHeaderSchema = z.looseObject({
  alg: nonempty.refine((value) => value !== "none"),
  typ: z.literal("kb+jwt"),
});

export const KbClaimsSchema = z.looseObject({
  aud: z.url(),
  nonce: nonempty,
  iat: epochSeconds,
  sd_hash: base64url,
});

const EvtTokenSchema = z.object({
  compact: nonempty,
  header: EvtHeaderSchema,
  rawClaims: EvtRawClaimsSchema,
  claims: EvtClaimsSchema,
  signature: base64url,
});

const KbTokenSchema = z.object({
  compact: nonempty,
  header: KbHeaderSchema,
  claims: KbClaimsSchema,
  signature: base64url,
});

export const ParsedTokenSchema = z.object({
  token: nonempty,
  evt: EvtTokenSchema,
  kb: KbTokenSchema,
  disclosures: z.array(base64url),
  presentation: nonempty,
});

const timingSeconds = z.number().nonnegative();
const ClockSchema = z
  .custom<() => number>((value) => typeof value === "function")
  .optional()
  .transform((value) => value ?? (() => Date.now()));

type FetchFunction = typeof globalThis.fetch;
type ResolveTxtFunction = typeof defaultResolveTxt;

const FetchSchema = z.custom<FetchFunction>(
  (value) => typeof value === "function",
);
const ResolveTxtSchema = z.custom<ResolveTxtFunction>(
  (value) => typeof value === "function",
);

export const ExpectedValuesInputSchema = z.object({
  token: ParsedTokenSchema,
  email: z.email(),
  nonce: nonempty,
  audience: z.url(),
  maxTokenAgeSeconds: timingSeconds.default(300),
  clockToleranceSeconds: timingSeconds.default(60),
  now: ClockSchema,
});

export const ExpectedValuesValidatedTokenSchema = z.object({
  token: ParsedTokenSchema,
  email: z.email(),
  audience: z.url(),
  maxTokenAgeSeconds: timingSeconds,
  clockToleranceSeconds: timingSeconds,
  nowEpochSeconds: epochSeconds,
});

export const DnsVerifiedTokenSchema = z.object({
  token: ExpectedValuesValidatedTokenSchema,
  issuer: nonempty,
});

export const IssuerMetadataSchema = z.looseObject({
  issuance_endpoint: z.url(),
  jwks_uri: z.url(),
  signing_alg_values_supported: z
    .array(nonempty.refine((value) => value !== "none"))
    .min(1)
    .default(["EdDSA"]),
});

export const JsonWebKeySetSchema = z.object({
  keys: z.array(PublicJwkSchema).min(1).max(20),
});

export const IssuerVerifiedTokenSchema = z.object({
  token: DnsVerifiedTokenSchema,
  metadata: IssuerMetadataSchema,
});

export const KeyBindingVerifiedTokenSchema = z.object({
  email: z.email(),
  issuer: nonempty,
  audience: z.url(),
  issuedAt: z.object({
    evt: epochSeconds,
    keyBinding: epochSeconds,
  }),
  claims: EvtClaimsSchema,
});

export const VerifyEmailTokenInputSchema = z.object({
  token: nonempty,
  nonce: nonempty,
  email: z.email(),
  audience: z.url(),
  maxTokenAgeSeconds: timingSeconds.default(300),
  clockToleranceSeconds: timingSeconds.default(60),
  fetch: FetchSchema.optional().transform((value) => value ?? globalThis.fetch),
  resolveTxt: ResolveTxtSchema.optional().transform(
    (value) => value ?? defaultResolveTxt,
  ),
  now: ClockSchema,
});

export const VerifiedEmailSchema = KeyBindingVerifiedTokenSchema;

export type PublicJwk = z.infer<typeof PublicJwkSchema>;
export type EvtHeader = z.infer<typeof EvtHeaderSchema>;
export type EvtRawClaims = z.infer<typeof EvtRawClaimsSchema>;
export type EvtClaims = z.infer<typeof EvtClaimsSchema>;
export type KbHeader = z.infer<typeof KbHeaderSchema>;
export type KbClaims = z.infer<typeof KbClaimsSchema>;
export type ParsedToken = z.infer<typeof ParsedTokenSchema>;
export type ExpectedValuesValidatedToken = z.infer<
  typeof ExpectedValuesValidatedTokenSchema
>;
export type DnsVerifiedToken = z.infer<typeof DnsVerifiedTokenSchema>;
export type IssuerMetadata = z.infer<typeof IssuerMetadataSchema>;
export type JsonWebKeySet = z.infer<typeof JsonWebKeySetSchema>;
export type IssuerVerifiedToken = z.infer<typeof IssuerVerifiedTokenSchema>;
export type KeyBindingVerifiedToken = z.infer<
  typeof KeyBindingVerifiedTokenSchema
>;
export type VerifyEmailTokenInput = z.input<typeof VerifyEmailTokenInputSchema>;
export type VerifiedEmail = z.infer<typeof VerifiedEmailSchema>;
