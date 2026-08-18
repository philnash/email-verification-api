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

export type PublicJwk = z.infer<typeof PublicJwkSchema>;
export type EvtHeader = z.infer<typeof EvtHeaderSchema>;
export type EvtRawClaims = z.infer<typeof EvtRawClaimsSchema>;
export type EvtClaims = z.infer<typeof EvtClaimsSchema>;
export type KbHeader = z.infer<typeof KbHeaderSchema>;
export type KbClaims = z.infer<typeof KbClaimsSchema>;
export type ParsedToken = z.infer<typeof ParsedTokenSchema>;
