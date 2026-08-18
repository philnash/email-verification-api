import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DisclosureTupleSchema,
  DnsVerifiedTokenSchema,
  EvtClaimsSchema,
  EvtHeaderSchema,
  EvtRawClaimsSchema,
  ExpectedValuesInputSchema,
  ExpectedValuesValidatedTokenSchema,
  IssuerMetadataSchema,
  IssuerVerifiedTokenSchema,
  JsonWebKeySetSchema,
  KbClaimsSchema,
  KbHeaderSchema,
  KeyBindingVerifiedTokenSchema,
  ParsedTokenSchema,
  PublicJwkSchema,
  ResolvedAddressSchema,
  ResolvedAddressesSchema,
  ResolveHostSchema,
  VerificationErrorCodeSchema,
  VerificationErrorSchema,
  VerificationStageSchema,
  VerifiedEmailSchema,
  VerifyEmailTokenInputSchema,
  err,
  isErr,
  isOk,
  ok,
  parseToken,
  validateExpectedValues,
  verifyDnsDelegation,
  verifyEmailToken,
  verifyIssuerSignature,
  verifyKeyBinding,
} from "../src/index.js";
import type {
  DnsVerifiedToken,
  EvtClaims,
  EvtHeader,
  EvtRawClaims,
  ExpectedValuesValidatedToken,
  IssuerMetadata,
  IssuerVerifiedToken,
  JsonWebKeySet,
  KbClaims,
  KbHeader,
  KeyBindingVerifiedToken,
  ParsedToken,
  PublicJwk,
  ResolvedAddress,
  ResolveHost,
  Result,
  VerificationError,
  VerificationErrorCode,
  VerificationStage,
  VerifiedEmail,
  VerifyEmailTokenInput,
} from "../src/index.js";
import * as publicApi from "../src/index.js";

const publicSchemas = [
  DisclosureTupleSchema,
  DnsVerifiedTokenSchema,
  EvtClaimsSchema,
  EvtHeaderSchema,
  EvtRawClaimsSchema,
  ExpectedValuesInputSchema,
  ExpectedValuesValidatedTokenSchema,
  IssuerMetadataSchema,
  IssuerVerifiedTokenSchema,
  JsonWebKeySetSchema,
  KbClaimsSchema,
  KbHeaderSchema,
  KeyBindingVerifiedTokenSchema,
  ParsedTokenSchema,
  PublicJwkSchema,
  ResolvedAddressSchema,
  ResolvedAddressesSchema,
  ResolveHostSchema,
  VerificationErrorCodeSchema,
  VerificationErrorSchema,
  VerificationStageSchema,
  VerifiedEmailSchema,
  VerifyEmailTokenInputSchema,
];

const publicFunctions = [
  err,
  isErr,
  isOk,
  ok,
  parseToken,
  validateExpectedValues,
  verifyDnsDelegation,
  verifyEmailToken,
  verifyIssuerSignature,
  verifyKeyBinding,
];

async function compilePublicApi(input: VerifyEmailTokenInput): Promise<void> {
  const resolveHost: ResolveHost = () =>
    Promise.resolve([{ address: "8.8.8.8", family: 4 }]);
  const inputWithResolver: VerifyEmailTokenInput = { ...input, resolveHost };
  const resolvedAddress: ResolvedAddress = {
    address: "8.8.8.8",
    family: 4,
  };
  void inputWithResolver;
  void resolvedAddress;
  const result = await verifyEmailToken(input);
  if (result.ok) {
    const email: string = result.value.email;
    const issuer: string = result.value.issuer;
    // @ts-expect-error A successful Result has no error branch.
    void result.error;
    void email;
    void issuer;
  } else {
    const code: VerificationErrorCode = result.error.code;
    // @ts-expect-error A failed Result has no value branch.
    void result.value;
    void code;
  }
}

function rejectIncompleteInputAtCompileTime(): void {
  // @ts-expect-error The public input requires an audience.
  void verifyEmailToken({
    token: "token",
    nonce: "nonce",
    email: "user@example.com",
  });
}

type PublicTypes = readonly [
  DnsVerifiedToken,
  EvtClaims,
  EvtHeader,
  EvtRawClaims,
  ExpectedValuesValidatedToken,
  IssuerMetadata,
  IssuerVerifiedToken,
  JsonWebKeySet,
  KbClaims,
  KbHeader,
  KeyBindingVerifiedToken,
  ParsedToken,
  PublicJwk,
  ResolvedAddress,
  ResolveHost,
  Result<VerifiedEmail>,
  VerificationError,
  VerificationErrorCode,
  VerificationStage,
  VerifiedEmail,
  VerifyEmailTokenInput,
];

function acceptPublicTypes(value: PublicTypes): PublicTypes {
  return value;
}

void describe("public API", () => {
  void it("exports the documented runtime surface", () => {
    assert.equal(
      publicSchemas.every((schema) => typeof schema.parse === "function"),
      true,
    );
    assert.equal(
      publicFunctions.every((operation) => typeof operation === "function"),
      true,
    );
    // @ts-expect-error canonicalIssuer is an internal normalization helper.
    assert.equal(publicApi.canonicalIssuer, undefined);
    // @ts-expect-error errorCause is an internal error-construction helper.
    assert.equal(publicApi.errorCause, undefined);
    // @ts-expect-error ASCII inspection is an internal security helper.
    assert.equal(publicApi.containsAsciiWhitespaceOrControl, undefined);
    // @ts-expect-error Default DNS wrappers are internal implementation details.
    assert.equal(publicApi.defaultResolveHost, undefined);
    void compilePublicApi;
    void rejectIncompleteInputAtCompileTime;
    void acceptPublicTypes;
  });
});
