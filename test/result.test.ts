import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { err, errorCause, isErr, isOk, ok } from "../src/result.js";
import type { VerificationError } from "../src/result.js";

void describe("Result", () => {
  void it("constructs and narrows success", () => {
    const result = ok("verified");
    assert.equal(isOk(result), true);
    assert.equal(isErr(result), false);
    assert.deepEqual(result, { ok: true, value: "verified" });
  });

  void it("constructs and narrows failure", () => {
    const error: VerificationError = {
      stage: "parse",
      code: "TOKEN_MALFORMED",
      message: "The token is malformed.",
    };
    const result = err(error);
    assert.equal(isErr(result), true);
    assert.equal(isOk(result), false);
    assert.deepEqual(result, { ok: false, error });
  });

  void it("normalizes Error, string, and arbitrary causes", () => {
    assert.equal(errorCause(new Error("network down")), "network down");
    assert.equal(errorCause("timeout"), "timeout");
    assert.equal(errorCause({ code: "ENOTFOUND" }), '{"code":"ENOTFOUND"}');
  });
});
