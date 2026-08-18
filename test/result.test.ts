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

  void it("contains hostile Error inspection and returns a stable fallback", () => {
    const throwingPrototype = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("prototype unavailable");
        },
      },
    );
    const throwingMessage = new Proxy(new Error("network down"), {
      get(target, property, receiver) {
        if (property === "message") throw new Error("message unavailable");
        const value: unknown = Reflect.get(target, property, receiver);
        return value;
      },
    });

    assert.equal(errorCause(throwingPrototype), "Unknown error");
    assert.equal(errorCause(throwingMessage), "Unknown error");
  });

  void it("contains hostile JSON and string conversion", () => {
    const hostileConversion = {
      toJSON() {
        throw new Error("JSON unavailable");
      },
      [Symbol.toPrimitive]() {
        throw new Error("string conversion unavailable");
      },
    };

    assert.equal(errorCause(hostileConversion), "Unknown error");
  });
});
