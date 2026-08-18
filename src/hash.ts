import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Hasher } from "@sd-jwt/core";

export const hashFunction: Hasher = (data, algorithm) => {
  const input = typeof data === "string" ? data : Buffer.from(data);
  return createHash(algorithm.replaceAll("-", "")).update(input).digest();
};
