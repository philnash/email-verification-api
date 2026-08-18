import { isIP } from "node:net";
import { ResolvedAddressesSchema, type ResolvedAddress } from "./schemas.js";

type AddressValidation =
  { ok: true; value: readonly ResolvedAddress[] } | { ok: false };

const IPV6_BITS = 128n;
const IPV4_MASK = 0xffff_ffffn;

export function isSafeNetworkHostname(hostname: string): boolean {
  const withoutBrackets =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  const normalized = withoutBrackets.endsWith(".")
    ? withoutBrackets.slice(0, -1).toLowerCase()
    : withoutBrackets.toLowerCase();

  if (isIP(normalized) !== 0 || !normalized.includes(".")) return false;
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized === "local" ||
    normalized.endsWith(".local") ||
    normalized === "home.arpa" ||
    normalized.endsWith(".home.arpa")
  ) {
    return false;
  }
  return true;
}

export function validateResolvedAddresses(value: unknown): AddressValidation {
  let parsed: ReturnType<typeof ResolvedAddressesSchema.safeParse>;
  try {
    parsed = ResolvedAddressesSchema.safeParse(value);
  } catch {
    return { ok: false };
  }
  if (!parsed.success) return { ok: false };

  const unique = new Map<string, ResolvedAddress>();
  for (const resolvedAddress of parsed.data) {
    const key = globallyReachableAddressKey(resolvedAddress);
    if (key === undefined) return { ok: false };
    unique.set(key, resolvedAddress);
  }
  return { ok: true, value: [...unique.values()] };
}

function globallyReachableAddressKey(
  resolvedAddress: ResolvedAddress,
): string | undefined {
  if (isIP(resolvedAddress.address) !== resolvedAddress.family)
    return undefined;
  if (resolvedAddress.family === 4) {
    const octets = parseIpv4(resolvedAddress.address);
    if (octets === undefined || !isGlobalIpv4(octets)) return undefined;
    return `4:${octets.join(".")}`;
  }

  const address = parseIpv6(resolvedAddress.address);
  if (address === undefined || !isGlobalIpv6(address)) return undefined;
  return `6:${address.toString(16)}`;
}

function parseIpv4(address: string): readonly number[] | undefined {
  const values = address.split(".").map(Number);
  if (
    values.length !== 4 ||
    values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  ) {
    return undefined;
  }
  return values;
}

function isGlobalIpv4(octets: readonly number[]): boolean {
  const first = octets[0];
  const second = octets[1];
  const third = octets[2];
  const fourth = octets[3];
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
  ) {
    return false;
  }

  return !(
    first === 0 ||
    first === 10 ||
    (first === 100 && second >= 64 && second <= 127) ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 &&
      second === 0 &&
      third === 0 &&
      fourth !== 9 &&
      fourth !== 10) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 192 && second === 88 && third === 99) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

function parseIpv6(address: string): bigint | undefined {
  if (address.includes("%")) return undefined;
  let normalized = address.toLowerCase();
  const finalColon = normalized.lastIndexOf(":");
  const finalPart = normalized.slice(finalColon + 1);
  if (finalPart.includes(".")) {
    const ipv4 = parseIpv4(finalPart);
    if (ipv4 === undefined) return undefined;
    const first = ipv4[0];
    const second = ipv4[1];
    const third = ipv4[2];
    const fourth = ipv4[3];
    if (
      first === undefined ||
      second === undefined ||
      third === undefined ||
      fourth === undefined
    ) {
      return undefined;
    }
    const high = first * 256 + second;
    const low = third * 256 + fourth;
    normalized = `${normalized.slice(0, finalColon + 1)}${high.toString(16)}:${low.toString(16)}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) return undefined;
  const left = splitIpv6Half(halves[0]);
  const right = splitIpv6Half(halves[1]);
  if (left === undefined || right === undefined) return undefined;

  const hasCompression = halves.length === 2;
  const suppliedGroups = left.length + right.length;
  if (
    (!hasCompression && suppliedGroups !== 8) ||
    (hasCompression && suppliedGroups >= 8)
  ) {
    return undefined;
  }
  const groups = hasCompression
    ? [
        ...left,
        ...Array.from({ length: 8 - suppliedGroups }, () => 0),
        ...right,
      ]
    : left;

  let result = 0n;
  for (const group of groups) result = (result << 16n) | BigInt(group);
  return result;
}

function splitIpv6Half(value: string | undefined): number[] | undefined {
  if (value === undefined || value === "") return [];
  const groups = value.split(":");
  const parsed: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/u.test(group)) return undefined;
    parsed.push(Number.parseInt(group, 16));
  }
  return parsed;
}

function isGlobalIpv6(address: bigint): boolean {
  if (inIpv6Range(address, ipv6("::ffff:0:0"), 96)) {
    return isGlobalIpv4Number(Number(address & IPV4_MASK));
  }
  if (inIpv6Range(address, ipv6("64:ff9b::"), 96)) {
    return isGlobalIpv4Number(Number(address & IPV4_MASK));
  }

  if (!inIpv6Range(address, ipv6("2000::"), 3)) return false;
  return !(
    inIpv6Range(address, ipv6("2001::"), 23) ||
    inIpv6Range(address, ipv6("2001:db8::"), 32) ||
    inIpv6Range(address, ipv6("2002::"), 16) ||
    inIpv6Range(address, ipv6("3fff::"), 20)
  );
}

function isGlobalIpv4Number(value: number): boolean {
  const first = Math.floor(value / 0x1_00_00_00);
  const second = Math.floor(value / 0x1_00_00) % 256;
  const third = Math.floor(value / 0x1_00) % 256;
  const fourth = value % 256;
  return isGlobalIpv4([first, second, third, fourth]);
}

function inIpv6Range(
  address: bigint,
  network: bigint,
  prefixLength: number,
): boolean {
  const shift = IPV6_BITS - BigInt(prefixLength);
  return address >> shift === network >> shift;
}

function ipv6(value: string): bigint {
  const parsed = parseIpv6(value);
  if (parsed === undefined) {
    throw new Error(`Internal IPv6 network is invalid: ${value}`);
  }
  return parsed;
}
