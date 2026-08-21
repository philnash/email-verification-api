"use client";

import { useId, useState } from "react";

type VerifyResult =
  | { verified: true }
  | { verified: false; reason: string };

type Status = "idle" | "submitting" | "done";

export function VerifyForm({ nonce }: { nonce: string }) {
  const [status, setStatus] = useState<Status>("idle");
  const [result, setResult] = useState<VerifyResult | null>(null);
  const resultId = useId();

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("submitting");
    setResult(null);

    const formData = new FormData(event.currentTarget);

    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        body: formData,
      });
      const data: VerifyResult = await response.json();
      setResult(data);
    } catch {
      setResult({
        verified: false,
        reason: "Something went wrong while checking your email. Please try again.",
      });
    } finally {
      setStatus("done");
    }
  }

  const submitting = status === "submitting";

  return (
    <div className="form-wrapper">
      <form onSubmit={handleSubmit} inert={submitting || undefined} noValidate>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            required
            id="email"
            name="email"
            autoComplete="email"
            placeholder="you@example.com"
            disabled={submitting}
          />
        </div>
        <input
          type="hidden"
          name="token"
          nonce={nonce}
          autoComplete="email-verification-token"
        />
        <div className="actions">
          <button type="submit" disabled={submitting} aria-busy={submitting}>
            {submitting && <span className="spinner" aria-hidden="true" />}
            {submitting ? "Verifying…" : "Verify"}
          </button>
        </div>
      </form>

      <p id={resultId} role="status" aria-live="polite" className="result">
        {result?.verified && (
          <span className="result--verified">✓ Email verified.</span>
        )}
        {result && !result.verified && (
          <span className="result--not-verified">✗ Not verified: {result.reason}</span>
        )}
      </p>
    </div>
  );
}
