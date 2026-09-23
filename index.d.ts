export type SigningScheme = 'hmac' | 'ed25519';

export const SIGNATURE_VERSION: string;

/**
 * Binds timestamp, request id and body together so tampering with any one invalidates the
 * signature. Must match the server's own construction exactly.
 */
export function buildSigningString(
  timestamp: string,
  requestId: string,
  rawBody: string | Uint8Array,
): string;

/** @param secret raw HMAC secret (not encrypted-at-rest form) */
export function signHmac(signingString: string, secret: string): string;

/** @param privateKeyPem Ed25519 private key, PEM format */
export function signEd25519(signingString: string, privateKeyPem: string): string;

/** Scheme-agnostic entry point. Returns the already-prefixed (`v1=...`) signature header value. */
export function sign(scheme: SigningScheme, signingString: string, secret: string): string;

export interface SignedRequestOptions {
  /** e.g. "https://dev-api.banglareels.com" or a partner's own API base */
  baseUrl: string;
  /** e.g. "/api/v1/partner/auth/handoff" */
  path: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Sent as JSON. Omit for no body. */
  body?: unknown;
  scheme: SigningScheme;
  /** HMAC secret, or Ed25519 private key PEM */
  secret: string;
  /**
   * The partner's slug (X-Partner-Id) — required when calling INTO BanglaReels. Omit when
   * simulating the outbound BanglaReels -> partner `/deduct` call, which never sends this header.
   */
  partnerId?: string;
  /** X-Request-Id — reuse the same value on any retry of the same attempt. Auto-generated (UUID) if omitted. */
  requestId?: string;
  extraHeaders?: Record<string, string>;
}

export interface SignedRequestResult {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  /** Parsed JSON when the response declares a JSON content-type, otherwise raw text. */
  body: unknown;
}

/**
 * The universal signed-request function — works for both HMAC and Ed25519, calls the target URL,
 * and returns just the response.
 */
export function signedRequest(options: SignedRequestOptions): Promise<SignedRequestResult>;

export interface HandoffOptions {
  /** e.g. "https://dev-api.banglareels.com" */
  baseUrl: string;
  /** @default "/api/v1" */
  apiPrefix?: string;
  scheme: SigningScheme;
  /** HMAC secret, or Ed25519 private key PEM */
  secret: string;
  /** The partner's slug (X-Partner-Id) */
  partnerId: string;
  /** The partner's own user id. Must match the id used on the payment callback. */
  partnerUserId: string;
  /** E.164 preferred, e.g. "+8801712345678" */
  phoneNumber: string;
  name?: string;
  email?: string;
  /** Where the WebView should return to inside the partner app once entitlement is confirmed. */
  returnPath?: string;
  requestId?: string;
}

export interface HandoffResponseBody {
  handoffCode: string;
  expiresIn: number;
  entryUrl: string;
  hasActiveSubscription: boolean;
  pendingMerge?: {
    required: true;
    reason: string;
  };
}

/**
 * Signs and calls `POST /partner/auth/handoff` — the actual "handoff first, then get a response"
 * flow. Body shape matches PartnerHandoffDto exactly.
 */
export function handoff(
  options: HandoffOptions,
): Promise<SignedRequestResult & { body: HandoffResponseBody }>;
