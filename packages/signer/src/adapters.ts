/**
 * Transport adapters for {@link EvolustrSigner} (SPEC §5.1). Each one turns a
 * transport's request into `handle(method, params, caller)`, taking the caller
 * from the transport itself.
 */
import type { Result } from "@evolustr/core";
import type { EvolustrSigner } from "./signer.ts";

/** postMessage envelope used between the app page and an iframe signer. */
export interface IframeRequest {
  readonly type: "evolustr";
  readonly id: string;
  readonly method: string;
  readonly params?: ReadonlyArray<unknown>;
}

export interface IframeResponse {
  readonly type: "evolustr";
  readonly id: string;
  readonly result?: unknown;
  readonly error?: { readonly type: string; readonly message: string };
}

const toResponse = (id: string, r: Result<unknown>): IframeResponse =>
  r.ok ? { type: "evolustr", id, result: r.value } : { type: "evolustr", id, error: r.error };

export const isIframeRequest = (data: unknown): data is IframeRequest =>
  typeof data === "object" &&
  data !== null &&
  (data as IframeRequest).type === "evolustr" &&
  typeof (data as IframeRequest).id === "string" &&
  typeof (data as IframeRequest).method === "string";

/**
 * Handles one message inside an iframe signer. The caller is `event.origin`,
 * which the browser sets; optionally only `allowedOrigin` is served.
 */
export const handleIframeMessage = async (
  signer: EvolustrSigner,
  event: { readonly origin: string; readonly data: unknown },
  allowedOrigin?: string,
): Promise<IframeResponse | null> => {
  if (!isIframeRequest(event.data)) return null;
  if (!event.origin || event.origin === "null") return null;
  if (allowedOrigin !== undefined && event.origin !== allowedOrigin) return null;
  const r = await signer.handle(event.data.method, event.data.params ?? [], { identity: "verified", origin: event.origin });
  return toResponse(event.data.id, r);
};

/** Wires {@link handleIframeMessage} to a window; returns a function that stops listening. */
export const listenForIframeRequests = (
  signer: EvolustrSigner,
  self: Pick<Window, "addEventListener" | "removeEventListener">,
  reply: (response: IframeResponse, origin: string) => void,
  allowedOrigin?: string,
): (() => void) => {
  const listener = (e: Event) => {
    const m = e as MessageEvent;
    void handleIframeMessage(signer, { origin: m.origin, data: m.data }, allowedOrigin).then((r) => {
      if (r !== null) reply(r, m.origin);
    });
  };
  self.addEventListener("message", listener);
  return () => self.removeEventListener("message", listener);
};

/** NIP-46: `evolustr_*` request from a connected client; results are strings. */
export const handleNip46Request = async (
  signer: EvolustrSigner,
  clientPubkey: string,
  request: { readonly id: string; readonly method: string; readonly params: ReadonlyArray<string> },
): Promise<{ readonly id: string; readonly result?: string; readonly error?: string }> => {
  const params = request.params.map((p) => {
    try {
      return JSON.parse(p) as unknown;
    } catch {
      return p;
    }
  });
  const r = await signer.handle(request.method, params, { identity: "connection", clientPubkey });
  return r.ok
    ? { id: request.id, result: typeof r.value === "string" ? r.value : JSON.stringify(r.value ?? null) }
    : { id: request.id, error: r.error.message };
};

/** Browser extension: the sender's origin comes from the extension runtime. */
export const handleExtensionRequest = (
  signer: EvolustrSigner,
  senderOrigin: string,
  method: string,
  params: ReadonlyArray<unknown> = [],
): Promise<Result<unknown>> => signer.handle(method, params, { identity: "verified", origin: senderOrigin });
