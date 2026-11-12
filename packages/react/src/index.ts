/**
 * React bindings for @evolustr/client: a provider that runs `connect()` once,
 * and hooks for the connection state, actions and settings.
 */
import type { ConnectResult, Evolustr, Ready, Status } from "@evolustr/client";
import type { SettingKey, SharedSettings } from "@evolustr/core";
import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type EvolustrState =
  | { readonly kind: "connecting" }
  | { readonly kind: "ready"; readonly ready: Ready }
  | { readonly kind: "needsUserAction"; readonly action: Extract<ConnectResult, { state: "needsUserAction" }>["action"] }
  | { readonly kind: "vaultChanged"; readonly result: Extract<ConnectResult, { state: "vaultChanged" }> }
  | { readonly kind: "error"; readonly message: string };

interface ContextValue {
  readonly client: Evolustr;
  readonly state: EvolustrState;
  /** Re-reads status and settings after an action. */
  readonly refresh: () => void;
  /** Applies a result that may complete a pending state. */
  readonly settle: (r: { readonly ok: true; readonly value: Ready } | { readonly ok: false; readonly error: { readonly message: string } }) => void;
  readonly version: number;
}

const EvolustrContext = createContext<ContextValue | null>(null);

const fromConnect = (r: Awaited<ReturnType<Evolustr["connect"]>>): EvolustrState => {
  if (!r.ok) return { kind: "error", message: r.error.message };
  const v = r.value;
  if (v.state === "ready") return { kind: "ready", ready: v };
  if (v.state === "needsUserAction") return { kind: "needsUserAction", action: v.action };
  return { kind: "vaultChanged", result: v };
};

/** Connects once on mount. Create `client` outside render (or memoize it). */
export const EvolustrProvider = (props: { readonly client: Evolustr; readonly children?: ReactNode }) => {
  const { client } = props;
  const [state, setState] = useState<EvolustrState>({ kind: "connecting" });
  const [version, setVersion] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState({ kind: "connecting" });
    void client.connect().then((r) => {
      if (!cancelled) setState(fromConnect(r));
    });
    return () => {
      cancelled = true;
    };
  }, [client]);

  const refresh = useCallback(() => setVersion((v) => v + 1), []);
  const settle = useCallback<ContextValue["settle"]>((r) => {
    setState(r.ok ? { kind: "ready", ready: r.value } : { kind: "error", message: r.error.message });
    setVersion((v) => v + 1);
  }, []);

  const value = useMemo(() => ({ client, state, refresh, settle, version }), [client, state, refresh, settle, version]);
  return createElement(EvolustrContext.Provider, { value }, props.children);
};

const useCtx = (): ContextValue => {
  const ctx = useContext(EvolustrContext);
  if (ctx === null) throw new Error("useEvolustr must be used inside <EvolustrProvider>");
  return ctx;
};

/** Connection state, current status, and the client for actions. */
export const useEvolustr = (): {
  readonly state: EvolustrState;
  readonly status: Status | null;
  readonly client: Evolustr;
  /** Call after an action (enrollPasskey, makeStrict, …) to re-render with the new status. */
  readonly refresh: () => void;
  /** Use with unlock / resolveVaultChange / restoreFromPhrase results. */
  readonly settle: ContextValue["settle"];
} => {
  const ctx = useCtx();
  void ctx.version;
  return { state: ctx.state, status: ctx.client.status(), client: ctx.client, refresh: ctx.refresh, settle: ctx.settle };
};

/** `app ?? shared ?? default` for one setting, re-read after `refresh()`. */
export const useSetting = <K extends SettingKey>(key: K): SharedSettings[K] => {
  const ctx = useCtx();
  void ctx.version;
  return ctx.client.settings.get(key);
};
