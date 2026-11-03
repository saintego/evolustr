/**
 * Evolustr Notes: a small demo of @evolustr/client with Evolu in the browser.
 *
 * Query parameters (useful for testing):
 *   ?relays=wss://a,wss://b   Nostr relays for the vault (default: public relays)
 *   ?sync=off                 keep Evolu data on this device only (no Evolu relay)
 */
import {
  AppName,
  NonEmptyTrimmedString1000,
  createEvolu,
  createQueryBuilder,
  id,
  type Evolu,
} from "@evolu/common";
import { createEvoluDeps, createRun } from "@evolu/web";
import {
  type ConnectResult,
  type Evolustr,
  createEvolustr,
  detectCapableSigner,
  evoluDatabases,
  evolustrSchema,
  keyValueCache,
  type WithEvolustr,
} from "@evolustr/client";
import {
  type Nip07,
  type Signer,
  appIdFromOrigin,
  nip07Signer,
  poolRelays,
  secretKeySigner,
  webauthnPasskeys,
  fromHex,
  randomBytes,
  toHex,
} from "@evolustr/core";

const Schema = {
  note: { id: id("Note"), text: NonEmptyTrimmedString1000 },
};
type AppSchema = WithEvolustr<typeof Schema>;

const params = new URLSearchParams(location.search);
const relayUrls = (params.get("relays") ?? "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net").split(",");
const appId = appIdFromOrigin(location.origin, ["nsite.lol"]);

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const show = (id: string, visible: boolean) => ($(id).hidden = !visible);
const fail = (message: string) => ($("error").textContent = message);

/** NIP-07 signer if present; otherwise a demo key kept in this browser (clearly labelled). */
const pickSigner = (): { signer: Signer; label: string } => {
  const nostr = (window as unknown as { nostr?: Nip07 }).nostr;
  if (nostr !== undefined) return { signer: nip07Signer(nostr), label: "your Nostr signer" };
  let hex = localStorage.getItem("evolustr-demo-key");
  if (hex === null) {
    hex = toHex(randomBytes(32));
    localStorage.setItem("evolustr-demo-key", hex);
  }
  return { signer: secretKeySigner(fromHex(hex)!), label: "a demo key in this browser (no NIP-07 signer found)" };
};

const evoluDeps = createEvoluDeps();
const run = createRun(evoluDeps);
const databases = evoluDatabases({
  appId,
  schema: Schema,
  createEvolu: ({ schema, appOwner, appName }) =>
    run.ok(
      createEvolu(schema, {
        appName: AppName.orThrow(appName),
        appOwner,
        // Evolustr deletes the old local database after a migration; don't reload the page.
        onDatabaseDeleted: () => {},
        ...(params.get("sync") === "off" ? { transports: [] } : {}),
      }),
    ),
});
const createQuery = createQueryBuilder({ ...Schema, ...evolustrSchema });
const notesQuery = createQuery((db) =>
  db.selectFrom("note").select(["id", "text"]).where("isDeleted", "is not", 1).orderBy("createdAt"),
);

let client: Evolustr | null = null;
// For end-to-end tests.
(window as unknown as { evolustrStatus?: () => unknown }).evolustrStatus = () => client?.status();
let unsubscribe: (() => void) | null = null;

const evolu = (): Evolu<AppSchema> => {
  const e = databases.current();
  if (e === null) throw new Error("Not connected");
  return e;
};

const renderNotes = () => {
  const rows = evolu().getQueryRows(notesQuery);
  $("list").replaceChildren(
    ...rows.map((r) => {
      const li = document.createElement("li");
      li.textContent = r.text ?? "";
      return li;
    }),
  );
};

const renderStatus = () => {
  const st = client?.status();
  if (!st) return;
  $("level").textContent = st.level === "strong" ? "strong (strict)" : "weak (as private as your Nostr DMs)";
  $("level").className = `badge ${st.level}`;
  $("detail").textContent = `opened with ${st.unlockedWith}${st.backupRecommended ? " · save your recovery phrase or add a second passkey" : ""}`;
  ($("strict") as HTMLButtonElement).disabled = !st.canMakeStrict;
  ($("downgrade") as HTMLButtonElement).disabled = st.mode !== "strict";
  ($("passkey") as HTMLButtonElement).disabled = !st.passkeySupported || !st.canAddStrongMethod;
  document.documentElement.dataset["theme"] = client!.settings.get("theme") === "system" ? "" : client!.settings.get("theme");
};

const becameReady = async () => {
  show("unlock", false);
  show("usePhrase", false);
  show("actions", true);
  show("notes", true);
  $("state").textContent = "Connected";
  renderStatus();
  unsubscribe?.();
  await evolu().loadQuery(notesQuery);
  unsubscribe = evolu().subscribeQuery(notesQuery)(renderNotes);
  renderNotes();
};

const handle = async (result: ConnectResult) => {
  if (result.state === "ready") return becameReady();
  show("actions", true);
  if (result.state === "needsUserAction") {
    $("state").textContent =
      result.action === "recoveryPhrase" ? "Enter your recovery phrase to open your notes on this device" : `Click Unlock (${result.action})`;
    show("unlock", result.action !== "recoveryPhrase");
    show("usePhrase", true);
    return;
  }
  $("state").textContent = `Your vault changed (${result.reason}). Options: ${result.options.join(", ")}`;
};

$("connect").onclick = async () => {
  fail("");
  const { signer, label } = pickSigner();
  client = createEvolustr(
    {
      signer,
      relays: poolRelays(),
      openDatabase: databases.open,
      cache: keyValueCache(localStorage),
      passkeys: webauthnPasskeys({ rpName: "Evolustr Notes" }),
      ...(detectCapableSigner((window as unknown as { nostr?: unknown }).nostr) === undefined
        ? {}
        : { capableSigner: detectCapableSigner((window as unknown as { nostr?: unknown }).nostr)! }),
    },
    { appId, relayUrls },
  );
  $("state").textContent = `Connecting with ${label}…`;
  const r = await client.connect();
  if (!r.ok) return fail(r.error.message);
  await handle(r.value);
};

$("unlock").onclick = async () => {
  if (client === null) return;
  const r = await client.unlock();
  if (!r.ok) return fail(`${r.error.message} — you can use your recovery phrase instead.`);
  await becameReady();
};

$("usePhrase").onclick = async () => {
  if (client === null) return;
  const phrase = prompt("Recovery phrase (12 words)");
  if (phrase === null) return;
  const r = await client.unlock({ recoveryPhrase: phrase });
  if (!r.ok) return fail(r.error.message);
  await becameReady();
};

$("add").onsubmit = (e) => {
  e.preventDefault();
  const input = $<HTMLInputElement>("text");
  const text = NonEmptyTrimmedString1000.fromUnknown(input.value.trim());
  if (!text.ok) return;
  evolu().insert("note", { text: text.value });
  input.value = "";
};

const action = (id: string, f: (c: Evolustr) => Promise<{ ok: boolean; error?: { message: string } }>) => {
  $(id).onclick = async () => {
    if (client === null) return;
    fail("");
    const r = await f(client);
    if (!r.ok) fail(r.error?.message ?? "Failed");
    renderStatus();
  };
};

action("passkey", async (c) => {
  const r = await c.enrollPasskey();
  if (r.ok && !r.value.done) {
    $("detail").textContent = "Click “Add passkey” again to finish setup";
    $("passkey").onclick = async () => {
      const f = await c.finishPasskeySetup();
      if (!f.ok) return fail(f.error.message);
      renderStatus();
      $("detail").textContent += " · passkey added";
    };
  }
  return r;
});
const passkeyButton = $("passkey").onclick;
$("passkey").onclick = async (e) => {
  await passkeyButton?.call($("passkey"), e);
  if ($("error").textContent === "" && !$("detail").textContent?.includes("again")) $("detail").textContent += " · passkey added";
};
action("strict", async (c) => {
  const r = await c.makeStrict();
  if (!r.ok && r.error.type === "backupRequired" && confirm(`${r.error.message}\n\nAccept losing these notes if you lose this device?`)) {
    return c.makeStrict({ acceptDeviceLoss: true });
  }
  if (r.ok) await becameReady();
  return r;
});
action("downgrade", (c) => c.downgrade());
action("showPhrase", async (c) => {
  const r = await c.showRecoveryPhrase();
  if (r.ok) {
    $("phrase").textContent = r.value;
    show("phrase", true);
  }
  return r;
});
action("theme", (c) => c.settings.setShared("theme", c.settings.get("theme") === "dark" ? "light" : "dark"));
$("logout").onclick = async () => {
  unsubscribe?.();
  await client?.logout();
  client = null;
  show("actions", false);
  show("notes", false);
  $("state").textContent = "Not connected";
};
