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
  webSecretCache,
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
const DEFAULT_RELAYS = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"];
// ?relays= only works on localhost (for tests): on the public demo a crafted
// link could otherwise point it at relays that hold back newer vaults (#33).
const isLocal = ["localhost", "127.0.0.1"].includes(location.hostname);
const relayUrls = isLocal && params.get("relays") ? params.get("relays")!.split(",") : DEFAULT_RELAYS;
const appIdResult = appIdFromOrigin(location.origin, ["nsite.lol"]);
if (!appIdResult.ok) document.body.textContent = `This page can't keep app data: ${appIdResult.error.message}`;
const appId = appIdResult.ok ? appIdResult.value : "";

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
// Show Evolu's own errors (database refused, worker failed, ...) instead of hanging silently.
evoluDeps.evoluError.subscribe(() => {
  const e = evoluDeps.evoluError.get();
  if (e !== null) fail(`Evolu: ${JSON.stringify(e).slice(0, 300)}`);
});
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
  ($("strict") as HTMLButtonElement).disabled = !st.canMakeStrict && !st.canReplaceRoot;
  $("strict").textContent = st.canReplaceRoot ? "Make strict with a new recovery phrase" : "Make strict";
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

/** After an unlock proved the vault on the relays isn't the user's (#39). */
const replacedChoices: ConnectResult = { state: "vaultChanged", reason: "replaced", options: ["republishCopy", "restorePhrase", "startNew"] };

const handle = async (result: ConnectResult) => {
  if (result.state === "ready") return becameReady();
  show("actions", true);
  if (result.state === "needsUserAction") {
    $("state").textContent =
      result.action === "recoveryPhrase"
        ? "Enter your recovery phrase to open your notes on this device"
        : result.action === "confirmWeak"
          ? "First time on this device: your notes will open through your Nostr signer (weak level, as private as your Nostr DMs). If you made them strict on another device, don't continue: use your passkey or recovery phrase instead. Click Unlock to continue."
          : `Click Unlock (${result.action})`;
    show("unlock", result.action !== "recoveryPhrase");
    show("usePhrase", true);
    return;
  }
  const reasons = {
    replaced: "Your notes' vault on the relays was replaced by something this device doesn't trust.",
    ambiguous: "Your notes' vault on the relays changed, and this device can't verify the change.",
    missing: "Your notes' vault wasn't found, or not every relay answered.",
  } as const;
  const labels = {
    republishCopy: "Restore this device's copy",
    followRelay: "Use the version on the relays",
    restorePhrase: "Use recovery phrase",
    startNew: "Start new notes",
  } as const;
  $("state").textContent = reasons[result.reason];
  $("choices").replaceChildren(
    ...result.options.map((choice) => {
      const b = document.createElement("button");
      b.textContent = labels[choice];
      b.onclick = async () => {
        if (client === null) return;
        if (choice === "startNew" && !confirm("Start a new, empty notes database? If you have notes elsewhere, they won't be here.")) return;
        const phrase = choice === "restorePhrase" ? prompt("Recovery phrase (12 words)") : null;
        if (choice === "restorePhrase" && phrase === null) return;
        const r = await client.resolveVaultChange(choice, phrase === null ? undefined : { recoveryPhrase: phrase });
        if (!r.ok) return fail(r.error.message);
        $("choices").replaceChildren();
        await becameReady();
      };
      return b;
    }),
  );
};

$("connect").onclick = async () => {
  fail("");
  const { signer, label } = pickSigner();
  client = createEvolustr(
    {
      signer,
      relays: poolRelays(),
      openDatabase: databases.open,
      cache: webSecretCache(),
      // Non-secret hint that survives logout (#44).
      hints: {
        get: async (k) => localStorage.getItem(k),
        set: async (k, v) => localStorage.setItem(k, v),
        remove: async (k) => localStorage.removeItem(k),
      },
      passkeys: webauthnPasskeys({ rpName: "Evolustr Notes" }),
      capableSigner: detectCapableSigner((window as unknown as { nostr?: unknown }).nostr),
    },
    {
      appId,
      relayUrls,
      onProgress: (step) => {
        const text = {
          lookingUpVault: "Looking up your notes' vault on the relays…",
          creatingVault: "First time: creating your notes' vault…",
          publishingVault: "Saving the vault to the relays (a slow relay can take a few seconds)…",
          openingDatabase: "Opening your notes…",
        } as const;
        $("state").textContent = text[step];
      },
    },
  );
  $("state").textContent = `Connecting with ${label} via ${relayUrls.join(", ")}…`;
  const r = await client.connect();
  if (!r.ok) return fail(r.error.message);
  await handle(r.value);
};

$("unlock").onclick = async () => {
  if (client === null) return;
  const r = await client.unlock();
  if (!r.ok && r.error.type === "vaultReplaced") return handle(replacedChoices);
  if (!r.ok) return fail(`${r.error.message} — you can use your recovery phrase instead.`);
  await becameReady();
};

$("usePhrase").onclick = async () => {
  if (client === null) return;
  const phrase = prompt("Recovery phrase (12 words)");
  if (phrase === null) return;
  const r = await client.unlock({ recoveryPhrase: phrase });
  if (!r.ok && r.error.type === "vaultReplaced") return handle(replacedChoices);
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
  if (!confirm("Strict protects notes you write from now on. Notes written before stay as private as they were (any app you let decrypt with your signer could have kept the old key). Continue?")) return { ok: true };
  // This device can't open the current root key (#49): start over with a new one.
  const replaceRoot = c.status()?.canReplaceRoot === true;
  if (replaceRoot && !confirm("This device can't unlock your current recovery phrase and passkeys for this app, so new ones are made. Your earlier recovery phrase and passkeys for this app will stop working. Continue?")) return { ok: true };
  let r = await c.makeStrict({ replaceRoot });
  if (!r.ok && r.error.type === "backupRequired" && confirm(`${r.error.message}\n\nAccept losing these notes if you lose this device?`)) {
    r = await c.makeStrict({ replaceRoot, acceptDeviceLoss: true });
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
action("exportEvolu", async (c) => {
  if (!confirm("This phrase opens these notes in any Evolu app, without Nostr. Anyone who has it can read and change them. It changes if you make the notes strict. Show it?")) return { ok: true };
  const r = c.exportEvoluMnemonic();
  if (r.ok) {
    $("phrase").textContent = `Evolu phrase: ${r.value}`;
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
