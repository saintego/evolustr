// End-to-end test of the demo in Chromium: real Evolu, a local relay, a virtual passkey.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");
import { startTestRelay as startRelay } from "../../../packages/core/test/support/relay.ts";

const RELAY = "ws://localhost:7781";
const APP = `http://localhost:4181/?relays=${encodeURIComponent(RELAY)}&sync=off`;
const relay = startRelay(7781);
const preview = spawn("npx", ["vite", "preview", "--port", "4181", "--strictPort"], { stdio: "ignore" });
await new Promise((r) => setTimeout(r, 2500));

const assert = (cond, msg) => { if (!cond) throw new Error(`FAILED: ${msg}`); console.log(`ok - ${msg}`); };
const text = (page, sel) => page.locator(sel).innerText();

const browser = await chromium.launch();
let failed = false;
try {
  // Device 1
  const ctx1 = await browser.newContext();
  const page = await ctx1.newPage();
  page.on("pageerror", (e) => console.log("pageerror:", e.message));
  page.on("console", (m) => { if (m.type() === "error") console.log("console error:", m.text()); });
  const cdp = await ctx1.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true,
    defaultBackupEligibility: true, defaultBackupState: true } });

  await page.goto(APP);
  await page.click("#connect");
  await page.waitForSelector("#notes:not([hidden])", { timeout: 20000 });
  assert((await text(page, "#level")).startsWith("weak"), "first use creates a weak (compatible) database");

  await page.fill("#text", "hello from evolu");
  await page.press("#text", "Enter");
  await page.waitForSelector("#list li", { timeout: 10000 });
  assert((await text(page, "#list")).includes("hello from evolu"), "a note is stored in the real Evolu database");

  await page.click("#showPhrase");
  await page.waitForSelector("#phrase:not([hidden])");
  const phrase = await text(page, "#phrase");
  assert(phrase.split(/\s+/).length === 12, "recovery phrase has 12 words");

  await page.click("#passkey");
  await page.waitForFunction(() => document.querySelector("#detail")?.textContent?.includes("passkey added"), null, { timeout: 15000 });
  assert(!(await page.locator("#strict").isDisabled()), "after adding a passkey, strict can be chosen");

  page.once("dialog", (d) => d.accept());
  await page.click("#strict");
  await page.waitForFunction(() => document.querySelector("#level")?.textContent?.startsWith("strong"), null, { timeout: 20000 });
  assert(true, "make strict switches to a strong database");
  await page.waitForSelector("#list li", { timeout: 10000 });
  assert((await text(page, "#list")).includes("hello from evolu"), "the note moved to the new data secret");

  await page.reload();
  await page.click("#connect");
  await page.waitForSelector("#notes:not([hidden])", { timeout: 20000 });
  await page.waitForSelector("#list li", { timeout: 10000 });
  assert((await text(page, "#detail")).includes("cache"), "a reload opens from the device cache, no prompt");
  assert((await text(page, "#list")).includes("hello from evolu"), "the note is still there after reload");

  // Device 2: same Nostr key, no passkey here: needs the recovery phrase for a strict vault.
  const key = await page.evaluate(() => localStorage.getItem("evolustr-demo-key"));
  const ctx2 = await browser.newContext();
  const page2 = await ctx2.newPage();
  await page2.addInitScript((k) => localStorage.setItem("evolustr-demo-key", k), key);
  await page2.goto(APP);
  await page2.click("#connect");
  await page2.waitForSelector("#usePhrase:not([hidden])", { timeout: 20000 });
  assert(true, "a second device can't open the strict database without a strong method");
  page2.once("dialog", (d) => d.accept(phrase));
  await page2.click("#usePhrase");
  await page2.waitForSelector("#notes:not([hidden])", { timeout: 20000 });
  assert((await text(page2, "#level")).startsWith("strong"), "the second device opens the strict database with the phrase");
} catch (e) {
  failed = true;
  console.error(e.message);
  for (const p of browser.contexts().flatMap((c) => c.pages())) {
    console.error("page state:", await p.locator("#state").innerText().catch(() => "?"), "| error:", await p.locator("#error").innerText().catch(() => "?"), "| detail:", await p.locator("#detail").innerText().catch(() => "?"));
  }
} finally {
  await browser.close();
  preview.kill();
  await relay.close();
}
process.exit(failed ? 1 : 0);
