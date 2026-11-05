// A minimal in-memory Nostr relay over WebSockets for tests (NIP-01 subset).
import { matchFilter, type Filter } from "nostr-tools/filter";
import { type Event, verifyEvent } from "nostr-tools/pure";
import { WebSocketServer } from "ws";

export const startTestRelay = (port: number) => {
  const events: Event[] = [];
  const wss = new WebSocketServer({ port });
  const dTag = (e: Event) => e.tags.find((t) => t[0] === "d")?.[1] ?? "";
  wss.on("connection", (ws) => {
    ws.on("message", (raw) => {
      const msg = JSON.parse(String(raw)) as unknown[];
      if (msg[0] === "EVENT") {
        const e = msg[1] as Event;
        if (!verifyEvent({ ...e })) return void ws.send(JSON.stringify(["OK", e.id, false, "invalid"]));
        const i = events.findIndex((x) => x.kind === e.kind && x.pubkey === e.pubkey && dTag(x) === dTag(e));
        if (e.kind >= 30000 && e.kind < 40000 && i !== -1) {
          if (events[i]!.created_at > e.created_at) return void ws.send(JSON.stringify(["OK", e.id, true, ""]));
          events.splice(i, 1);
        }
        events.push(e);
        ws.send(JSON.stringify(["OK", e.id, true, ""]));
      } else if (msg[0] === "REQ") {
        const [, sub, ...filters] = msg as [string, string, ...Filter[]];
        for (const e of events) if (filters.some((f) => matchFilter(f, e))) ws.send(JSON.stringify(["EVENT", sub, e]));
        ws.send(JSON.stringify(["EOSE", sub]));
      } else if (msg[0] === "CLOSE") {
        ws.send(JSON.stringify(["CLOSED", msg[1], ""]));
      }
    });
  });
  return { events, close: () => new Promise<void>((r) => wss.close(() => r())) };
};
