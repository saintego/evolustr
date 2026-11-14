/**
 * The app database behind an interface (SPEC §2, §3.4, §6.2 rules 5–6).
 * `evolu.ts` implements it with Evolu 8.x; tests use `memoryDatabases`.
 */
import { type Bytes, sHash } from "@evolustr/core";

export interface Row {
  readonly id: string;
  readonly isDeleted: boolean;
  /** `updatedAt ?? createdAt`, as Unix milliseconds. */
  readonly changedAt: number;
  /** The app's own columns (no system columns). */
  readonly values: Readonly<Record<string, unknown>>;
}

export interface AppDatabase {
  /** `sHash` of the data secret this database was opened with. */
  readonly sHash: string;
  /** The app's tables, which a migration copies. */
  readonly tables: ReadonlyArray<string>;
  readonly readRows: (table: string) => Promise<ReadonlyArray<Row>>;
  readonly upsertRows: (table: string, rows: ReadonlyArray<Row>) => Promise<void>;
  /** Evolustr's own small key-value table (vault copy, settings cache). */
  readonly getMeta: (key: string) => Promise<string | null>;
  readonly setMeta: (key: string, value: string) => Promise<void>;
  /** Deletes the local database (not data on relays). */
  readonly deleteLocal: () => Promise<void>;
  readonly close: () => Promise<void>;
}

/** Opens (or creates) the local database for a data secret S. */
export type OpenDatabase = (s: Bytes) => Promise<AppDatabase>;

export const META_VAULT = "vault";
export const META_SHARED_SETTINGS = "sharedSettings";

export type MigrationMode =
  | { readonly kind: "all" }
  /** Copy rows missing in the target, or changed after `cutoffMs - marginMs`. */
  | { readonly kind: "since"; readonly cutoffMs: number; readonly marginMs: number }
  /** Copy only rows whose id isn't in the target; never overwrite (#51). */
  | { readonly kind: "missingOnly" };

export interface MigrationResult {
  /** Rows written to the target. */
  readonly copied: number;
  /** Rows the target already had, with different content in the source, that weren't copied. */
  readonly skippedChanged: number;
}

const sameContent = (a: Row, b: Row): boolean =>
  a.isDeleted === b.isDeleted && JSON.stringify(a.values) === JSON.stringify(b.values);

/** Copies rows between databases with upsert, keeping ids (SPEC §3.4). */
export const migrateRows = async (
  from: AppDatabase,
  to: AppDatabase,
  mode: MigrationMode,
): Promise<MigrationResult> => {
  let copied = 0;
  let skippedChanged = 0;
  for (const table of from.tables) {
    const source = await from.readRows(table);
    let rows = source;
    if (mode.kind !== "all") {
      const existing = new Map((await to.readRows(table)).map((r) => [r.id, r]));
      const after = mode.kind === "since" ? mode.cutoffMs - mode.marginMs : Number.POSITIVE_INFINITY;
      rows = source.filter((r) => !existing.has(r.id) || r.changedAt > after);
      const taken = new Set(rows.map((r) => r.id));
      skippedChanged += source.filter((r) => {
        const there = existing.get(r.id);
        return there !== undefined && !taken.has(r.id) && !sameContent(r, there);
      }).length;
    }
    if (rows.length > 0) await to.upsertRows(table, rows);
    copied += rows.length;
  }
  return { copied, skippedChanged };
};

/** In-memory databases for tests, one per data secret. */
export const memoryDatabases = (tables: ReadonlyArray<string>, now: () => number = Date.now) => {
  const dbs = new Map<string, { rows: Map<string, Map<string, Row>>; meta: Map<string, string>; deleted: boolean }>();
  const open: OpenDatabase = (s) => {
    const key = sHash(s);
    let state = dbs.get(key);
    if (state === undefined || state.deleted) {
      state = { rows: new Map(tables.map((t) => [t, new Map()])), meta: new Map(), deleted: false };
      dbs.set(key, state);
    }
    const st = state;
    const db: AppDatabase = {
      sHash: key,
      tables,
      readRows: async (table) => [...(st.rows.get(table)?.values() ?? [])],
      upsertRows: async (table, rows) => {
        const t = st.rows.get(table);
        if (t === undefined) throw new Error(`Unknown table ${table}`);
        for (const r of rows) t.set(r.id, { ...r, changedAt: now() });
      },
      getMeta: async (k) => st.meta.get(k) ?? null,
      setMeta: async (k, v) => void st.meta.set(k, v),
      deleteLocal: async () => {
        st.deleted = true;
      },
      close: async () => {},
    };
    return Promise.resolve(db);
  };
  /** Test helper: write a row as the app would. */
  const write = async (s: Bytes, table: string, id: string, values: Record<string, unknown>) =>
    (await open(s)).upsertRows(table, [{ id, isDeleted: false, changedAt: now(), values }]);
  return { open, write, has: (s: Bytes) => dbs.has(sHash(s)) && !dbs.get(sHash(s))!.deleted };
};
