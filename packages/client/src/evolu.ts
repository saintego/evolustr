/**
 * {@link AppDatabase} over Evolu 8.x (SPEC §2).
 *
 * The app keeps control of Evolu's platform setup (web workers, React Native):
 * it passes `createEvolu`, which Evolustr calls with the schema, the AppOwner
 * made from S, and the app name.
 */
import {
  type AppOwner,
  type Evolu,
  type EvoluSchema,
  OwnerSecret,
  String as EvoluString,
  createAppOwner,
  createIdFromString,
  createQueryBuilder,
  id,
} from "@evolu/common";
import { type Bytes, sHash, sha256Hex } from "@evolustr/core";
import type { AppDatabase, OpenDatabase, Row } from "./database.ts";

/** Evolustr's own table, merged into the app's schema. */
export const evolustrSchema = {
  evolustrMeta: { id: id("EvolustrMeta"), value: EvoluString },
} as const;

export type WithEvolustr<S extends EvoluSchema> = S & typeof evolustrSchema;

/** Local database name: Evolu adds the AppOwner, so accounts never mix (SPEC §2). */
export const evoluAppName = (appId: string): string => `evolustr-${sha256Hex(appId).slice(0, 16)}`;

export interface EvoluDatabaseOptions<S extends EvoluSchema> {
  readonly appId: string;
  readonly schema: S;
  readonly createEvolu: (args: {
    readonly schema: WithEvolustr<S>;
    readonly appOwner: AppOwner;
    readonly appName: string;
  }) => Evolu<WithEvolustr<S>> | Promise<Evolu<WithEvolustr<S>>>;
}

const SYSTEM_COLUMNS = new Set(["id", "createdAt", "updatedAt", "isDeleted", "ownerId"]);

/* Evolu's API is typed per table name; Evolustr works over any table, so the
   few dynamic calls below go through `Loose`. */
type Loose = any;

const toRow = (raw: Record<string, unknown>): Row => {
  const values: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) if (!SYSTEM_COLUMNS.has(k)) values[k] = v;
  const changed = (raw["updatedAt"] ?? raw["createdAt"]) as string | null | undefined;
  return {
    id: String(raw["id"]),
    isDeleted: raw["isDeleted"] === 1,
    changedAt: changed ? Date.parse(changed) : 0,
    values,
  };
};

/** Opens Evolu databases for data secrets; the latest instance is exposed for the app. */
export const evoluDatabases = <S extends EvoluSchema>(options: EvoluDatabaseOptions<S>) => {
  const schema = { ...options.schema, ...evolustrSchema } as WithEvolustr<S>;
  const createQuery = createQueryBuilder(schema) as Loose;
  const appTables = Object.keys(options.schema);
  const appName = evoluAppName(options.appId);
  let current: Evolu<WithEvolustr<S>> | null = null;

  const open: OpenDatabase = async (s: Bytes) => {
    const appOwner = createAppOwner(OwnerSecret.orThrow(s));
    const evolu = await options.createEvolu({ schema, appOwner, appName });
    current = evolu;
    const e = evolu as Loose;

    const upsert = (table: string, values: Record<string, unknown>) =>
      new Promise<void>((resolve) => {
        e.upsert(table, values, { onComplete: resolve });
      });

    const db: AppDatabase = {
      sHash: sHash(s),
      tables: appTables,
      readRows: async (table) => {
        const rows = (await e.loadQuery(createQuery((q: Loose) => q.selectFrom(table).selectAll()))) as ReadonlyArray<
          Record<string, unknown>
        >;
        return rows.map(toRow);
      },
      upsertRows: async (table, rows) => {
        await Promise.all(
          rows.map((r) => upsert(table, { ...r.values, id: r.id, isDeleted: r.isDeleted ? 1 : 0 })),
        );
      },
      getMeta: async (key) => {
        const metaId = createIdFromString(key);
        const rows = (await e.loadQuery(
          createQuery((q: Loose) => q.selectFrom("evolustrMeta").select(["value"]).where("id", "=", metaId)),
        )) as ReadonlyArray<{ value: string | null }>;
        return rows[0]?.value ?? null;
      },
      setMeta: (key, value) => upsert("evolustrMeta", { id: createIdFromString(key), value }),
      deleteLocal: async () => {
        await e.deleteDatabase();
      },
      close: async () => {
        await e[Symbol.asyncDispose]?.();
        if (current === evolu) current = null;
      },
    };
    return db;
  };

  return { open, current: () => current };
};
