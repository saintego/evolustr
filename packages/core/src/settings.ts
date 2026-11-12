/** Shared settings document (SPEC §9): per-field values with timestamps. */
import { type EvolustrError, type Result, error, ok } from "./result.ts";

export interface SharedSettings {
  readonly theme: "light" | "dark" | "system";
  readonly language: string;
  readonly locale: string;
  readonly timeZone: string;
  readonly reducedMotion: boolean;
  readonly fontScale: number;
  readonly density: "compact" | "comfortable";
}

export type SettingKey = keyof SharedSettings;

export interface SettingEntry {
  readonly value: unknown;
  /** Unix seconds of the change. */
  readonly at: number;
}

export interface SettingsDoc {
  readonly v: 1;
  readonly values: Readonly<Record<string, SettingEntry>>;
}

export const emptySettings: SettingsDoc = { v: 1, values: {} };

const validators: { readonly [K in SettingKey]: (v: unknown) => v is SharedSettings[K] } = {
  theme: (v): v is SharedSettings["theme"] => v === "light" || v === "dark" || v === "system",
  language: (v): v is string => typeof v === "string" && v.length > 0 && v.length <= 35,
  locale: (v): v is string => typeof v === "string" && v.length > 0 && v.length <= 35,
  timeZone: (v): v is string => typeof v === "string" && v.length > 0 && v.length <= 64,
  reducedMotion: (v): v is boolean => typeof v === "boolean",
  fontScale: (v): v is number => typeof v === "number" && v >= 0.75 && v <= 2,
  density: (v): v is SharedSettings["density"] => v === "compact" || v === "comfortable",
};

/** Own keys only: `constructor`, `__proto__` and the like are not settings (#33). */
export const isSettingKey = (key: string): key is SettingKey => Object.hasOwn(validators, key);

/** A plain map with no prototype, so keys like `__proto__` are ordinary entries. */
const emptyValues = (): Record<string, SettingEntry> => Object.create(null) as Record<string, SettingEntry>;

/** Valid value for a known key? Unknown (namespaced) keys accept any JSON value. */
export const isValidSetting = (key: string, value: unknown): boolean =>
  isSettingKey(key) ? validators[key](value) : key.startsWith("x-");

export const parseSettings = (json: string): Result<SettingsDoc, EvolustrError> => {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return error("invalidSettings", "Settings content is not JSON");
  }
  if (typeof data !== "object" || data === null || (data as { v?: unknown }).v !== 1) {
    return error("invalidSettings", "Unknown settings version");
  }
  const raw = (data as { values?: unknown }).values;
  if (typeof raw !== "object" || raw === null) return error("invalidSettings", "Missing values");
  const values = emptyValues();
  for (const [k, e] of Object.entries(raw)) {
    if (typeof e === "object" && e !== null && typeof (e as SettingEntry).at === "number" && "value" in e) {
      values[k] = { value: (e as SettingEntry).value, at: (e as SettingEntry).at };
    }
  }
  return ok({ v: 1, values });
};

/** Per field, the newer `at` wins; unknown keys are kept (SPEC §9.1). */
export const mergeSettings = (a: SettingsDoc, b: SettingsDoc): SettingsDoc => {
  const values = Object.assign(emptyValues(), a.values);
  for (const [k, e] of Object.entries(b.values)) {
    const mine = values[k];
    if (mine === undefined || e.at > mine.at || (e.at === mine.at && JSON.stringify(e.value) > JSON.stringify(mine.value))) {
      values[k] = e;
    }
  }
  return { v: 1, values };
};

export const setSetting = (doc: SettingsDoc, key: string, value: unknown, at: number): Result<SettingsDoc, EvolustrError> =>
  isValidSetting(key, value)
    ? ok({ v: 1, values: Object.assign(emptyValues(), doc.values, { [key]: { value, at } }) })
    : error("invalidSetting", `Invalid value for setting "${key}"`);

export const defaultSettings = (env: { readonly language?: string; readonly timeZone?: string } = {}): SharedSettings => ({
  theme: "system",
  language: env.language ?? "en",
  locale: env.language ?? "en",
  timeZone: env.timeZone ?? "UTC",
  reducedMotion: false,
  fontScale: 1,
  density: "comfortable",
});

/** `app ?? shared ?? default`, ignoring invalid stored values (SPEC §9.2). */
export const resolveSetting = <K extends SettingKey>(
  key: K,
  app: SettingsDoc,
  shared: SettingsDoc,
  defaults: SharedSettings,
): SharedSettings[K] => {
  for (const doc of [app, shared]) {
    const v = Object.hasOwn(doc.values, key) ? doc.values[key]?.value : undefined;
    if (validators[key](v)) return v;
  }
  return defaults[key];
};
