/** A value or an error, returned instead of throwing. */
export type Result<T, E = EvolustrError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

/** Errors are plain data: a stable `type` plus a human-readable `message`. */
export interface EvolustrError {
  readonly type: string;
  readonly message: string;
}

export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });

export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });

export const error = (type: string, message: string): Result<never, EvolustrError> =>
  err({ type, message });

export const map = <T, U, E>(r: Result<T, E>, f: (value: T) => U): Result<U, E> =>
  r.ok ? ok(f(r.value)) : r;

export const flatMap = <T, U, E, F>(
  r: Result<T, E>,
  f: (value: T) => Result<U, F>,
): Result<U, E | F> => (r.ok ? f(r.value) : r);

/** Runs `f` and turns a thrown exception into an error result. */
export const attempt = <T>(type: string, f: () => T): Result<T, EvolustrError> => {
  try {
    return ok(f());
  } catch (e) {
    return error(type, e instanceof Error ? e.message : String(e));
  }
};

/** Async variant of {@link attempt}. */
export const attemptAsync = async <T>(
  type: string,
  f: () => Promise<T>,
): Promise<Result<T, EvolustrError>> => {
  try {
    return ok(await f());
  } catch (e) {
    return error(type, e instanceof Error ? e.message : String(e));
  }
};

/** Collects results: the first error, or all values. */
export const all = <T, E>(results: ReadonlyArray<Result<T, E>>): Result<ReadonlyArray<T>, E> => {
  const values: T[] = [];
  for (const r of results) {
    if (!r.ok) return r;
    values.push(r.value);
  }
  return ok(values);
};

/** For tests and boundaries where an error is a bug. */
export const unwrap = <T, E>(r: Result<T, E>): T => {
  if (r.ok) return r.value;
  const e = r.error as unknown;
  throw new Error(typeof e === "object" && e !== null && "message" in e ? String(e.message) : String(e));
};
