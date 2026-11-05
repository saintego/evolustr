import { describe, expect, it } from "vitest";
import { all, attempt, err, flatMap, map, ok } from "../src/index.ts";

describe("Result", () => {
  it("maps values and passes errors through", () => {
    expect(map(ok(2), (n) => n * 2)).toEqual(ok(4));
    expect(map(err("x"), (n: number) => n * 2)).toEqual(err("x"));
  });
  it("chains with flatMap", () => {
    expect(flatMap(ok(2), (n) => (n > 1 ? ok(n) : err("small")))).toEqual(ok(2));
    expect(flatMap(ok(0), (n) => (n > 1 ? ok(n) : err("small")))).toEqual(err("small"));
  });
  it("turns throws into errors", () => {
    const r = attempt("boom", () => {
      throw new Error("bad");
    });
    expect(r).toEqual(err({ type: "boom", message: "bad" }));
  });
  it("collects all or the first error", () => {
    expect(all([ok(1), ok(2)])).toEqual(ok([1, 2]));
    expect(all([ok(1), err("a"), err("b")])).toEqual(err("a"));
  });
});
