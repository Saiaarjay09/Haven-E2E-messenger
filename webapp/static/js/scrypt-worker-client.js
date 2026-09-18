/**
 * Main-thread handle for scrypt-worker.js — same deriveSplitKeys()
 * shape as Haven.deriveSplitKeys (see crypto.js), just routed through a
 * Worker so the heavy computation can't freeze the tab. One worker is
 * reused for the page's lifetime rather than spun up per call; requests
 * are correlated by an incrementing id since the worker may be asked to
 * do more than one derivation without waiting for the first to finish
 * (e.g. signup's password + recovery-phrase derivations).
 */
const HavenScryptWorker = (() => {
  "use strict";

  let worker = null;
  let nextId = 1;
  const pending = new Map();

  function getWorker() {
    if (worker) return worker;
    worker = new Worker("js/scrypt-worker.js?v=30");
    worker.onmessage = (e) => {
      const { id, error, ...result } = e.data;
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      if (error) p.reject(new Error(error));
      else p.resolve(result);
    };
    worker.onerror = (e) => {
      // A worker-level crash (e.g. a syntax error) has no per-request id
      // to route to — fail every call still waiting rather than hang
      // them forever.
      for (const p of pending.values()) p.reject(new Error(e.message || "scrypt worker failed"));
      pending.clear();
    };
    return worker;
  }

  function deriveSplitKeys(password, saltBytes, n) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      getWorker().postMessage({ id, op: "deriveSplitKeys", password, salt: saltBytes, n });
    });
  }

  function deriveKeyFromPassword(password, saltBytes, n) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      getWorker().postMessage({ id, op: "deriveKeyFromPassword", password, salt: saltBytes, n });
    }).then((r) => r.key);
  }

  return { deriveSplitKeys, deriveKeyFromPassword };
})();
