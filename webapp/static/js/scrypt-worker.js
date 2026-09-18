/**
 * Runs scrypt derivation off the main thread. crypto.js's scrypt() is a
 * from-spec implementation (WebCrypto has no native scrypt) whose ROMix
 * step is a tight synchronous loop with no `await` inside it — on the
 * main thread that freezes the tab (no repaint, no input) for the
 * entire derivation, which is exactly the "click Log in, nothing
 * happens for a second" feeling this worker exists to fix. Moving the
 * SAME computation here doesn't make it faster, but it stops it from
 * blocking the page, so the loading spinner (see app.js) actually
 * animates while it runs instead of freezing along with everything else.
 */
importScripts("crypto.js?v=31");

self.onmessage = async (e) => {
  const { id, op, password, salt, n } = e.data;
  try {
    let result;
    if (op === "deriveKeyFromPassword") {
      result = { key: await Haven.deriveKeyFromPassword(password, salt, 32, n) };
    } else {
      result = await Haven.deriveSplitKeys(password, salt, n);
    }
    self.postMessage({ id, ...result });
  } catch (err) {
    self.postMessage({ id, error: err.message || String(err) });
  }
};
