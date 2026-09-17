/**
 * GIF search via Giphy's public API. This only ever talks directly to
 * Giphy from the browser (no Haven server involvement) to fetch public
 * GIF search results and the GIF bytes themselves — nothing here is
 * encrypted or private, it's the same as browsing giphy.com. Once a GIF
 * is picked, it's sent to a contact/group through the existing
 * attachment channel (kind="gif"), which IS end-to-end encrypted like
 * everything else.
 *
 * Get a free API key at https://developers.giphy.com (takes ~2 minutes,
 * no cost) and paste it in below — without one, GIF search won't work.
 */

const HavenGiphy = (() => {
  "use strict";

  const GIPHY_API_KEY = "YRP6iu66lCdqL5iLqPNe4Aq3JqbOozzV";

  async function search(query, limit = 12) {
    const url = `https://api.giphy.com/v1/gifs/search?api_key=${encodeURIComponent(GIPHY_API_KEY)}&q=${encodeURIComponent(query)}&limit=${limit}&rating=pg-13`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Giphy search failed (${resp.status})`);
    const data = await resp.json();
    return data.data.map((g) => ({
      id: g.id,
      previewUrl: g.images.fixed_width_small.url,
      fullUrl: g.images.fixed_width.url,
      title: g.title,
    }));
  }

  async function fetchGifBytes(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Could not download GIF (${resp.status})`);
    return new Uint8Array(await resp.arrayBuffer());
  }

  return { search, fetchGifBytes, get configured() { return GIPHY_API_KEY !== "YOUR_GIPHY_API_KEY_HERE"; } };
})();
