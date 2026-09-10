/** Bound reads through both response headers and JSON body consumption. */
export async function requestJson(path, options = {}, timeoutMs = 30000, transport = {}) {
  const controller = new AbortController();
  const fetcher = transport.fetch || fetch;
  const schedule = transport.setTimeout || setTimeout;
  const cancel = transport.clearTimeout || clearTimeout;
  let timer;
  const read = async () => {
    const response = await fetcher(path, { ...options, signal: controller.signal });
    let data;
    try {
      data = await response.json();
    } catch (cause) {
      const error = new Error("Invalid JSON response", { cause });
      error.code = "INVALID_RESPONSE";
      throw error;
    }
    return { response, data };
  };
  try {
    if (!timeoutMs) return await read();
    return await Promise.race([
      read(),
      new Promise((_, reject) => {
        timer = schedule(() => {
          reject(new Error("Request timed out"));
          controller.abort();
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) cancel(timer);
  }
}
