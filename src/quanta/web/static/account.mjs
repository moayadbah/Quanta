/** Publish each successful startup read immediately, even if the other is offline. */
export async function loadAccount(options, kinds = ["session", "workspace"]) {
  const wait = options.wait || ((delay) => new Promise((resolve) => setTimeout(resolve, delay)));
  await Promise.all(kinds.map(async (kind) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      let value;
      try {
        value = await options.read[kind]();
      } catch (error) {
        if (attempt === 2) {
          options.failed(kind, error);
          return;
        }
        options.retrying(kind);
        await wait(1000 * (attempt + 1));
        continue;
      }
      options.loaded(kind, value);
      return;
    }
  }));
}
