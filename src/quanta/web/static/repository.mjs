/** Convert common repository inputs to the strict URL accepted by the API.
 * Match the raw text before building a URL so parser normalization cannot hide
 * credentials, ports, extra paths, encoded separators, or traversal segments.
 */
export function normalizeRepositoryUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return null;
  const input = value.trim();
  const match = input.match(
    /^(?:(?:https?:\/\/)?(?:www\.)?github\.com\/)?([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,104})\/?$/i,
  );
  if (!match) return null;
  const owner = match[1];
  const repository = match[2].replace(/\.git$/, "");
  if (
    !repository ||
    repository.length > 100 ||
    [owner, repository].some((part) => part === "." || part === "..")
  ) {
    return null;
  }
  return `https://github.com/${owner}/${repository}`;
}
