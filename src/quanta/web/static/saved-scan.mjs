/** A completed scan stays complete even while its report is loading or retrying. */
export async function watchSavedScan(options) {
  let complete = options.initial?.status === "succeeded";
  const tick = async () => {
    if (!options.isCurrent()) return;
    try {
      if (!complete) {
        const data = await options.getStatus();
        if (!options.isCurrent()) return;
        complete = data.status === "succeeded";
        if (["failed", "timeout"].includes(data.status)) {
          options.failure(data);
          return;
        }
        if (!complete) {
          options.progress(data);
          if (data.status === "queued") options.queued();
        }
      }
      if (complete) {
        options.progress({ status: "loading_report", progress: 100 });
        await options.loadResult();
        return;
      }
    } catch (error) {
      if (!options.isCurrent()) return;
      if (["AUTH_REQUIRED", "REPO_NOT_FOUND"].includes(error.code)) {
        options.failure({ detail: error.message });
        return;
      }
      options.retry(error);
    }
    if (options.isCurrent()) options.schedule(tick, 3000);
  };
  options.progress(
    complete
      ? { status: "loading_report", progress: 100 }
      : options.initial || { status: "checking", progress: 0 },
  );
  await tick();
}
