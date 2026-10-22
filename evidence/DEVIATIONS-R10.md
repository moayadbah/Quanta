# Deviations from PROTOCOL-R10

## 1. A usage limit stopped two annotators mid-batch

The annotators of batch 1 and batch 7 stopped on an API usage limit. Each was resumed from its own transcript after the limit reset, and each finished its batch. Label files written before the stop were kept as written.

- **Before the stop:** the v10 source had been frozen (`evidence/r10/v10-source.sha256`) before any annotator started.
- **At the time:** no label had been read, and no engine had run on H10.

## 2. Annotator prompts

Every H10 annotator received the prompt that states the defensive purpose of the study. Round nine had used that prompt only on the second attempt (DEVIATIONS-R9 1).

- **Solo annotators:** the three repositories that are security scanners (ysrc/GourdScanV2, gyoisamurai/GyoiThon, guelfoweb/knockpy) were each given to an annotator of their own.
- **Final message:** each annotator's final message was limited to unit counts per repository, so no annotator report could inform development (R10-C5).
- **Outcome:** no annotator was stopped by the model's safeguards.

## 3. First H10 run failed before producing any output

The first run of v5, v9 and v10 over H10 failed on every repository with the same error: `FileNotFoundError` for `config/standards.json`. The engine snapshots had been copied as bare `src` folders, and the readiness pass reads `config/` beside `src`. No findings file was written, so nothing was scored or read.

The snapshots were rebuilt as `engines/<version>/src` with `config/`, `templates/` and `content/` beside them:
- v5 from main ce201a3.
- v9 and v10 from the working copy. Their configuration is identical to main.

The v10 hashes were checked again, and the run was repeated once.
