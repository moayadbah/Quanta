# Deviations from PROTOCOL-R11

## 1. v11 frozen before the speed check finished

The v11 source was frozen, and the annotators started, while the speed check (R11-A4) was still running. Every code change was complete at that point.

The rule fixed at the time: the speed result is reported whatever it is, and no code changes after the freeze.

**Result:** v11 was 0.2% faster than v10 (245.1 s against 245.5 s; median of three alternating runs over 21 H4 clones). So the gate was met, and nothing changed.

## 2. A usage limit stopped eighteen of the nineteen annotators

All annotators except batch 15 stopped on an API usage limit, a few minutes after they started. At that point two label files existed: batch 15's, and the second label of one double-labelled repository.

The limit reset some hours later. Each annotator was resumed from its own transcript, and label files already written were kept as written.

The limit stopped twelve of the resumed annotators a second time. At that point:
- 31 of the 60 primary label files existed.
- 8 of the 10 second label files existed.

They were resumed again the same way after the next reset.

During both stops:
- No label was read.
- No engine ran on H11.
- The v11 source stayed as frozen. Its hashes are in `evidence/r11/v11-source.sha256`.

## 3. How the double-labelled set was drawn

C6 says the 10 repositories are drawn "within each stratum" with `random.Random("20261021:double")`. The script used one generator for both strata: 7 from the sorted P names, then 3 from the sorted G names. The draw (`evidence/r11/double.json`) was made right after the sample was fixed, and before any label existed.

## 4. Option 5 not done

Cross-file tracking (option 5, "if time allows") was not implemented. The cross-file misses in the development data need two things a first version would not have:
- Tuple unpacking of another module's return value (django-allauth's `jwkkit`).
- Attribute types of another module's objects (kr8s).

The reason is recorded in `evidence/r11/dev-log.jsonl`.
