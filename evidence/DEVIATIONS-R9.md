# Deviations from PROTOCOL-R9

## 1. Repositories the annotators cannot read (2026-10-17T22:25:34Z, before any H9 label was read and before any engine ran on H9)

Two annotator agents stopped with "safeguards flagged this message" while reading offensive-
security repositories of H9 (batch 3 at garrettfoster13/sccmhunter, batch 2 at a batch holding
MD-SEC/MDPOCS, NullArray/AutoSploit and ma1co/Sony-PMCA-RE). The frame (GitHub repositories with
more than 500 stars) contains such tools.

Rule, fixed now: each such repository is given once more to its own annotator with a prompt that
states the defensive purpose. If that annotator also stops, the repository is replaced by the
next kept repository of the same stratum in frame order (selection continued with the same rule,
`evidence/r9/extra/`), and the replacement is listed here. Repositories whose labels were
written are kept. The rule reads only whether a label file exists, never a label or a tool output.

Outcome: every repository was labelled on its second attempt (sccmhunter, Sony-PMCA-RE, MDPOCS
and AutoSploit by single-repository annotators with the defensive prompt; the rest of batches 2
and 3 by new annotators). No repository was replaced; `evidence/r9/extra/` is unused. Annotator
names agent-1 to agent-9 in the label files record who labelled what.

## 2. A usage limit stopped five annotators mid-batch

Five annotators stopped on an API usage limit. Each was resumed from its own transcript after
the limit reset and finished its batch; label files written before the stop were kept as written.
