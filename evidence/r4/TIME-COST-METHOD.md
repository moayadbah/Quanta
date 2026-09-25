# Time, cost and risk: method (round four)

Written before any figure below was computed. The hash and time are in TIME-COST-METHOD.sha256.
No human timing experiment was run. Every rate comes from a published source.

## Sources

1. Kemerer, C. F. and Paulk, M. C. (2009). The Impact of Design and Code Reviews on Software
   Quality: An Empirical Study Based on PSP Data. IEEE Transactions on Software Engineering
   35(4), 534 to 550. https://sites.pitt.edu/~ckemerer/PSP_Data.pdf.
   Abstract: "The recommended review rate of 200 LOC/hour or less was found to be an effective
   rate for individual reviews". Section 2 gives the inspection guidance: preparation for a code
   inspection "about 100 LOC/hour and no more than 200 LOC/hour".
2. U.S. Bureau of Labor Statistics, Occupational Outlook Handbook, Software Developers.
   https://www.bls.gov/ooh/computer-and-information-technology/software-developers.htm.
   "The median annual wage for software developers was $135,980 in May 2025."
3. Office of Management and Budget and ONCD (July 2024). Report on Post-Quantum Cryptography,
   as required by the Quantum Computing Cybersecurity Preparedness Act.
   https://bidenwhitehouse.archives.gov/wp-content/uploads/2024/07/REF_PQC-Report_FINAL_Send.pdf.
   Total federal civilian migration cost 2025 to 2035 "approximately $7.1 billion in 2024
   dollars"; agencies must perform "an annual manual inventory", which "entails researching each
   piece of hardware and software to discover the type of cryptography used".

## Corpus

The 60 labelled repositories of PROTOCOL-R4 (D: S01 to S20, H3: S21 to S40, H4: S41 to S60), at
the commits already cloned in evidence/clones/sample and evidence/clones/sample-r4. They were
chosen by the sampling rules of PROTOCOL-R3 and R4, not for this measurement.

## Measures

M1. Lines. Non-blank lines in every Python file the product walks, split by the product's own
file role (quanta.core.roles.classify_role). The headline uses shipped code (role "source")
only, because that is what the readiness assessment covers. All-file totals are reported too.

M2. Manual reading time = shipped lines / 200 lines per hour. 200 is the published upper
bound of an effective review rate (source 1), so this is a floor: it assumes a reviewer reads
every shipped line once at the fastest effective pace and spends nothing on cataloguing,
mapping deadlines or writing the result.

M3. Review of Quanta's output. A developer still reads what Quanta reports. Each finding is
charged 10 lines of context (the line and its surroundings) at 200 lines per hour, which is
3 minutes per finding. This charge is our assumption, stated as such.

M4. Quanta time = wall-clock seconds of the product's analysis of the local clone
(walk, parse, detect, graph, score, render, readiness, fix proposals), on the development
machine, one process, clone and network excluded. Reported as the total and the median.

M5. Time saved = M2 minus M3 minus M4, in hours. Reported as a total and per repository
(median).

M6. Cost saved = M5 hours times the BLS median wage per hour, $135,980 / 2,080 hours =
$65.38. Wage only, no overhead or benefits, so again a floor.

M7. Risk found and removed. From each analysis: shipped sites by readiness status
(vulnerable, weak, review, pq, safe); sites under an overdue milestone; and the number of
proposed changes that replace a weak or disallowed algorithm (MD5, SHA-1, DES, 3DES, RC4,
ECB) in shipped code. A proposal is counted, not assumed applied.

M8. Recall caveat carried with the figure. On the fresh held-out set H4, recall of labelled
crypto units was 70/74 (94.6%). The time a reviewer saves is time spent finding; the M3 charge
is the time spent confirming. The page shows both beside the figure.

## What is not claimed

No claim that a developer using Quanta finishes a migration faster in total. No claim about
the cost of a breach avoided. The OMB figure is shown as context for the scale of the work,
not as a Quanta saving.
