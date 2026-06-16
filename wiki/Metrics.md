# Metrics

deep-xpia reports the standard detection metrics plus two specific to multi-hop delegation.

## Standard metrics

- **ASR (attack success rate)** - fraction of attack cases where the injection reached its goal.
- **TPR (true positive rate)** - fraction of attacks the defense detected.
- **FPR (false positive rate)** - fraction of clean cases the defense wrongly flagged.

## DDA: depth-dependent accuracy

DDA bins detection accuracy by injection depth (number of delegation hops the payload travels). It was built to test a hypothesis: that detection falls as depth grows, because each trusted intermediate agent rephrases the injection closer to natural output.

In the live run, that hypothesis did not hold. Intent-verification detection by depth was flat and noisy (0.20 / 0.19 / 0.25 / 0.38 / 0.18), and with all defenses it rose with depth rather than falling. Depth turned out to be confounded with attack type: depth-1 cases are all registry injection (DXPIA-008), which evades prompt-stream defenses, while deeper buckets are dominated by patterns the defenses catch well.

So DDA's value here was as a falsifier. It took a clean simulated curve and showed that live measurement does not reproduce it. That is what a metric is for. The honest conclusion is that hop count does not predict detection; trust-boundary position and attack type do.

## CAS: context accumulation score

CAS tracks `breadth_ratio = accessed / available` sources per hop, then buckets cases as low, medium, or high breadth. It captures the intuition that an agent pulling many sources into one window assembles context no human reviewer would gather by hand, where every individual access looks authorized and the risk is the aggregate. CAS remains a metric plus the `context_budget` defense; the proposed DXPIA-009 (context harvesting) would promote it to a first-class attack class.

## Reading the numbers

Report the case count with every rate. With n=1 per case, small per-depth and per-taxonomy cells are noisy, so read them as directional. A single aggregate TPR hides the structure; the per-taxonomy breakdown (especially the DXPIA-008 blind spot) tells you more.
