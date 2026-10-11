# v2 depth effect: GEE logistic sensitivity model

Model: detected ~ depth + C(taxonomy); binomial/logit; exchangeable correlation within payload
template (16 clusters); robust SEs. Odds ratio per extra hop with 95% CI; AME = average marginal
effect on detection probability per hop (point estimate).
Command: `python results/reanalysis/depth_gee_v2.py` (statsmodels; `pip install -e '.[analysis]'`)

| Defense | depth | odds ratio per hop [95% CI] | p | AME per hop |
|---|---|---|---|---|
| intent | executed calls | 0.96 [0.52, 1.76] | 0.894 | -0.008 |
| intent | hops after injection | 1.44 [0.93, 2.22] | 0.105 | +0.072 |
| all | executed calls | 2.51 [1.45, 4.36] | 0.00107 | +0.107 |
| all | hops after injection | 2.02 [1.13, 3.59] | 0.0171 | +0.083 |

Read with v2_stats.md: the logistic model agrees on direction. Some taxonomies are detected in all or
none of their cases under one defense, so their fixed effects sit near the boundary; treat the odds
ratios as a sensitivity check, not the primary estimate.
