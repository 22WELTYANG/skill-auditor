# We scanned N public AI Skills: X% contained dangerous patterns

> Replace every placeholder from a frozen corpus snapshot. Use "dangerous
> pattern" rather than "malicious Skill"; scanner matches are evidence for
> review, not proof of author intent.

## Executive summary

- Repositories: `N`
- Valid Skills: `N`
- Scanner version and rule digest: `vX / SHA256`
- Skills with CRITICAL patterns: `X%`
- Skills with WARNING-only patterns: `X%`
- Human-reviewed findings: `N`
- Overall precision with 95% Wilson interval: `X% [low, high]`

## Method

Describe repository discovery queries, fixed commit selection, license
collection, safe tarball extraction, scanner settings, deduplication by
fingerprint, stratified sampling, and the 20% independent second-review set.

## Results

Report prevalence by category and rule, separating deterministic findings from
semantic pre-filters. Include baseline adoption results as the reduction in
existing findings shown as new CI annotations.

## False-positive analysis

List the most common benign contexts, the rules changed in response, and the
synthetic negative fixtures added. Do not reproduce third-party source,
credentials, or identifying snippets.

## Limitations

State sampling bias, GitHub-only coverage, inaccessible or deleted repositories,
language coverage, semantic-provider configuration, annotation disagreement,
and why dangerous patterns do not establish malicious intent.

## Reproducibility

Publish the metadata-only manifest, result set, aggregate statistics, labeling
sheet, scanner tag, rule digest, and exact commands from
`scripts/research_corpus.py`.
