# Domain docs

How engineering skills consume this repository's domain documentation.

## Layout and reading rules

This repository uses a single-context layout:

- Root `CONTEXT.md` for domain concepts and vocabulary.
- `docs/adr/` for architecture decision records.

Before exploring the codebase, read `CONTEXT.md` and any ADRs relevant to the work.

If these files do not exist, proceed silently. Do not flag their absence or suggest creating empty documents upfront. The `/domain-modeling` skill creates them as terms and decisions are resolved.

If the repository later adopts a root `CONTEXT-MAP.md`, follow its links to relevant context documents and also consult context-specific ADR directories.

## Use the glossary's vocabulary

When naming a domain concept in an issue, proposal, hypothesis, test, or implementation, use its definition in `CONTEXT.md`. Avoid synonyms the glossary explicitly excludes.

If a needed concept is absent, consider whether it belongs in the domain. Note genuine gaps for `/domain-modeling`.

## Flag ADR conflicts

If proposed work contradicts an existing ADR, identify the decision and explain the reason for reconsidering it rather than silently overriding it.
