# Issue tracker: GitHub

Issues and specs for this repo live in GitHub Issues for `junnengsoo/ai-native-rmm`. Use the `gh` CLI for operations. Infer the repository from `git remote -v` when working inside the clone, or specify `--repo junnengsoo/ai-native-rmm` explicitly.

## Conventions

- **Create an issue:** `gh issue create --title "..." --body-file <path>`.
- **Read an issue:** `gh issue view <number> --comments`; also fetch labels when relevant using `--json number,title,body,labels,comments`.
- **List issues:** `gh issue list --state open --json number,title,body,labels,comments`, with appropriate label and state filters.
- **Comment:** `gh issue comment <number> --body-file <path>`.
- **Update body:** `gh issue edit <number> --body-file <path>`.
- **Apply or remove labels:** `gh issue edit <number> --add-label "..."` or `--remove-label "..."`.
- **Close:** `gh issue close <number>`; add an explanatory comment when appropriate.

For multiline bodies and comments, prepare the exact text in a temporary file and pass it with `--body-file` to preserve formatting and avoid shell interpolation.

## Pull requests as a triage surface

**PRs as a request surface: no.** Set to `yes` only if this repository should treat external PRs as feature requests; `/triage` reads this flag.

When enabled, use the equivalent `gh pr` commands to read, comment, label, and close PRs. Read both `gh pr view <number> --comments` and `gh pr diff <number>`. For external triage requests, retain authors with `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` associations, rather than owners, members, or collaborators.

GitHub shares one number space across issues and PRs. Resolve an ambiguous reference with `gh pr view <number>` and fall back to `gh issue view <number>`.

## Skill operations

- **Publish to the issue tracker:** Create a GitHub issue.
- **Fetch the relevant ticket:** Run `gh issue view <number> --comments`.

## Wayfinding operations

Used by `/wayfinder`. A map is a single issue with child issues as tickets.

- **Map:** An issue labeled `wayfinder:map`, containing Notes, Decisions-so-far, and Fog.
- **Child ticket:** Link the issue to the map using GitHub sub-issues. If unavailable, add a task-list link in the map and `Part of #<map>` in the child. Use `wayfinder:<type>` labels (`research`, `prototype`, `grilling`, or `task`). Assign claimed tickets to the driving developer.
- **Blocking:** Prefer native issue dependencies. Add a blocker using `gh api --method POST repos/junnengsoo/ai-native-rmm/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`. Obtain the numeric database ID through `gh api repos/junnengsoo/ai-native-rmm/issues/<number> --jq .id`; it is not the issue number or node ID. If dependencies are unavailable, use a `Blocked by: #<number>` line in the child.
- **Frontier:** Read the map's open children and exclude tickets with open blockers or an assignee. Select the first remaining ticket in map order. Native `issue_dependencies_summary.blocked_by` counts open blockers.
- **Claim:** `gh issue edit <number> --add-assignee @me`.
- **Resolve:** Comment with the outcome, close the ticket, and append a concise result and link to the map's Decisions-so-far.
