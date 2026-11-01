# Keep workflow inventories in the requested Git repository

Tested base: `599891304e83e853ec723dc1417550bef4e1c074`.

`scripts/check_workflow_inputs.py --repo TARGET --base HEAD^ --head HEAD`
can report success with zero checked references when invoked from a Git hook
belonging to another repository. Its Git subprocesses use `-C TARGET`, but an
inherited `GIT_DIR` still selects the enclosing repository's history. The stated
head and baseline consequently refer to another repository.

The reproduction invokes a real local pre-commit hook using Git's explicit
`--git-dir`/`--work-tree` route. The requested repository contains the unchanged
retained `.github/workflows/search-dependency.yml` and its actual script. After
committing removal of that private script copy, a direct check finds four new
missing references and exits 1. The same command inside the routed hook checks
zero references and exits 0. Neither the workflow commands nor the search
script are executed.

## Correction and controls

The existing Git helper removes the repository-local variables reported by
`git rev-parse --local-env-vars` from its child environment before each `git -C`
command. The caller's environment and repository remain unchanged. This follows
[Git's documented foreign-repository hook guidance](https://git-scm.com/docs/githooks#_description)
and the existing repository fixes for
[bisection #3507](https://github.com/lalalune/pumpfun-source/pull/3507),
[minimizer stages #3564](https://github.com/lalalune/pumpfun-source/pull/3564), and
[composition/source receipts #3712](https://github.com/lalalune/pumpfun-source/pull/3712).
It changes the workflow checker's repository selection, not shell parsing or
missing-input classification.

The actual probe covers working-tree and committed views with both `--base`
and `--all`, through direct execution, an ordinary hook, and an explicitly routed
hook. Each of those 12 combinations runs before and after the private deletion:
24 real checker invocations per revision. Before the fix, four routed committed
rows incorrectly check zero inputs. Afterward all check four inputs; both missing
committed cases now exit 1. The other 20 controls retain identical complete
reports and exit statuses. Ordinary hooks and working-tree checks were already
correct in this fixture and remain so. Retained repository input bytes stay
unchanged. Results are recorded in [results.json](results.json).

## Reproduce

Use Git and the repository's pinned Python requirements. No SDK is required.

```sh
python -B research/workflow-git-context-20261101/probe.py --repo . \
  --revision 599891304e83e853ec723dc1417550bef4e1c074 --output work/workflow-git-before.json
python -B research/workflow-git-context-20261101/probe.py --repo . \
  --output work/workflow-git-after.json
python -B scripts/test_workflow_git_context.py
python -B -m unittest discover -s scripts -p 'test_workflow*.py'
```

Use fresh proof output paths. The base command reads the complete historical
checker from Git; the fixed command reads current bytes. The probe creates two
temporary repositories and local commits, installs its own small hook, records
only the hook's repository-routing variables, and removes those repositories.
It does not change the user's Git configuration, branches or index. The regression
is included in `verify.yml`.

This is a static workflow-inventory correction. It does not execute CI jobs,
compiler builds, dependency searches, programs or VMs, and establishes no build
or runtime-equivalence result. Existing missing-input debt and uninspected
dynamic commands remain explicit.
