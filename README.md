# frama-c-mcp

An [MCP](https://modelcontextprotocol.io/) server that gives an AI agent
[Frama-C](https://frama-c.com/): EVA abstract interpretation, WP deductive
proof, ACSL annotation injection, and isolated sandboxes for trying annotations
out.

The server is designed to be driven by an agent rather than by a person. An MCP
client spawns it and speaks to it over stdio, so there is no command for a human
to type. It is built around an iterative loop: propose an annotation, prove it,
read why the goal did not close, then revise. The session state follows from
that loop rather than from shell use, since one project stays loaded across
calls, sandboxes are addressed by name, and proof receipts compare only within
a run.

Wire it into Claude Code, Claude Desktop, or any MCP client, then prompt in
English. See [Connect an agent](#connect-an-agent) and
[Prompt patterns](#prompt-patterns). A `check` subcommand exists for CI and is
the only part intended to be run by hand.

## Architecture

```text
┌──────────┐  MCP over stdio   ┌────────────────┐  Unix socket  ┌─────────────────┐
│ AI agent │◄─────────────────►│ frama-c-mcp    │◄─────────────►│ Frama-C main    │
└──────────┘                   │ Rust server    │               │ + ast-utils     │
                               └───────┬────────┘               └─────────────────┘
                                       │ Unix socket per sandbox
                                       ▼
                               ┌──────────────────┐
                               │ Frama-C sandbox  │
                               │ + ast-utils      │
                               │  per experiment  │
                               └──────────────────┘
```

The server has two required components:

- Rust MCP server: exposes the tools over MCP stdio, translates requests into
  Frama-C's server protocol, and lazily starts the main Frama-C process on the
  first project operation.
- `ast-utils` Frama-C plugin: provides the custom requests for AST access,
  dependency extraction, ACSL injection, sandboxing, and WP configuration.
  Build and install it in the same opam switch as Frama-C.

`create_sandbox` extracts a function together with its type, callee, and global
dependencies into a temporary C file, then starts a separate Frama-C process.
An agent can iterate on annotations there without mutating the main project;
verified sandbox annotations are merged back explicitly.

### Session model

The server holds one project: `reload_project` or the first `check` loads it,
and later calls operate on that AST. Sandboxes are separate processes,
addressed as `experiment_id:function`.

The preprocessor surface is `include_paths`, `defines`, `force_includes`, and
`machdep`, applied in that order. Each value is written without its compiler
flag.

## Quick start

Build the Frama-C plugin, build and install the server, then point an MCP client
at it. The plugin and Frama-C must be installed in the same opam switch.

### Prerequisites

- Frama-C 32.1 or newer (CI exercises 33.0)
- OCaml 4.14.2, opam, and dune >= 3.0
- Rust 2021 toolchain
- WP provers: Alt-Ergo, with Z3 and CVC5 optional

### Build

```bash
# Name the switch that holds Frama-C. A bare `opam env` picks up whichever
# switch happens to be active, which is the failure described below.
eval $(opam env --switch=frama-c-33 --set-switch)

cd ast-utils
dune build && dune install
cd ..

cargo build --release
```

`dune` resolves Frama-C through the opam switch, not through `PATH`. Setting
only `PATH` builds the plugin against whichever switch is active and fails with
unbound modules in files you did not touch.

After changing the plugin, run `dune clean && dune build && dune install`.
Incremental builds may not relink the installed `.cmxs`.

### Prebuilt binaries

Every push to `main` that passes the full test lane replaces a rolling
[`latest` release][latest], so the download link never moves:

[latest]: https://github.com/sysprog21/frama-c-mcp/releases/tag/latest

```bash
# Linux x86_64
curl -sSfL -o frama-c-mcp.tar.gz \
    https://github.com/sysprog21/frama-c-mcp/releases/download/latest/frama-c-mcp-x86_64-unknown-linux-gnu.tar.gz

# macOS arm64
curl -sSfL -o frama-c-mcp.tar.gz \
    https://github.com/sysprog21/frama-c-mcp/releases/download/latest/frama-c-mcp-aarch64-apple-darwin.tar.gz

tar xzf frama-c-mcp.tar.gz
mkdir -p ~/.local/bin
install -m 755 frama-c-mcp ~/.local/bin/
```

There is no Windows build: the transport speaks Unix sockets and Frama-C does
not target Windows either.

The tarball holds the Rust MCP server and nothing else. It is half the product:
most tools return `invalid` without the `ast-utils` plugin, and that plugin
still has to be built from source in the opam switch holding your Frama-C,
because a `.cmxs` is tied to the exact OCaml and Frama-C that compiled it. So a
download is `dune build && dune install` under [Build](#build) plus this binary
in place of `cargo build --release`, not a way to skip the switch.

### Install

```bash
make install                     # to ~/.local/bin
make install BINDIR=/usr/local/bin
```

`make install` builds and installs both the Rust binary and the `ast-utils`
plugin. It runs `dune` through `opam exec`, so the plugin lands in the active
switch; select the switch holding Frama-C before running it. The install fails
if the resulting plugin is not loadable by that switch's `frama-c`. `BINDIR`
must be writable without `sudo`, which would discard the opam environment.

It finishes by pointing whichever agents are installed at the binary it just
placed: Claude Code through `claude mcp add`, and codex by adding an
`[mcp_servers.frama-c]` section to `~/.codex/config.toml` when that file exists
and has no such section. An agent that is not installed is skipped rather than
failing the install, and an existing codex section is left alone rather than
rewritten. Run `make register` on its own to redo just that step.

Use it instead of copying over an existing binary. On macOS, replacing an
executed binary in place can leave a stale code-signature blob and cause every
subsequent execution to fail with `SIGKILL (Code Signature Invalid)`. The
install goes through a temporary file, ad-hoc signs it, runs it once, and then
renames it into place.

The other targets: `make` builds the release binary, `make indent` runs `shfmt`
over the shell scripts and `commentflow` over the sources that carry comments,
and `make clean` removes `target/` and the plugin's `_build/`.

### Connect an agent

Declare the server in `.mcp.json` for a project, or in
`claude_desktop_config.json` for Claude Desktop:

```json
{
  "mcpServers": {
    "frama-c": {
      "command": "/path/to/frama-c-mcp",
      "args": ["--frama-c", "/path/to/frama-c"]
    }
  }
}
```

The client spawns that command and speaks MCP over its stdin and stdout, so
there is nothing to start beforehand; run the binary from a terminal and it
simply waits on stdin. Frama-C itself is spawned lazily, on the agent's first
project operation, which is why a misconfigured `--frama-c` surfaces on the
first `check` rather than at startup.

The arguments the client passes:

| Flag | Default | Description |
|------|---------|-------------|
| `--frama-c` | `frama-c` | Path to the Frama-C binary |
| `--max-sandboxes` | `32` | Maximum concurrent sandbox Frama-C processes |
| `--socket` | none | Deprecated; ignored when set because sockets are generated per process |

Once connected, drive it in English rather than by naming tools; the agent picks
the calls. [Prompt patterns](#prompt-patterns) is the table of what to say.

### CLI escape hatch for CI

The `check` subcommand runs the same code path as the `check` tool and prints
its JSON payload, so a pipeline can use the server without an agent and without
speaking MCP. It is the one entry point meant to be typed:

```bash
./target/release/frama-c-mcp check src/foo.c --function foo \
    -I include -D NDEBUG --force-include builtins.h --require-complete
```

`--require-complete` exits non-zero when `incomplete[]` is non-empty, which is
the difference between "nothing was reported" and "everything was checked".
The rest of the tool surface has no CLI form, on purpose: it is stateful across
calls and there is no session to hold that state in from a shell.

### Prompt patterns

Say what evidence you want back, and hand over what the server cannot infer:
the include paths, the defines, and which function is the target. The left
column is what you type; the middle is what a well-behaved agent does with it;
the right is the trap that makes the obvious call the wrong one.

| Say | Call | Trap |
|-----|------|------|
| *"Check foo.c for runtime errors and prove its contracts; it builds with `-Iinclude -DNDEBUG`. Target `bar`. Tell me what was left unchecked."* | `check({files:["foo.c"], function:"bar", include_paths:["include"], defines:["NDEBUG"]})` | `check` reloads the project, so it needs the real build flags. Without them Frama-C parses a different program, or none |
| *"Give me every goal and alarm, not the first few."* | `check({..., detail:"full"})` | The default is `summary`. `full` runs to hundreds of kilobytes on a real file, and `verdict` and `incomplete[]` are computed from the complete data either way |
| *"Frama-C cannot parse this. Reproduce the compiler configuration; do not delete code to make it parse."* | `reload_project({files, include_paths, defines, force_includes, machdep})` | `force_includes` supplies declarations Frama-C lacks. A define that erases the call site parses, and then proves the wrong program |
| *"What can `n` hold at foo.c:42?"* | `context({want:["marker_at"], file:"foo.c", line:42})` → `context({want:["eva_value"], marker})` | Needs EVA to have run. Which marker comes back follows the position, not the intent: a declaration line answers with the variable's `#v`, so read `marker_kind` before passing it on |
| *"Why might line 42 overflow? Show the values, the callers, and the annotations in force."* | `get_wp_goals({want:["alarms"]})` → `get_wp_goals({want:["investigation"], marker:"#p10", depth:"deep"})` | `investigation` takes the property marker off the alarm row. `depth` defaults to `normal`, which omits the annotations |
| *"List everything this run did not establish for `bar`."* | `get_wp_goals({want:["alarms","goals"], function:"bar", status:"unproved"})` | `unproved` is every status other than valid. A status that is neither a Frama-C name nor one this run produced is an error, so a typo cannot read as proved |
| *"Why is that goal not proved? Show the hypotheses WP had."* | `get_wp_goals({want:["vc"], function:"bar"})` | The sequent is per function, and `vc` requires `function` |
| *"Show me `bar` as Frama-C sees it, with my contract read back."* | `context({want:["contract_context","loop_effects"], function:"bar"})` | The read-back route for annotations you injected: type-checked, macros expanded, as WP will use them |
| *"I have no annotations yet. What does the code itself determine?"* | `propose_annotations({function:"bar"})` → `inject_all_annotations({function:"bar", dry_run:true, annotations:[...]})` | Frames only, each already type-checked against the AST. The predicates that make a proof go through are under `not_proposed`, named rather than guessed |
| *"Type-check this ACSL against the real AST but change nothing."* | `inject_all_annotations({function:"bar", dry_run:true, annotations:[...]})` | Invariants, asserts, `assigns`, ghost code and lemmas all inject on main. `requires` and `ensures` are the exception, refused there whatever `dry_run` says |
| *"Try requiring `n >= 0` without touching the main project."* | `create_sandbox({function:"bar", experiment_id:"exp42"})` → `inject_all_annotations({sandbox_name:"exp42:bar", annotations:[...]})` → `run_wp({functions:["exp42:bar"]})` | Contracts belong to whoever reviews the source, so main refuses them and the sandbox is where one gets tried. Merge back explicitly |
| *"Prove `bar` now, and tell me what my last change actually bought."* | `run_wp({functions:["bar"], cache:"None"})` → `get_wp_goals({since:"<earlier receipt sha256>"})` | `-wp-cache` defaults to `update`, so a valid verdict may be replayed rather than computed. `since` only names receipts from this session |
| *"Prove the ready functions, one bounded batch at a time, then record what `bar` assumed."* | `run_wp({functions:["bar"], retry_unproved:true})` → `store_function_conclusion({function:"bar", status:"verified", proof_receipt, wp_summary})` → `list({kind:"conclusions", function:"bar"})` | WP's budget is per call, so an oversized batch returns nothing at all. `verified` is refused unless the receipt's goals are all valid and their count matches `wp_summary` |
| *"Verify the file bottom up and tell me what to do next."* | `verify_program_step({lock_project:false})` | The lock defaults on and blocks every later `run_wp` on main |
| *"Does it actually break when it runs?"* | `run_e_acsl({use_current_ast:true, args:[...]})` | Compiles and executes the code with your privileges; trusted source only. Without `use_current_ast` it runs the files on disk, which do not carry this session's annotations |
| *"Write out the annotated source."* | `context({want:["source"], output:"out/annotated.c"})` | Whole program, every contract and generated RTE assert. The path must stay inside the working directory |
| *"Why did that tool fail?"* | `self_check({canary:true})` | Versions, provers, which requests answer. `canary` adds about 30s proving the backend still tells a bundled bug from its fix |

The WP memory model is process state. Frama-C takes some changes within one
process and not others, so a change that aborts reports what it changed from
and points at `reload_project`.

Ask for a verdict rather than a summary. `check` reports `proved` only when
`incomplete[]` is empty, so "no alarms were reported" and "everything was
checked" stay distinguishable. See [docs/agent-playbook.md](docs/agent-playbook.md)
for the shortest reliable call order for each workflow, and
[docs/writing-acsl.md](docs/writing-acsl.md) for what to write when a goal will
not close, keyed to the finding categories and `incomplete[]` codes.

## Tools

The server exposes the following tool groups:

| Domain | Tools | Purpose |
|--------|-------|---------|
| Project | `reload_project`, `list`, `context`, `self_check`, `parse_surface` | Load source, inspect declarations, navigate call relationships, report server capabilities, and measure how much of a file set Frama-C can parse at all |
| EVA/WP | `check`, `run_wp`, `get_wp_goals`, `proof_coverage`, `run_e_acsl` | Run verification, read its conclusions, report stored proof coverage, and execute runtime counterexamples |
| Annotations | `inject_all_annotations`, `propose_annotations` | Dry-run validate and inject ACSL annotations, and propose the frame conditions the code determines |
| Sandbox | `create_sandbox`, `delete_sandbox` | Isolate annotation experiments |
| Orchestration | `verify_program_step` | Run bottom-up verification steps |
| State | `store_function_conclusion` | Persist verification conclusions |

> `run_e_acsl` compiles the loaded source and runs the resulting binary with
> your privileges. Every other tool only analyzes. Do not point it at C source
> you do not trust, and note that an agent reading untrusted source can be
> steered into calling it.

`proof_coverage {}` measures defined loaded functions against their stored
conclusions. Use `proof_coverage {verify_profile: "target", detail: "full"}`
to measure the function set declared by a build-system target. It splits its
valid WP goals into `fresh_valid` and `cached_valid`, the latter being verdicts
WP replayed from its cache rather than computed on the run that produced the
receipt, and it counts a receipt shared by several functions once.
It proves only the obligations generated by the ACSL/RTE/WP configuration that
produced those receipts; omitted requirements are not coverage. It reads WP
only, so a `complete` verdict is a statement about proof obligations rather
than about every analysis this server can run, and it does not inspect whether
a covered function declares an `assigns` clause, because the `specs` a
conclusion carries are supplied by the caller and may be absent for a function
that has one.

The goal denominator holds every in-scope receipt, not only the ones behind a
covered function, so obligations that were attempted and did not discharge are
counted rather than dropped. Storing a verified conclusion already requires
every goal in its receipt to be valid, so a denominator drawn from covered
functions alone could only ever read 100 percent.

A function is uncovered, with the reason named in its row, whenever anything at
all disqualifies it: no stored conclusion (`missing_conclusion`), a stored
conclusion that is not verified, which is reported under its own status name,
or a verified one with no receipt (`missing_proof_receipt`). Beyond those, when
its conclusion belongs to another `verify_profile` (`different_verify_profile`)
or no longer fits a re-registered one (`profile_evidence_mismatch`), when the
receipt was produced over a different file set or under different preprocessor
settings (`different_project`, which is what makes it safe to keep conclusions
across a `reload_project` that switches projects), when its callee contracts or
proof environment have gone stale, when a source file its
receipt hashed has since changed on disk (`stale_source`), when the receipt does
not name this function among the ones WP ran over
(`receipt_does_not_prove_function`), when the run was restricted by `prop` and so
attempted only part of the function (`proved_under_a_goal_filter`), when a
`verify_profile` names a function this project does not define, whether it is
absent or only declared (`not_defined_in_project`), or when a callee inside the
measured set is itself uncovered (`unverified_callee`, propagated through the
call chain).

`docs/agent-playbook.md` carries the full table of reasons and what each one
asks you to do about it.

A file the receipt named that cannot be read now, such as one from a deleted
sandbox, a path that is not a regular file, or a bare relative name with no
directory on it, which would otherwise resolve against the server's working
directory, is listed under `unchecked_sources` rather than judged either way. A
relative path that keeps its directory is resolved, since that is the path
`reload_project` was given and the one Frama-C itself was launched with.

A receipt records the whole loaded file set rather than the one file its
function lives in, so editing any loaded source marks every stored conclusion
`stale_source`, not only the conclusions about that file. That is the honest
reading, since WP proves a function against the AST of all loaded files and a
receipt carries no per-function source attribution, but expect one edit to turn
the whole report red. The edited paths are listed once for the whole
report under `changed_sources`, as the unreadable ones are under
`unchecked_sources`, with each row carrying only its own counts.

A function this project declares without defining sits outside both
denominators, named under `scope.declared_not_defined`, unless a
`verify_profile` names it as a target. Then it stays in the denominator as
`not_defined_in_project`, because a target does not stop declaring a function
when the file defining it was not loaded, and excusing it would let a profile
report `complete` on whichever of its functions happened to be present.

The rest of this section covers the parameters whose behavior is not obvious
from the tool schema.

### Input constraints

Identifiers that become directory names, `store_function_conclusion {function}`
and `create_sandbox {experiment_id}`, are restricted to `[A-Za-z0-9_-]` so they
cannot escape `.frama-c-mcp/` or the sandbox root.

`context {want: ["source"], output}` is the only tool that writes a file the
caller names, and the path must resolve inside the working directory. An
absolute path elsewhere, a `..` that climbs out, and a symlink inside the tree
that points out of it are all refused.

`run_e_acsl {tool}` names the E-ACSL wrapper, not an arbitrary executable: it
must be `e-acsl-gcc` or `e-acsl-gcc.sh`, resolved through PATH. Both names
exist because installs differ.

### Proving what the build system proves

This server's WP defaults are not what a project's proof targets use. A goal
discharged under `Typed+nocast` says nothing about a target that declares
`caveat`, so evidence produced under the wrong model is not evidence about that
target at all.

Register what the build system says, and name it on the same call or a later
one. Registration happens before the load, so one call can both hand over the
set and load under one of them:

```
reload_project {verify_profiles: <json>, verify_profiles_source: "make print-verify-profiles",
                verify_profile: "elf"}   # registers, then loads elf's sources and cpp flags
run_wp         {verify_profile: "elf"}   # its model, provers and timeout
check          {verify_profile: "elf"}   # both
reload_project {verify_profile: "gva"}   # a later target, already registered
```

Registering without naming a profile and without `files` is not a load, and a
fresh session answers it with "no project loaded" because there is nothing to
reparse. A malformed set is refused before anything is replaced; a set that
parses is registered even if the load that follows it fails.

A profile that is only used to load may carry `sources`, `machdep`,
`include_paths`, `defines`, `force_includes` and `reproduce`. One you intend to
prove under additionally needs `functions`, `model`, `provers` and
`timeout_seconds`, and a run naming it is refused unless all four are there:
without the proof settings it would fall back to this server's defaults and
report the target's name over them, and without a function set there is nothing
for the coverage check to compare against. Emit the JSON from the build system that defines the targets
rather than writing it by hand, so it cannot drift from the command that
decides. An unknown key is refused rather than ignored. A profile
whose model key is misspelled as `models` would otherwise register with no
model at all, and the next run would prove under this server's default and
report it as that target's evidence, which is the failure profiles exist to
prevent. Naming a profile nobody registered is refused too, rather than
falling back to the default.

Passing `model`, `prover`, `provers` or `timeout` alongside `verify_profile` is
refused rather than allowed to win. A run labelled as a target's evidence has
to be the target's settings, and letting an override through produced exactly
the mislabelling profiles exist to prevent: proving under one model while the
response named another. Omit `verify_profile` to deviate on purpose.
Evidence profiles must declare all three proof settings: `model`, non-empty
`provers`, and `timeout_seconds`; an incomplete profile may be registered for
loading, but cannot label a proof result. Sandboxes are likewise excluded:
their generated source is not the registered build target.

The load settings behave the same way by a different route. `reload_project`
lets an explicit `machdep` or include path override the profile, and a later
profiled run then compares what was loaded against what the profile declares
and refuses if they differ, so a deviating load cannot be reported as that
target's evidence either.

`reproduce` is the command that actually decides. This server is an
accelerator: goals discharging here are progress, and the project's own command
is the verdict.

`reload_project {include_paths, defines, force_includes}` become preprocessor
flags, and Frama-C hands those to a shell (its `-cpp-extra-args` is "unsafe in
sandbox mode"). Each entry is therefore restricted to `[A-Za-z0-9_./+-]`, plus
`=` for defines, with no leading dash, so a value cannot carry a command
substitution or the `${IFS}` space trick into that shell. A define needing a
shell-active character (a parenthesized expression, a quoted string) is refused;
`force_includes` a header that spells it instead.

### `list` and `run_wp`

`list` accepts a `kind` of `files`, `functions`, `globals`, `declarations`,
`sandboxes`, or `conclusions`. For conclusions, `status` filters the summaries
and `function` returns one full conclusion.

`run_wp` accepts `smoke: true` together with `provers` to run isolated CLI
smoke tests.

### `self_check`

`self_check` reports `tool_surface`: the tool count, the byte size of the
`tools/list` result that is resent on every agent turn, and the three heaviest
tools. Computed from the running server, so it cannot be quoted stale.

It parses the `frama-c -version` banner rather than only checking that the
command exited zero. `frama_c.major`, `frama_c.minor`, `frama_c.supported`
and `frama_c.minimum_version` report whether the installed version meets
this server's minimum supported version, and `frama_c.unsupported_reason`
names the mismatch when it does not. The minimum carries a minor because the
floor has one: 32.0 is a real release the plugin does not build against. An
older Frama-C exits zero like any other, and the failure it causes lands
somewhere with no version in it: a plugin that will not load, or a request
answered `invalid`.
`capabilities.known_frama_c_version_limitations` repeats the reason and is
derived from the same probe, so it cannot go stale against the version actually
installed.

`self_check` also accepts `canary: true`. The request probes report which
requests answer; they cannot report whether EVA and WP still catch anything, and
an install where every request answers and no alarm is ever raised passes them
while being useless. The canary runs `tests/fixtures/abs-int-buggy.c` and its
fixed twin through `check` and judges the reason rather than the verdict: the
buggy file must report an `ALARM_NOT_VALID` naming `signed_overflow`, and the
fixed one must be `proved` with an empty `incomplete[]`. The pair is the test,
not either half: with WP dead the buggy file still reports its alarm from EVA,
and it is the fixed file that catches it.

The canary is off by default because it is two full EVA and WP runs, about 30
seconds, and it performs them in a separate Frama-C process with its own state.
`check` reloads whatever project it runs against, so a canary sharing the
session would discard the loaded AST and every annotation injected into it.

### `get_wp_goals`

`get_wp_goals` reads the one property table every analysis writes to, selected by
a `want` array in the idiom `context` uses: `goals` (the default, WP proof
goals, filtered by `function` and `status`, or diffed against an earlier run
with `since`), `alarms` (EVA alarms, filtered by `function`, `alarm_kind` or
`status`), `counts` (property counts plus EVA and WP state), `vc` (one
function's verification condition as a sequent), and `investigation` (one
property joined to its value ranges, callers, and annotations, keyed on
`marker` and taking `depth`).

Each of `alarm_kind`, `marker`/`depth`/`callstack`, and `since` belongs to one
want and is rejected without it, so a call cannot quietly get an answer that
ignored what it passed. `status` is the one parameter two wants read, and it
means the same thing on both: `unproved` selects everything not valid, whether
the rows are goals or alarms.

### `inject_all_annotations`

`inject_all_annotations` takes every clause in one `annotations` array, each entry
tagged with a `kind` of global, behavior, requires, ensures, assigns, assert,
loop, complete_behaviors, disjoint_behaviors, terminates, exits, or decreases.
Generated clauses get readable labels by default, so WP goals trace back to the
entry that produced them, and diagnostics name the failing `annotations[i]`.

The same array carries ghost code: `ghost_global`, `ghost_formal`,
`ghost_lemma_function`, `ghost_loop`, and `ghost_stmt`, each with its fields on
the entry rather than nested under a `spec`. Ghost entries
are applied before clause entries in one call, because a ghost formal changes
the signature a `requires` refers to, and the clause plan is skipped entirely
if any ghost fails. Each one answers under `ghosts[]`, which carries the
plug-in's payload verbatim: `vid` for a ghost global, `loop_sid` and `sids` for
a ghost loop.

`ghost_global` and `ghost_lemma_function` belong to a project rather than to a
function, so `function` there only selects main or which sandbox.

Under `dry_run`, ghost entries are checked for their kind's fields and a
resolvable target but not inserted, and the clauses are then validated against
an AST that does not carry them. The response says so with
`ghosts_not_applied`, because a `requires` naming a proposed ghost formal reads
as invalid there and may not be.

### `context`

`context` accepts `want` values for `function_ast`, `cil_context`,
`contract_context`, `logic_deps`, `property_context`, `rte_obligations`,
`current_annotations`, `write_effects`, `loop_effects`, `messages`, `source`,
`symbol`, `marker_at`, `eva_value`, `callgraph`, `callers`, and `call_chain`.

`marker_at` and `eva_value` are the two halves of "what does this variable hold
here": `marker_at` turns `{file, line, column?}` into a statement marker, and
`eva_value` reads EVA's range at it. `eva_value` was once its own tool; it lives
here because `get_wp_goals` reads the property table, and a statement marker is
not in that table.

The navigation wants divide as follows. `symbol` takes the identifier in
`function` and answers for a global variable too. `callgraph` and `call_chain`
read the syntactic call graph, while `callers` returns EVA caller data and so
requires `check` to have run first. `callgraph` is whole-program and rejects
`function` when it is the only want.

## Verdicts and evidence

### Verdicts

Silence is not a proof, so results carry both what was found and what was
actually checked.

`check` returns a `verdict` of `proved` only when `incomplete[]` is empty. Any
step that did not run, timed out, or was skipped becomes an `incomplete[]`
entry, and the verdict falls back to `incomplete` even when nothing failed.

Every entry carries a `code`, and only the code is frozen; see
[docs/architecture.md](docs/architecture.md) for the
payload contract and the change rule. The full set:

<!-- incomplete-codes -->

| Code | Meaning |
|------|---------|
| `RTE_DISABLED` | Ran without RTE, so no alarms does not exclude runtime errors |
| `EVA_NOT_RUN` | EVA did not complete, so `eva_alarms` proves nothing |
| `WP_NOT_RUN` | WP did not complete, so `wp_goals` proves nothing |
| `WP_STILL_RUNNING` | WP was working when its goals were read, so a goal may be missing entirely |
| `ALARM_NOT_VALID` | EVA left a generated runtime-error alarm undischarged |
| `GOAL_NOT_VALID` | WP has a non-valid goal |
| `PROVER_TIMEOUT` | A prover timed out on a goal |
| `PROPERTY_DEAD` | EVA proved the code unreachable, so nothing proved about it constrains a run |
| `PROPERTY_DISPROVED` | Frama-C disproved a property and WP emits no goal for one that already has a status |
| `PROPERTY_INCONSISTENT` | Frama-C consolidated contradictory statuses, so the verdict cannot be trusted |
| `LEMMA_NOT_PROVED` | WP assumed a lemma everywhere without discharging it |
| `ASSUMED_VALID` | Recorded valid by external assumption, an `axiom`, not by proof |
| `ASSUMED_CALLEE_CONTRACT` | A callee's contract was taken on faith, with no finite `assigns` |
| `UNCONSTRAINED_ASSIGNS` | The contract lists a location in `assigns` that no postcondition mentions, so proving the function says nothing about the value written there |
| `RESULT_UNCONSTRAINED` | The contract bounds `\result` to a small range but never ties some of those values to the inputs, so proving it does not pin down what the function returns |
| `UNPROVED_ASSUMPTION` | An assertion or postcondition WP could not prove, which it still hands to later goals as a hypothesis |
| `VALID_UNDER_HYP` | WP proved the goal, but Frama-C consolidated its property as valid only under hypotheses nothing has established |
| `EVA_NOT_REQUESTED` | `want` excluded EVA, so nothing here excludes the alarms it finds |
| `WP_NOT_REQUESTED` | `want` excluded WP, so nothing here is a proof |
| `WP_BACKEND_ANOMALY` | Why3 aborted, so the FAILED goals of this run were never judged by a prover |
| `AST_ASM_CLOBBER` | Frama-C assumed inline assembly has no effects beyond its operands, so the analyzed statement is weaker than the compiled one |
| `AST_UNKNOWN_ATTRIBUTE` | Frama-C ignored an unknown attribute, so the analyzed declaration differs from the source |
| `AST_UNCLASSIFIED_WARNING` | Frama-C emitted parse warnings in categories this server has not classified, so their effect on the analyzed program is unknown |
| `AST_PARSE_DIAGNOSTICS_UNAVAILABLE` | This server has no record of what the front end dropped, so nothing says the analyzed program is the compiled one |

Treat the set as additive: codes are added as gaps are found, and three were
added in one day. Branch on the ones you handle and surface the rest rather
than assuming an unknown code is benign.

The four `AST_*` codes are about the parse and not the verdict: they say the
program that was analyzed is not the program that would be compiled, or that
nothing checked. The two soundness codes carry `count`, `count_unit` (clobber
sites, or distinct attribute names, since Frama-C announces an unknown
attribute once per name for the life of the process), and a capped `locations`
sample with `locations_omitted`. `AST_UNCLASSIFIED_WARNING` is a single entry
for every category nobody has classified, carrying a `categories` object that
maps each category to that same record; it has no `count` of its own. The same
numbers are on `reload_project` under `ast_reload_health.parse_diagnostics`.

`AST_PARSE_DIAGNOSTICS_UNAVAILABLE` is the fourth and carries no counts at all,
only a `detail` naming what went missing. It replaces the other three rather
than joining them, because a record that could not be taken has nothing to say
about any category.

How long it lasts depends on which failure it names, and the `detail` is what
says which. Four of them cost the process. Three are properties of its spawn:
Frama-C had written nothing to its log when the socket appeared, the boot parse
could not be measured in it (`cannot measure the boot parse in ...`), or the
sources moved while Frama-C was starting. The fourth is the same race one
reload later, when the sources move while Frama-C is rebuilding the AST in
place. None can be recovered by looking again, since the boundary they would
need was a property of an instant that has passed, so the server marks that
Frama-C unusable: the next `reload_project` replaces it whether or not the file
set changed, and the code goes with it.

The one that does not is the spawn log being unreadable when a later call goes
to read it (`cannot read the Frama-C stdout log at ...`). That one is neither
cached nor fatal: the same process answers the code for as long as its log
stays unreadable, and reports counts again as soon as it does not. The two
unreadable cases are worded apart on purpose, because that wording is the only
thing telling a caller which of the two it is holding.

None of them carries a completeness caveat, because there is nothing for one to
say. The record is always the boot parse of the Frama-C process that answered,
and a boot parse is complete in both directions: Frama-C suppresses a warn-once
category for the rest of the process, so no later parse could re-announce one,
and the log is process-wide, so a call running alongside a later parse would
write into its window. Nothing can be in flight before the socket exists.

Keeping that true costs a respawn. `reload_project` reuses the running Frama-C
only when the file set is byte-identical to the one that process booted on and
carries no preprocessor directive; anything else, including a source with an
`#include`, gets a new process. Reload rebuilds the AST from source either way,
so what this costs is process lifetime rather than anything you were holding.
The payoff is that a zero means the front end dropped nothing, that two checks
in one session report the same codes, and that `proof_receipt.sha256` therefore
does not move between them.

When the spawn log cannot be read at all, `parse_diagnostics` carries an
`unavailable` string and no categories, rather than the zeros that would read
as "nothing was dropped".

`check` also returns `messages[]`, Frama-C's own errors and warnings from the
run, each with its plugin and source location. A generated `assigns` for an
uncontracted callee is announced there and nowhere else, and it weakens every
proof above it.

`check`, `run_wp`, and stored conclusions carry a `proof_receipt`: the
source-file hash, an `ast_digest`, the
Frama-C and prover environment, the effective EVA and WP configurations,
per-goal statuses, and a sha256 over all of it. Two runs are comparable exactly
when their receipts match.

What it reports about `incomplete[]` is a digest, `{count, codes, sha256}`, not
the array. The array is already one key away at the payload's top level, and
embedding it a second time measured 509 KB of a 1.4 MB response on a 1,144-line
file, almost all of it repeated `guidance` and `source_location` text. The hash
is over the array as it stands, so any change to any entry still moves the
receipt and the comparison guarantee is unchanged.

The EVA half of that is read back off the Frama-C process, not copied from the
request, and the two can disagree on purpose. EVA's settings outlive one call: a
profile that leaves `precision`, `slevel` or `ilevel` unset issues no setter, so
whatever an earlier call wrote is still in force, and `-eva-precision` is a
meta-option that moves a dozen further parameters when it is set. So `check
{profile: "deep"}` followed by `check {profile: "default"}` reports an empty
`eva.frama_c_options`, because this run set nothing, beside a
`proof_receipt.eva` still holding the deep values, because that is what the
analysis ran with. Read `frama_c_options` as what this call asked for and
`proof_receipt.eva` as what it got; where they differ, the receipt is the one
describing the run. `self_check` writes to the same parameters, so a self-check
shows up in every later receipt the same way.

`ast_digest` is a hash of the normalised AST, and it answers a question the
source-file hash cannot: what was actually analysed. Different `defines`,
include paths, or machdep over identical files produce different digests; and,
more usefully, `defines` that select nothing different produce the *same*
digest. That second case is the dangerous one, because it reads as
configuration coverage that was never there. A real instance: a project's
verify target ran a default pass and a `-DTLSF_NO_INTRINSICS` pass, reported
both green, and analysed identical code both times, because Frama-C does not
predefine `__GNUC__` and the source selected its portable fallbacks either way.
Equal goal counts cannot show that. Equal digests can. `null` means the digest
could not be established, so two nulls never count as agreement: the receipt
carries a random `ast_digest_unavailable_nonce` in that case, which makes two
such receipts differ by construction. `ast_digest_unavailable_reason` says why, because the
nonce that enforces the non-equality would otherwise erase the distinction. It
is `no_client` when nothing is attached, `reload_failed` when the input did not
parse and the resident AST is a previous project's, `request_answered_empty`
when the print came back with nothing, and `request_failed: <message>`
otherwise. That last one covers both an absent `ast-utils` and a print that
outran its budget: the client reports the two the same way, and separating them
would mean parsing the error text. The isolated CLI retry is not one of those
cases and gets the same `unavailable_isolated_cli_retry` marker the contracts
field already uses: it proves the files on disk in another process, so the live
AST does not describe it.

### Checking several configurations at once

`check {variants: [...]}` runs the same check over a list of configurations and
reports them together. Each entry may carry `defines`, `machdep`, `model` and a
`label`, overriding the top-level value; `files` and `function` are shared.

This exists because the questions worth asking about a real project are
comparative: portable path against compiler intrinsics, 32-bit against 64-bit,
one memory model against another. Answering them one `check` at a time makes
the comparison the caller's job, and the comparison is where the mistakes are.

The result carries `ast_digest` per variant and reports `duplicate_ast` when two
entries asked for different code and analysed byte-identical ASTs, which no goal
count can show. Entries differing only in `model` are exempt, since no WP option
changes the AST and a memory-model sweep is meant to share one. A real
instance, and the reason this is here: a project's verify target ran a default
pass alongside a `-DTLSF_NO_INTRINSICS` pass and reported both green for
several rounds. Frama-C does not predefine `__GNUC__`, so the source selected
its portable fallbacks either way and the two passes analysed the same code.
Equal goal counts, equal verdicts, nothing disagreeing. A duplicate makes the
overall verdict `incomplete`, because coverage that was never there should not
read as a clean run.

So does a missing digest. `ast_digest_unavailable_count` reports variants that
had none, which happens when the ast-utils plug-in is absent or printing the AST
outran its budget, and a non-zero count also forces `incomplete`: those variants
were compared to nothing, and a comparison that did not happen must not read as
one that happened and found nothing. Field list in
[docs/architecture.md](docs/architecture.md), under the
`frama-c-mcp.check-variants.v1` schema this call returns instead of the usual
one.

### Proof evidence

Each goal also reports `from_cache`. Frama-C's `-wp-cache` defaults to
`update`, so WP reuses verdicts it proved in earlier runs; such a verdict is a
real proof of that obligation by that prover, but not one the current run
performed, and the receipt records the difference. Pass
`run_wp {cache: "None"}` to prove everything in this run.

A proof is only as good as what it assumed. `run_wp` reports an
`assumed_callee_contract` finding for every callee whose contract it took on
faith instead of proving. Conclusions carry `stale_dependencies` when a callee's
conclusion changed underneath them and `stale_proof_environment` when the
prover environment moved, so a stored `verified` does not quietly outlive its
justification. `store_function_conclusion` refuses `verified` without a receipt,
and `list {kind: "conclusions", function}` returns `verified_with`: the memory
model, provers, timeout, assumed callee contracts, and receipt hash behind that
conclusion.

`verify_program_step` returns one `next_action` plus the unverified `frontier`
and any `blocked_functions`, under a hard `payload_budget` cap; when the payload
would exceed it, lists are truncated and the dropped count is reported rather
than silently omitted. `next_action.args` is never truncated, because it is a
call to make rather than a list to read. When truncation cannot bring the
payload under the cap, `next_action.tool` is `null` and `blockers` names why,
and in the last resort the whole body is replaced by
`status: "payload_truncated"`; a `null` tool means stop, since repeating the
call returns the same answer.

## Verification workflows

The common workflows are:

Direct EVA/WP loop:

```text
check {files or source, function?, detail?}

# detail defaults to "summary": wp_goals and eva_alarms come back as counts
# plus the first few entries that need attention. Pass detail: "full" for every
# goal and alarm, which runs to hundreds of kilobytes on a real file. The
# verdict and incomplete[] are computed from the complete data either way.

# reload_project takes a detail of its own, with the same two words and a
# different subject: its own function list, not goals and alarms. Summary gives
# each function's name and whether it is defined, which is what picking a target
# needs; full adds the signature, source location, declaration marker and filter
# flags, and turns 65 functions into 58KB. The two never interact, and a check
# never passes its value down: the reload embedded in a check payload is always
# summarised, so check {detail: "full"} returns a document whose nested
# reload.detail reads "summary". That is deliberate, because the function list
# is not what a check was asked about.

# Or step-by-step:
check {files, want: ["eva"]} -> get_wp_goals {want: ["alarms"]}
  -> get_wp_goals {want: ["investigation"], marker}
               -> inject_all_annotations
               -> run_wp -> get_wp_goals
```

Sandboxed CEGIS loop:

```text
create_sandbox -> inject_all_annotations {dry_run: true} -> inject_all_annotations -> run_wp
               -> get_wp_goals
               -> inject_all_annotations with the verified annotations -> run_wp
               -> store_function_conclusion -> delete_sandbox
```

Whole-program bottom-up loop:

```text
reload_project -> verify_program_step
               -> create_sandbox -> inject_all_annotations {dry_run: true}
               -> inject_all_annotations -> run_wp -> get_wp_goals
               -> store_function_conclusion
               -> repeat until every function has a conclusion
```

## Testing

Use the gate runner locally; it runs all thirteen repository checks, keeps logs
under `target/gate-logs`, and names failed tests. A unit test pins the runner
against the CI workflows, so the two cannot drift apart.

```bash
# Fast lane: formatting, lint, unit tests and the release build; no Frama-C needed.
scripts/run-gates.sh fast

# Full lane: requires Frama-C, WP provers, and ast-utils on PATH.
eval "$(opam env)"
scripts/run-gates.sh

# Run selected gates by name, for example:
scripts/run-gates.sh unit stdio
```

| Suite | Needs Frama-C? | Coverage |
|-------|----------------|----------|
| `shfmt -d` | no | Every tracked shell script matches `.editorconfig` |
| `cargo clippy --all-targets` | no | Lint checks for all targets, denied via `[lints.clippy]` |
| `cargo test --test unit` | no | Codec, state, callgraph, topological order, tool payload shapes |
| `test-store-conclusion` | no | Conclusion persistence and the on-disk long-text layout |
| `test-integration` | yes | Live Frama-C EVA, WP, annotations, and sandbox behavior |
| `test-mcp-stdio` | yes | Full MCP stdio surface |
| `test-process-lifecycle` | yes | Lazy spawn, SIGTERM cleanup, zombie reaping, capabilities |
| `test-reload-project-regression` | yes | In-place reload versus respawn |

CI is one workflow, `.github/workflows/ci.yml`. Four jobs run in parallel: a
fast Rust-only job on Ubuntu and macOS, an artifact scan over the tracked tree,
a full job that installs Frama-C, provers, and the `ast-utils` plugin before
running version smoke tests, the tutorial and abs-int fixture gates and the live
suites, and a job building the binaries above, each run on the platform it was
built for. A push to `main` that clears all four republishes the `latest`
release.

Steps whose shell is more than a couple of commands live in `.ci/` and the
workflow names the path, so those scripts are formatted by the `shfmt` gate and
runnable by hand. The guards in `tests/unit/repo-guards.rs` read `.ci/` as well
as `.github/workflows/`, since that is where the commands CI runs now are.

### Rust formatting is by hand

There is no `cargo fmt` gate and no `rustfmt.toml`, and that is a decision
rather than an oversight. The tree is about 800 hunks away from rustfmt
defaults across 40 files, because the wrapping is deliberate: payload literals
are laid out to mirror the JSON they build, and the comments that carry most of
this repository's reasoning are wrapped to be read rather than to fill a column
budget.

So do not run `cargo fmt` on this tree. Match the formatting of the code you
are editing, which is the same rule the shell gate enforces mechanically and
the one thing a formatter cannot check. Import ordering in particular is not a
rule here; several modules group by origin instead of alphabetically, and no
gate has an opinion.

Shell is the exception and is machine-checked, because `shfmt` agrees with what
the scripts already look like and there is no cost to enforcing it.

## Technical notes

### Frama-C server protocol

Frama-C uses a custom binary protocol, not JSON-RPC. Commands are `GET`,
`SET`, `EXEC`, `POLL`, and `SHUTDOWN`; `SET` and `EXEC` are queued and must be
driven with `POLL`.

### AST reload

Reparsing files requires `setFiles([])`, then `setFiles(files)`, then `compute`.
Directly setting the same file list is a no-op in Frama-C's state dependency
system.

### Incremental fetch APIs

`fetchFunctions` returns a full list only after `reloadFunctions`; later calls
return deltas.

### WP memory model

The server uses `Typed+nocast`, so a cast makes the relevant VC fail instead of
being silently assumed away. That failure is not always safe. Measured on
Frama-C 33 with Why3 1.8.2, a cast that reaches the goal rather than only the
code aborts Why3 with `Invalid_argument("unbound variable in of_term")`, and WP
then stamps the goals `FAILED` with no prover having answered; the same contract
proves under `Typed+cast`. `check` reports that case as `wp_backend_diagnosis`
plus the `WP_BACKEND_ANOMALY` code, because the goal records alone cannot show
it: the anomaly is on the message stream, so a per-goal classifier reads a
crashed backend as a wrong specification.

Which goals the abort cost is read off their `FAILED` status rather than off the
message. WP words the abort as `Goal <kind>:`, where the kind comes from a fixed
table (`Property`, `Invariant`, `Preservation`, and a dozen more), so the text
names a kind and never a goal. A goal left `FAILED` is one no prover answered,
and that is the only link the two have.

### Callee contracts

A bare declaration without a contract defaults to `assigns \nothing`, which is
unsound for many callees. Sandbox extraction emits empty-body stubs for callees
that lack explicit `assigns`.

## License

`frama-c-mcp` is available under a permissive
[MIT](https://opensource.org/license/mit)-style license.
Use of this source code is governed by a MIT license that can be found
in the [LICENSE](LICENSE) file.
