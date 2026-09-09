# Build, install and register frama-c-mcp.
#
# Both halves of the product are built here: the Rust MCP server and the
# ast-utils Frama-C plugin. Most tools return invalid without the plugin, so
# installing one without the other is not a partial install, it is a broken one.
#
# The multi-line recipes are held in "define" blocks and run as a single
# "bash -c", rather than written as ordinary recipe lines. Make runs each recipe
# line in its own shell, and .ONESHELL is not available: macOS ships GNU Make
# 3.81, which predates it. The install recipe needs one shell for the whole
# body, because the trap that removes its temp file has to still be in force
# several steps later. Written as plain lines it parses, runs, and silently does
# not clean up.

BINDIR ?= $(HOME)/.local/bin
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BIN := $(ROOT)/target/release/frama-c-mcp

export BINDIR
export ROOT
export BIN

.PHONY: all build plugin install register indent clean

all: build

build:
	cargo build --release --manifest-path "$(ROOT)/Cargo.toml"

# Through "opam exec", not a bare dune: dune resolves Frama-C through the opam
# switch rather than through PATH, so an unwrapped invocation compiles and
# installs the plugin against whichever switch happens to be active.
define PLUGIN_SCRIPT
set -euo pipefail
cd "$$ROOT/ast-utils"
# Clean first because an incremental build may not relink the .cmxs, which
# installs the old plugin under a new timestamp and looks like a no-op change.
opam exec -- dune clean
opam exec -- dune build
opam exec -- dune install
# The plugin's own option only parses once the .cmxs has loaded, so this fails
# when the install landed in a switch this frama-c does not read. Without it the
# mismatch first shows up as MCP tools failing at run time for no stated reason.
if ! opam exec -- frama-c -ast-utils-h >/dev/null 2>&1; then
    echo "error: ast-utils is not loadable by frama-c in this switch" >&2
    exit 1
fi
endef
export PLUGIN_SCRIPT

plugin:
	@bash -c "$$PLUGIN_SCRIPT"

# Overwriting the destination in place is what breaks this on macOS: once a
# binary has been executed the kernel holds a validated code-signature blob on
# that vnode, so a new image written over the same path is checked against a
# blob describing bytes that are no longer there. Page validation then fails at
# fault-in and every exec dies with SIGKILL (Code Signature Invalid). Install to
# a temp name in the same directory, ad-hoc sign it there, then rename over the
# target so the destination gets a fresh inode with no blob attached.
define INSTALL_SCRIPT
set -euo pipefail
mkdir -p "$$BINDIR"
tmp=$$(mktemp "$$BINDIR/frama-c-mcp.XXXXXX")
# INT TERM HUP as well as EXIT: bash does not run an EXIT trap on a signal in a
# non-interactive shell, so a Ctrl-C during the sign or smoke step below would
# otherwise leave an executable temp file sitting in the bin directory.
trap 'rm -f "$$tmp"' EXIT INT TERM HUP
cp "$$BIN" "$$tmp"
chmod 755 "$$tmp"
if command -v codesign >/dev/null 2>&1; then
    codesign -f -s - "$$tmp"
fi
# Prove the image runs before it becomes the installed one. This is what turns a
# signature failure into an install-time error rather than an MCP client
# reporting an unexplained connection failure later.
if ! "$$tmp" --help >/dev/null; then
    echo "error: built binary failed to run, not installing" >&2
    exit 1
fi
# Kept armed across the rename and cleared only once it has succeeded. Cleared
# before it, a failing mv exits under set -e with the trap already gone and
# leaves an executable temp file in the bin directory. Firing it after a
# successful mv is harmless: the temp path no longer exists by then.
mv -f "$$tmp" "$$BINDIR/frama-c-mcp"
trap - EXIT INT TERM HUP
echo "installed $$BINDIR/frama-c-mcp"
endef
export INSTALL_SCRIPT

# Both halves are built before either is installed, so a Rust compile error does
# not leave a freshly installed plugin paired with the previous binary. Ordered
# rather than parallel for the same reason, which is why this recipe drives the
# two explicitly instead of listing them as prerequisites.
install:
	@$(MAKE) --no-print-directory build
	@$(MAKE) --no-print-directory plugin
	@bash -c "$$INSTALL_SCRIPT"
	@$(MAKE) --no-print-directory register

# Point whichever agents are installed at the binary just installed. An absent
# agent is skipped rather than failing the install: registration is a
# convenience, and someone building this on a machine with neither still wants
# the binary in place.
#
# Claude's registration is removed and re-added so the recorded path follows a
# BINDIR change instead of silently pointing at the previous location. Codex has
# no CLI for this, so its TOML is appended to only when the section is absent:
# rewriting a value in someone's config file is not something a build target
# should do behind their back.
define REGISTER_SCRIPT
set -euo pipefail
# Through sh -c because "command" is a shell builtin rather than a program.
# opam exec happens to resolve it on this machine, which is exactly the kind of
# thing that stops being true on another opam version, and the failure mode is
# silent: an empty result skips both registrations below.
frama_c=$$(opam exec -- sh -c 'command -v frama-c' 2>/dev/null || true)
if [ -z "$$frama_c" ]; then
    echo "register: no frama-c in the active opam switch, skipping"
    exit 0
fi
if command -v claude >/dev/null 2>&1; then
    # Migrate the old local name before replacing the user-scoped registration.
    claude mcp remove -s local frama-c-mcp >/dev/null 2>&1 || true
    claude mcp remove -s user frama-c >/dev/null 2>&1 || true
    claude mcp add -s user frama-c -- "$$BINDIR/frama-c-mcp" --frama-c "$$frama_c"
    echo "registered with Claude Code"
else
    echo "register: claude not found, skipping"
fi
codex_cfg="$$HOME/.codex/config.toml"
if [ -f "$$codex_cfg" ]; then
    # Widened from an exact header match, which missed a quoted name and a
    # leading space; appending a second stanza there would expose every tool
    # twice under two prefixes.
    if grep -qE '^[[:space:]]*\[mcp_servers\.("?)frama-c\1\]' "$$codex_cfg"; then
        echo "register: codex already has [mcp_servers.frama-c], left as is"
    else
        # args as well as command: codex launches this outside the opam
        # environment, so without the resolved path the server cannot find the
        # switch-local frama-c and every tool fails at run time.
        printf '\n[mcp_servers.frama-c]\ncommand = "%s"\nargs = ["--frama-c", "%s"]\n' \
            "$$BINDIR/frama-c-mcp" "$$frama_c" >>"$$codex_cfg"
        echo "registered with codex"
    fi
else
    echo "register: no ~/.codex/config.toml, skipping"
fi
endef
export REGISTER_SCRIPT

register:
	@bash -c "$$REGISTER_SCRIPT"

# Formatting, not reformatting. Each of these is a gate ci.yml already runs, so
# this target exists to satisfy them rather than to have opinions of its own:
# clang-format for C, shfmt for shell, and commentflow for the comments neither
# of those two owns. cargo fmt is deliberately absent: it rewrites 834 sites
# across nearly every file in src/, which is a rewrite of the tree rather than a
# formatting pass, and no gate in this repository asks for it.
define INDENT_SCRIPT
set -euo pipefail
cd "$$ROOT"
# The version comes from .ci/llvm-version, which scripts/check-c-formatting.sh
# and the installer CI runs read too. Majors disagree on output, so formatting
# with the wrong one produces a tree that fails the gate this target exists to
# satisfy, which is a worse outcome than refusing to format at all.
want_clang=$$(cat .ci/llvm-version)
clang_format=$${CLANG_FORMAT:-clang-format-$$want_clang}
if ! command -v "$$clang_format" >/dev/null 2>&1; then
    echo "indent: $$clang_format not found, no C file formatted" >&2
    exit 1
fi
have_clang=$$("$$clang_format" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ "$${have_clang%%.*}" != "$$want_clang" ]; then
    echo "indent: clang-format $$have_clang but this tree wants $$want_clang.x; formatting would fail the gate" >&2
    exit 1
fi
git ls-files -z '*.c' '*.h' | xargs -0 "$$clang_format" -i
if ! command -v shfmt >/dev/null 2>&1; then
    echo "indent: shfmt not found, nothing formatted" >&2
    exit 1
fi
# Version-checked against .ci/check-shell-formatting.sh, which pins shfmt by
# sha256 because this formatter decides what the tree's shell looks like. That
# gate downloads a linux binary, so it cannot be reused here; matching the
# version is what keeps a local reformat from failing the gate it exists to
# satisfy.
want_shfmt=$$(sed -n 's|.*/download/v\([0-9.]*\)/shfmt.*|\1|p' .ci/check-shell-formatting.sh | head -1)
have_shfmt=$$(shfmt --version | tr -d 'v')
if [ -n "$$want_shfmt" ] && [ "$$want_shfmt" != "$$have_shfmt" ]; then
    echo "indent: shfmt $$have_shfmt but CI pins $$want_shfmt; formatting would fail the gate" >&2
    exit 1
fi
git ls-files -z '*.sh' '*.hook' | xargs -0 shfmt -w
if command -v commentflow >/dev/null 2>&1; then
    # The fixtures too, which they were not until they were reflowed once and
    # the suites taught the new positions. Reflowing a header comment there
    # adds a line, and the suites pin source positions in them: the ACSL error
    # in acsl-type-error.c moved from line 11 to 12, uncontracted-callee.c
    # shifted by one throughout, and a loop annotation whose closing marker
    # took its own line pushed the loop past it. Excluding them was right while
    # the tree was unreflowed and is not now, because the exclusion would let
    # the next fixture edit drift back out of the shape the tree is in, with no
    # gate to catch it. A shift that reaches a test fails the suite, which is
    # how all nine of those coordinates were found.
    git ls-files -z '*.rs' '*.c' '*.h' '*.sh' | xargs -0 commentflow
else
    echo "indent: commentflow not found, comments left alone"
fi
endef
export INDENT_SCRIPT

indent:
	@bash -c "$$INDENT_SCRIPT"

# The plugin's _build too, not just Rust's target: leaving it is what lets a
# stale .cmxs be reinstalled, which is the failure the dune clean above exists
# to prevent.
clean:
	cargo clean --manifest-path "$(ROOT)/Cargo.toml"
	rm -rf "$(ROOT)/ast-utils/_build" "$(ROOT)/target/gate-logs"
