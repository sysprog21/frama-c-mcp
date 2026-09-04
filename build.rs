//! Stamp the commit this binary was built from.
//!
//! CARGO_PKG_VERSION is the only identity the server had, and it has read
//! 0.1.0 for the whole project's life, so an installed binary and a freshly
//! built one describe themselves identically. That gap is expensive in
//! practice: a caller comparing behaviour against the source cannot tell that
//! the server answering them predates the code they are reading, and every
//! conclusion drawn that way is about a binary nobody has.
//!
//! Best effort by design. A build from a tarball has no git, and that is not a
//! reason to fail the build; it is a reason to say "unknown" and let the reader
//! know the answer is unavailable rather than reassuring.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Asked first, because it is the one answer that refuses the whole job: a
    // copy of these sources vendored into another repository would otherwise
    // report that repository's HEAD as this server's build identity, which is
    // worse than unknown, since a confident wrong sha is the value a caller
    // compares against their own git rev-parse.
    //
    // Asked as a question about this directory rather than as a comparison of
    // two paths. --show-prefix prints the path from the worktree top down to
    // here, so empty output means this is the top, and git answers it having
    // already resolved whatever symlinks or "." components the path was
    // reached through. Comparing --show-toplevel against CARGO_MANIFEST_DIR as
    // strings did not: git resolves symlinks and cargo does not, so a
    // symlinked checkout compared unequal and stamped itself unknown, which is
    // this guard turning the feature off rather than protecting it.
    //
    // Read through command() rather than git(), because git() maps empty
    // output to None and empty is the answer being looked for.
    let in_own_checkout = command(&manifest, &["rev-parse", "--show-prefix"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| out.stdout.iter().all(u8::is_ascii_whitespace));
    if !in_own_checkout {
        println!("cargo:rustc-env=BUILD_COMMIT=unknown");
        return;
    }

    // Naming any rerun-if-changed path turns off cargo's default "re-run when
    // any file in the package changed", so both halves have to be listed here
    // or the stamp goes stale in one of two ways: the git metadata alone misses
    // a source edit, which is the dirty bit, and the sources alone miss a
    // commit, which is the sha.
    //
    // A missing tracked path is named anyway. Cargo re-runs a build script on
    // every build while a watched path does not exist, and that is the right
    // signal for a tracked file: missing from the working tree means the tree
    // is dirty, the cost is a few git calls and a relink, and it stops the
    // moment the file comes back. It is the wrong signal for a ref file, whose
    // absence is normal, and watched_paths probes those for that reason. Dropping the path instead was a one-way door, since
    // restoring the file did not re-run this script and the stamp stayed
    // "-dirty" over a tree that had become clean.
    //
    // Substituting the nearest existing ancestor, which is what this did
    // first, is the worst of the three. Cargo prices a directory as a
    // recursive walk, so a deleted top-level file resolves to the manifest
    // root and watches target/ with it: measured at 9.6 GB and 131,902 files
    // here, dirty on every no-op build afterwards, which is the whole-tree
    // watch the doc below records as having been removed once already.
    for path in watched_paths(&manifest).unwrap_or_default() {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    println!("cargo:rustc-env=BUILD_COMMIT={}", build_commit(&manifest));
}

/// Everything whose change can move the stamp.
///
/// The tracked files, from git, and not the directory listing. Reading the
/// directory watched whatever happened to be sitting in it: measured at 12,483
/// files and 220 MB against git's 193, the difference being ignored output such
/// as externals, ast-utils/_build and the .frama-c cache that every WP run
/// writes. None of it can move the stamp, because the dirty bit comes from
/// git diff against HEAD, which does not see an ignored file. What it did do is
/// re-run this script and relink the crate after every gate, once costing a
/// full release rebuild in the middle of a gate run.
///
/// None when git cannot enumerate the tracked files. Watching the metadata
/// alone would be worse than watching nothing: naming any path at all turns
/// cargo's default package scan off, so the script would stop re-running on a
/// source edit and the dirty bit would freeze. With no directives cargo keeps
/// that default, which is the conservative answer.
fn watched_paths(manifest: &Path) -> Option<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = git(manifest, &["ls-files"])?
        .lines()
        .map(|line| manifest.join(line))
        .collect();

    // The git directory is a file in a worktree and in a submodule, and the ref
    // that HEAD points at lives under the common directory rather than the
    // per-worktree one. Asking git for both is the only way to name them.
    if let Some(git_dir) = git(manifest, &["rev-parse", "--absolute-git-dir"]) {
        // HEAD and the index are per-worktree; a detached HEAD moves HEAD
        // itself and needs nothing further.
        paths.push(Path::new(&git_dir).join("HEAD"));
        paths.push(Path::new(&git_dir).join("index"));
    }
    // --path-format wants git 2.31. On an older one the whole query fails, and
    // the answer without it is a path relative to the current directory, which
    // is the manifest dir here, so joining it gives the same result. Without
    // the fallback an old git watched no branch ref at all, and switching
    // branches or committing left the stamp naming the previous commit.
    let common_dir = git(
        manifest,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    .map(PathBuf::from)
    .or_else(|| git(manifest, &["rev-parse", "--git-common-dir"]).map(|dir| manifest.join(dir)));
    if let Some(common_dir) = common_dir {
        // These two are probed, and the tracked files above are not, because
        // absence means opposite things. A tracked file missing from the
        // working tree is a dirty tree, so naming it and letting cargo re-run
        // until it returns is the right signal. A missing ref file is the
        // normal state of a healthy repository: packed-refs does not exist
        // until refs are packed, and the loose ref does not exist once they
        // are. Naming either unconditionally re-runs this script and relinks
        // the server on every build, forever, which is the cost this whole
        // list was rewritten to avoid.
        //
        // One of the two always exists, so the branch HEAD points at is
        // watched either way: pack the refs and the loose file goes but
        // packed-refs appears, unpack them and the reverse.
        let head_ref = git(manifest, &["symbolic-ref", "--quiet", "HEAD"]);
        let refs = [Some(common_dir.join("packed-refs")), head_ref.map(|r| common_dir.join(r))];
        paths.extend(refs.into_iter().flatten().filter(|path| path.exists()));
    }
    Some(paths)
}

fn build_commit(manifest: &Path) -> String {
    // The full object id, not --short. Git picks the abbreviation length from
    // the object database and lengthens it as the database grows, so two
    // builds of the same commit can stamp different strings and a caller
    // comparing them would read a difference that is not one. The full id is
    // the only spelling that is a function of the commit alone.
    let Some(commit) = git(manifest, &["rev-parse", "HEAD"]) else {
        return "unknown".to_string();
    };

    // A dirty tree is the case this exists for: it is what an installed binary
    // built from uncommitted work looks like, and the commit alone would name a
    // tree it does not match.
    //
    // Tracked changes only, and by exit code. git status walks every untracked
    // file, so a stray scratch directory would stamp a release binary dirty,
    // and it rewrites the index it just walked, which is one of the paths this
    // script watches. A git that cannot answer at all is reported dirty rather
    // than as a third state: "-dirty" already means "do not compare this sha to
    // a tree", which is what a reader must do with a tree nobody could read,
    // and it understates confidence rather than overstating it.
    //
    // "diff", not "diff-index". Both compare the working tree against HEAD, and
    // only the first falls back to reading the file when the index says a path
    // is stat-dirty. GIT_OPTIONAL_LOCKS=0 is what makes that difference matter:
    // git may not refresh the index it just found stale, so "diff-index"
    // reports every touched-but-unchanged file as a difference, and a clean
    // checkout stamps "-dirty" after anything that rewrites a source with the
    // same bytes.
    let clean = command(manifest, &["diff", "--quiet", "HEAD", "--"])
        .status()
        .ok()
        .and_then(|status| status.code())
        == Some(0);
    if clean {
        commit
    } else {
        format!("{commit}-dirty")
    }
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = command(dir, args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");

    // Without this, a read-only query takes index.lock to refresh stat data,
    // which fails outright when a concurrent cargo or git holds it and degrades
    // the stamp nondeterministically.
    command.env("GIT_OPTIONAL_LOCKS", "0");
    command.args(args).current_dir(dir);
    command
}
