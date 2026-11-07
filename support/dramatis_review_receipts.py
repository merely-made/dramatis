#!/usr/bin/env python3
# Copyright 2026 Mark Alan Boykin
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# SPDX-License-Identifier: MPL-2.0
"""Reproduce the Windows Dramatis app's synthetic custody receipts and native captures.

The app builds here. Djinn's review host and custody tests build in the sibling
Mere checkout (--mere). The consent control breaks this checkout's review gate
and runs Mere's test against it, with Mere's dramatis.git packages patched to
this checkout through a lock copy in the receipt directory; no Mere file is
written. No actual vault is opened. Deletes only marker-identified fixture data.
"""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, time, tomllib

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/dramatis"
APP_TARGET = Path("C:/t/cargo-targets/dramatis-app")
MERE_TARGET = Path("C:/t/cargo-targets/mere")
GATE = ROOT / "crates/dramatis-resident/src/keeper/review.rs"
FLAG = "DRAMATIS_SYNTHETIC_CONSENT_CONTROL"
FOCUSED = "cards_are_secret_free_scoped_and_denial_preserves_the_item"
REVIEW_TESTS = 16
# Store discovery runs in djinn-custodian's unlock (claim_credentials) since
# custody isolation H2; these drive it through a real custodian after the
# selected persona changes.
DISCOVERY = ["persona_selection_and_lock_preserve_the_original_credential_root",
             "multiple_stores_keep_keys_and_review_targets_distinct"]
DRAMATIS_GIT = "https://github.com/merely-made/dramatis.git"
MERE_GIT = "https://github.com/merely-made/mere.git"
CODE = ("*.rs", "*.toml", "Cargo.lock")
records = []
JOBS = 1
OUT = MERE = None


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True, encoding="utf-8").strip()


def primary():
    """The main checkout, also when this runs from a worktree."""
    return Path(git(ROOT, "rev-parse", "--path-format=absolute", "--git-common-dir")).parent


def channel(repo):
    return tomllib.loads((repo / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name, args, cwd, env=None, expected=0, patched=False):
    path = OUT / (name + ".log")
    with path.open("w", encoding="utf-8") as log:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    records.append({"name": name, "cwd": str(cwd), "command": args, "exit_code": result.returncode, "expected": expected})
    print(name, result.returncode, flush=True)
    assert result.returncode == expected, f"{name}: see {path}"
    text = path.read_text(encoding="utf-8", errors="replace")
    assert not patched or "was not used in the crate graph" not in text, f"{name}: unused patch; see {path}"
    return text


def cargo(repo, target, *args):
    return ["cargo", "+" + channel(repo), *args, "--locked", "--target-dir", str(target), "-j" + str(JOBS)]


def app(name, *args, env=None, after=()):
    return run(name, cargo(ROOT, APP_TARGET, *args) + list(after), APP, env)


def mere(name, *args, env=None, after=()):
    return run(name, cargo(MERE, MERE_TARGET, *args) + list(after), MERE, env)


def lock_packages(path):
    return {(p["name"], p["version"]): p for p in tomllib.loads(path.read_text(encoding="utf-8"))["package"]}


def patch_config(lock):
    """Serve every dramatis.git package in Mere's graph from this checkout, one copy each."""
    names = sorted(n for (n, _), p in lock_packages(MERE / "Cargo.lock").items()
                   if p.get("source", "").startswith("git+" + DRAMATIS_GIT))
    homes = {tomllib.loads(m.read_text(encoding="utf-8"))["package"]["name"]: m.parent
             for m in ROOT.glob("crates/*/Cargo.toml")}
    assert names and set(names) <= homes.keys(), ("dramatis.git packages without a home here", names)
    # Mere redirects mere.git names to dramatis.git; those must follow the patch too.
    table = tomllib.loads((MERE / "Cargo.toml").read_text(encoding="utf-8"))["patch"].get(MERE_GIT, {})
    redirects = sorted(n for n, spec in table.items() if isinstance(spec, dict) and spec.get("git") == DRAMATIS_GIT)
    args = ["--config", f"resolver.lockfile-path='{lock.as_posix()}'"]
    for source, group in [(DRAMATIS_GIT, names), (MERE_GIT, redirects)]:
        for name in group:
            args += ["--config", f'patch."{source}".{name}.path="{homes[name].as_posix()}"']
    return names, args


def check_patched_lock(lock, names):
    """Only the patched packages' sources may differ from Mere's own lock."""
    before, after = lock_packages(MERE / "Cargo.lock"), lock_packages(lock)
    assert before.keys() == after.keys(), "patched graph changed its package set"
    for key, package in after.items():
        if key[0] in names:
            assert "source" not in package and before[key]["source"].startswith("git+" + DRAMATIS_GIT), key
            package = dict(package, source=before[key]["source"])
        assert package == before[key], key


def consent_control():
    original = GATE.read_bytes()
    start = original.index(b"fn review_quarantine(")
    assert original.count(b"if !self", start) == 1, "the per-item consent gate moved"
    offset = original.index(b"if !self", start)
    broken = original[:offset] + b'if std::env::var_os("' + FLAG.encode() + b'").is_none() && !self' + original[offset + 8:]
    lock = OUT / "control-lock/Cargo.lock"  # cargo requires this file name
    lock.parent.mkdir()
    shutil.copyfile(MERE / "Cargo.lock", lock)
    names, patch = patch_config(lock)
    run("control-lock", ["cargo", "+" + channel(MERE), "tree", "-p", "mere-resident", "--depth", "0", *patch], MERE, patched=True)
    check_patched_lock(lock, names)
    suite = cargo(MERE, MERE_TARGET, "test", "-p", "mere-resident", "--test", "quarantine_review", "--features", "cxf", *patch)
    ordinary = {k: v for k, v in os.environ.items() if k != FLAG}
    try:
        GATE.write_bytes(broken)
        # Without this process-scoped flag the broken build still asks for consent.
        log = run("control-unflagged", suite + ["--", "--exact", FOCUSED], MERE, ordinary, patched=True)
        # The suite is cfg(unix) since custody isolation H2; zero tests proves nothing.
        assert "running 1 test" in log and "test result: ok. 1 passed" in log, "the focused test did not run"
        log = run("negative-consent", suite + ["--", "--exact", FOCUSED], MERE, dict(ordinary, **{FLAG: "1"}), expected=101, patched=True)
        assert f"{FOCUSED} ... FAILED" in log and "error[E" not in log
    finally:
        GATE.write_bytes(original)
    assert GATE.read_bytes() == original and not git(ROOT, "status", "--porcelain", "--", str(GATE))
    log = run("restored", suite, MERE, ordinary, patched=True)
    assert f"test result: ok. {REVIEW_TESTS} passed" in log
    return {"synthetic_process_flag": FLAG, "patched_packages": names, "restored_consent_sha256": digest(GATE),
            "patched_lock_sha256": digest(lock)}


def remove_runtime(root):
    assert root.resolve().parent == OUT.resolve() and root.name.startswith("runtime-")
    assert (root / ".dramatis-generated").read_text() == "synthetic Dramatis custody fixture"
    shutil.rmtree(root)


def endpoint_env(mode, **extra):
    endpoint = r"\\.\pipe\dramatis-app-receipt-" + mode
    return endpoint, dict(os.environ, GRAPHSHELL_APP_ENDPOINT=endpoint, DRAMATIS_RECEIPT_ENDPOINT=endpoint,
                          DRAMATIS_RECEIPT_MODE=mode, **extra)


def window(name, env):
    run(name, [str(APP_TARGET / "debug/dramatis-ui.exe")], APP, env)
    assert Path(env["DRAMATIS_CAPTURE"]).is_file()


def absent():
    _, env = endpoint_env("absent", DRAMATIS_CAPTURE=str(OUT / "absent.png"), DRAMATIS_CAPTURE_MODE="absent")
    app("app-wire-absent", "test", "-p", "dramatis-app", "--test", "state", env=env, after=["--", "--ignored", "--exact", "app_wire_receipt"])
    window("window-absent", env)


def fixture(mode):
    root = OUT / ("runtime-" + mode)
    assert not root.exists(), "retain unexpected runtime for inspection"
    endpoint, env = endpoint_env(mode)
    host_exe = MERE_TARGET / "debug/dramatis-review-host.exe"
    with (OUT / ("host-" + mode + ".log")).open("w") as host_log:
        host = subprocess.Popen([str(host_exe), endpoint, str(root), mode], cwd=MERE, stdout=host_log,
                                stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 60
            while not (root / "ready").exists():
                assert host.poll() is None, "fixture host exited"
                assert time.monotonic() < deadline, "fixture readiness"
                time.sleep(.1)
            app("app-wire-" + mode, "test", "-p", "dramatis-app", "--test", "state", env=env,
                after=["--", "--ignored", "--exact", "app_wire_receipt", "--nocapture"])
            for size in ["860x900", "420x900"]:
                window(f"window-{mode}-{size}", dict(env, DRAMATIS_CAPTURE=str(OUT / f"{mode}-{size}.png"),
                                                     DRAMATIS_CAPTURE_MODE=mode, DRAMATIS_CAPTURE_SIZE=size))
        finally:
            if host.poll() is None:
                host.terminate()
            host.wait(timeout=30)
    remove_runtime(root)


def app_source_digest():
    """The app's build.rs digest: its manifest, lock, build script and src/*.rs, LF-normalised."""
    names = ["Cargo.lock", "Cargo.toml", "build.rs"] + ["src/" + p.name for p in (APP / "src").glob("*.rs")]
    hash = hashlib.sha256()
    for name in sorted(names):
        hash.update(name.encode() + b"\0" + (APP / name).read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return hash.hexdigest()


def tracked(repo, *paths):
    files = git(repo, "ls-files", "--", *paths).splitlines()
    return {f: digest(repo / f) for f in files if f.endswith((".rs", ".toml", "Cargo.lock"))}


def clean_code(repo):
    dirty = git(repo, "status", "--porcelain", "--", *CODE)
    assert not dirty, (f"uncommitted code in {repo}; a receipt names revisions", dirty)


def write(name, **extra):
    mere_lock = {p.get("source", "").split("#")[-1] for p in lock_packages(MERE / "Cargo.lock").values()
                 if p.get("source", "").startswith("git+" + DRAMATIS_GIT)}
    exes = {p.name: digest(p) for p in [APP_TARGET / "debug/dramatis-ui.exe", MERE_TARGET / "debug/dramatis-review-host.exe"] if p.is_file()}
    value = {"platform": "Windows native Cambium/Genet",
             "dramatis": {"revision": git(ROOT, "rev-parse", "HEAD"), "toolchain": channel(ROOT)},
             "mere": {"path": str(MERE), "revision": git(MERE, "rev-parse", "HEAD"), "toolchain": channel(MERE),
                      "locked_dramatis_revisions": sorted(mere_lock)},
             "controller_sha256": digest(Path(__file__)), "commands": records, **extra, "executables_sha256": exes,
             "artifacts_sha256": {p.name: digest(p) for p in sorted(OUT.iterdir()) if p.suffix in [".png", ".log", ".lock"]}}
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def built_app():
    info = json.loads(subprocess.check_output([str(APP_TARGET / "debug/dramatis-ui.exe"), "--build-info"], text=True))
    assert info["source_sha256"] == app_source_digest(), "app binary does not match this checkout's source"
    return info


def main():
    global JOBS, OUT, MERE
    assert os.name == "nt", "Windows receipt; other native hosts remain pending"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mere", type=Path, default=primary().parent / "mere", help="Mere checkout that builds the resident host")
    parser.add_argument("--out", type=Path, default=primary().parents[1] / "testing/dramatis/support-receipts/dramatis-app")
    parser.add_argument("--jobs", type=int, default=1, help="Compiler jobs; keep memory for concurrent lanes")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--window-only", action="store_true", help="Requalify app views without repeating custody tests")
    parser.add_argument("--control-only", action="store_true", help="Requalify the scoped control and restore the gate")
    args = parser.parse_args()
    assert args.jobs > 0
    JOBS, OUT, MERE = args.jobs, args.out.resolve(), args.mere.resolve()
    clean_code(ROOT)
    clean_code(MERE)
    OUT.mkdir(parents=True, exist_ok=True)
    if args.control_only:
        return write("control-scope.json", **consent_control())
    if args.window_only:
        if not args.skip_build:
            mere("host-build", "build", "-p", "mere-resident", "--bin", "dramatis-review-host", "--features", "custody-receipt-host,cxf")
        app("app-build", "build", "-p", "dramatis-app", "--bin", "dramatis-ui")
        app("app-state", "test", "-p", "dramatis-app", "--test", "state")
        app("interaction", "test", "-p", "dramatis-app", "--test", "interaction")
        absent()
        fixture("locked")
        fixture("unlocked")
        return write("window-scope.json", build_info=built_app(), source_sha256={"dramatis": tracked(ROOT, "apps/dramatis")})
    assert not any(OUT.iterdir()), f"{OUT} holds an earlier run"
    # The control runs first, so the shared target's later builds are Mere's own.
    control = consent_control()
    if not args.skip_build:
        mere("host-build", "build", "-p", "mere-resident", "--bin", "dramatis-review-host", "--features", "custody-receipt-host,cxf")
        app("app-build", "build", "-p", "dramatis-app", "--bin", "dramatis-ui")
    log = mere("green", "test", "-p", "mere-resident", "--test", "quarantine_review", "--features", "cxf")
    assert f"running {REVIEW_TESTS} tests" in log and f"test result: ok. {REVIEW_TESTS} passed" in log
    log = mere("store-discovery", "test", "-p", "mere-resident", "--test", "quarantine_review", "--features", "cxf",
               after=["--", "--exact", *DISCOVERY])
    assert f"test result: ok. {len(DISCOVERY)} passed" in log
    app("app-state", "test", "-p", "dramatis-app", "--test", "state")
    app("interaction", "test", "-p", "dramatis-app", "--test", "interaction")
    run("castellan", cargo(ROOT, primary() / "target", "test", "-p", "castellan", "--features", "cxf", "--lib"), ROOT)
    absent()
    fixture("locked")
    fixture("unlocked")
    write("receipt.json", **control, build_info=built_app(), app_source_sha256=app_source_digest(),
          source_sha256={"dramatis": tracked(ROOT, "Cargo.toml", "Cargo.lock", "apps/dramatis", "crates"),
                         "mere": tracked(MERE, "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "ports/mere-resident")},
          scope="synthetic fixtures; no actual vault; native captures require separate visual review; consent gate restored byte-exact")


if __name__ == "__main__":
    main()
