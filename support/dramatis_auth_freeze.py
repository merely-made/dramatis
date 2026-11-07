#!/usr/bin/env python3
# Copyright 2026 Mark Alan Boykin
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# SPDX-License-Identifier: MPL-2.0
"""Freeze native authentication fixtures and record both repositories' inputs.

Run on the acceptance machine after building the app here and Mere's ignored
test host in the sibling checkout (--mere):
  apps/dramatis: cargo build --locked -p dramatis-app --bin dramatis-ui
  mere: cargo test --locked --no-run --message-format json -p mere-resident
        --test passphrase_change > host-build.json
The executables remain private; build-inputs.json is public receipt material.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_build_input(path, repo, tracked, build_roots):
    """Keep generated cache inputs separate without accepting untracked source."""
    relative = path.relative_to(repo).as_posix() if path.is_relative_to(repo) else None
    if relative in tracked:
        return "repository", relative
    for label, root in build_roots.items():
        assert root != repo and not repo.is_relative_to(root), "build root contains repository source"
        if path.is_relative_to(root):
            return "generated", label + "/" + path.relative_to(root).as_posix()
    assert relative is None, ("untracked repository build input", relative)
    return None


def locate(path, repos, tracked, build_roots):
    """Classify against whichever checkout holds the path; repository names carry its label."""
    owner = next((label for label, repo in repos.items() if path.is_relative_to(repo)), None)
    if owner is None:
        # Outside both checkouts; each still asserts no build root contains it.
        return [classify_build_input(path, repo, set(), build_roots) for repo in repos.values()][0]
    entry = classify_build_input(path, repos[owner], tracked[owner], build_roots)
    if entry and entry[0] == "repository":
        return "repository", owner + "/" + entry[1]
    return entry


def depfile_sources(source):
    """Read rustc's Make escapes without treating Windows separators as escapes."""
    rule = source.replace("\\\n", " ").splitlines()[0]
    dependencies = rule.split(": ", 1)[1]
    names, word = [], []
    index = 0
    while index < len(dependencies):
        char = dependencies[index]
        if char == "\\" and index + 1 < len(dependencies) and dependencies[index + 1] in " \\#:":
            word.append(dependencies[index + 1])
            index += 2
            continue
        if char.isspace():
            if word:
                names.append("".join(word))
                word = []
        else:
            word.append(char)
        index += 1
    if word:
        names.append("".join(word))
    return names


def binary_format(path):
    if platform.system() != "Windows":
        return subprocess.check_output(["file", "-b", str(path)], text=True).strip()
    data = path.read_bytes()
    assert data[:2] == b"MZ" and len(data) >= 64, "not a Windows executable"
    offset = int.from_bytes(data[60:64], "little")
    assert data[offset:offset + 4] == b"PE\0\0", "missing PE header"
    assert int.from_bytes(data[offset + 4:offset + 6], "little") == 0x8664, "unqualified PE architecture"
    assert int.from_bytes(data[offset + 24:offset + 26], "little") == 0x20b, "not PE32+"
    return "PE32+ x86-64 Windows executable"


def app_source_names(app):
    """The inputs the app's build.rs digests, relative to the app's workspace."""
    names = {"Cargo.lock", "Cargo.toml", "build.rs"}
    names.update("src/" + p.name for p in (app / "src").glob("*.rs"))
    return sorted(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["artifacts", "build-dir", "mere-build-dir", "host-build", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=ROOT, help="Dramatis checkout")
    parser.add_argument("--mere", type=Path, help="Mere checkout; default: beside the Dramatis repository")
    parser.add_argument("--toolchain", default="1.99.1")
    args = parser.parse_args()
    repo = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    assert platform.system() in {"Linux", "Darwin", "Windows"}, "unqualified native format"
    suffix = ".exe" if platform.system() == "Windows" else ""

    def run(*command, cwd=repo):
        return subprocess.check_output(command, cwd=cwd, text=True, encoding="utf-8").strip()

    primary = Path(run("git", "rev-parse", "--path-format=absolute", "--git-common-dir")).parent
    mere = (args.mere or primary.parent / "mere").resolve()
    repos = {"dramatis": repo, "mere": mere}
    app_root = repo / "apps/dramatis"
    cargo = str(Path.home() / (".cargo/bin/cargo" + suffix))
    compiler = str(Path.home() / (".cargo/bin/rustc" + suffix))
    if platform.system() == "Darwin":
        bundle = output / "Dramatis.app"
        app = bundle / "Contents/MacOS/dramatis-ui"
        app.parent.mkdir(parents=True)
        with (bundle / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleIdentifier": "made.merely.dramatis.authentication.acceptance",
                          "CFBundleName": "Dramatis authentication test",
                          "CFBundleExecutable": "dramatis-ui", "CFBundlePackageType": "APPL",
                          "NSHighResolutionCapable": True}, stream)
    else:
        app = output / ("dramatis-ui" + suffix)
    shutil.copy2(args.artifacts / ("debug/dramatis-ui" + suffix), app)
    artifacts = [json.loads(line) for line in args.host_build.read_text(encoding="utf-8").splitlines()
                 if line.startswith("{")]
    artifacts = [a for a in artifacts if a.get("reason") == "compiler-artifact"]
    host_source = next(a["executable"] for a in artifacts
                       if a["target"]["name"] == "passphrase_change" and a.get("executable"))
    host = output / ("authentication-host" + suffix)
    shutil.copy2(host_source, host)
    if platform.system() == "Darwin":
        for path in [bundle, host]:
            run("/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(path))
            run("/usr/bin/codesign", "--verify", "--strict", str(path))

    info = json.loads(run(str(app), "--build-info"))
    names = app_source_names(app_root)
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b"\0" + (app_root / name).read_text(encoding="utf-8").replace("\r\n", "\n").encode() + b"\0")
    assert digest.hexdigest() == info["source_sha256"], "app source digest mismatch"

    files = {"dramatis/apps/dramatis/" + name for name in names}
    files.update(["dramatis/support/dramatis_auth_receipts.py", "dramatis/support/dramatis_auth_freeze.py",
                  "dramatis/support/test_dramatis_auth_tools.py", "mere/ports/mere-resident/tests/passphrase_change.rs"])
    depfiles = {args.artifacts / "debug/dramatis-ui.d"}
    for artifact in artifacts:
        manifest = Path(artifact["manifest_path"]).resolve()
        for label, root in repos.items():
            if manifest.is_relative_to(root):
                files.add(label + "/" + manifest.relative_to(root).as_posix())
        for filename in artifact["filenames"]:
            stem = Path(filename).stem.removeprefix("lib")
            depfile = args.mere_build_dir / "debug/deps" / (stem + ".d")
            if depfile.is_file():
                depfiles.add(depfile)
    tracked = {label: set(run("git", "ls-files", cwd=root).splitlines()) for label, root in repos.items()}
    build_roots = {"build": args.build_dir.resolve(), "artifacts": args.artifacts.resolve(),
                   "mere-build": args.mere_build_dir.resolve(), "mere-artifacts": Path(host_source).resolve().parents[2]}
    generated = {}
    for depfile in depfiles:
        for name in depfile_sources(depfile.read_text(encoding="utf-8")):
            path = Path(name)
            path = (path if path.is_absolute() else repo / path).resolve()
            if not path.is_file():
                continue
            entry = locate(path, repos, tracked, build_roots)
            if entry is not None:
                kind, name = entry
                if kind == "repository":
                    files.add(name)
                else:
                    generated[name] = sha(path)
    known = {label + "/" + name for label, names in tracked.items() for name in names}
    assert files <= known, ("untracked repository build inputs", sorted(files - known))

    suppliers = {}
    actual_packages = {a["package_id"] for a in artifacts}
    external_paths = []
    for workspace, owner in [(app_root, repo), (mere, mere)]:
        metadata = json.loads(run(cargo, "+" + args.toolchain, "metadata", "--locked", "--offline", "--format-version", "1", cwd=workspace))
        for package in metadata["packages"]:
            source = package["source"]
            manifest = Path(package["manifest_path"])
            if source and source.startswith("git+"):
                root = run("git", "rev-parse", "--show-toplevel", cwd=manifest.parent)
                if root not in suppliers:
                    head = run("git", "rev-parse", "HEAD", cwd=root)
                    assert head == source.split("#")[-1], (root, head, source)
                    assert not run("git", "diff", "--name-only", "HEAD", "--", "*.rs", "*.toml",
                                   "Cargo.lock", "*.wgsl", "*.c", "*.h", "*.cpp", "*.hpp", cwd=root), root
                    suppliers[root] = {"source": source, "head": head, "packages": [], "tracked_code_changes": []}
                if package["name"] not in suppliers[root]["packages"]:
                    suppliers[root]["packages"].append(package["name"])
            elif source is None and not manifest.is_relative_to(owner):
                assert package["id"] not in actual_packages, ("unrecorded external source", package["name"])
                external_paths.append({"name": package["name"], "manifest": str(manifest)})
    for package, workspace in [("dramatis-app", app_root), ("mere-resident", mere)]:
        tree = run(cargo, "+" + args.toolchain, "tree", "--locked", "--offline", "-p", package, "--edges", "normal,build", cwd=workspace)
        (output / (package + "-tree.txt")).write_text(tree + "\n", encoding="utf-8")
        if package == "dramatis-app":
            assert "castellan v" not in tree, "secret custody entered the app dependency cone"
    binaries = {}
    for path in [app, host]:
        binaries[path.relative_to(output).as_posix()] = {
            "sha256": sha(path), "bytes": path.stat().st_size,
            "format": binary_format(path),
            "signing": "ad-hoc; timestamp none" if platform.system() == "Darwin" else "native executable; no signing step",
        }
    value = {"source_commits": {label: run("git", "rev-parse", "HEAD", cwd=root) for label, root in repos.items()},
             "build_info": info,
             "files": {name: sha(repos[name.split("/", 1)[0]] / name.split("/", 1)[1]) for name in sorted(files)},
             "binaries": binaries,
             "generated_build_inputs": {"roots": {name: str(root) for name, root in build_roots.items()},
                                        "files": dict(sorted(generated.items()))},
             "git_suppliers": suppliers, "uncompiled_external_path_packages": external_paths,
             "rustc": run(compiler, "+" + args.toolchain, "-Vv"), "depfiles_read": len(depfiles),
             "supplier_scope": "Resolved Git checkouts; tracked Rust/TOML/lock/WGSL/C/C++ only. Untracked and asset-only supplier changes excluded.",
             "environment": {key: os.environ.get(key) for key in ["CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"]}}
    (output / "build-inputs.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sources": value["source_commits"], "files": len(files), "git_suppliers": len(suppliers), "binaries": binaries}))


if __name__ == "__main__":
    main()
