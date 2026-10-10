# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT = "casbin-node-casbin"
COMPONENT = "node-casbin"
MANIFEST = "package.json"
ASF_BASE = "https://downloads.apache.org/incubator/casbin"


def git(*args):
    return subprocess.check_output(["git", *args])


def metadata(tag):
    match = re.fullmatch(r"v(\d+\.\d+\.\d+)(-rc[1-9]\d*)?", tag)
    if not match:
        raise ValueError("Use vX.Y.Z or vX.Y.Z-rcN (N >= 1)")
    version, rc = match.groups()
    manifest = git("show", f"{tag}:{MANIFEST}")
    actual = json.loads(manifest)["version"] if MANIFEST.endswith("json") else tomllib.loads(manifest.decode())["project"]["version"]
    if actual != version:
        raise ValueError(f"Commit version {actual} does not match {version}; no version stamping")
    name = f"apache-{PROJECT}-{version}-incubating-src"
    return version, bool(rc), name


def inventory(data, name):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            parts = Path(member.name).parts
            if not parts or parts[0] != name or ".." in parts or "\\" in member.name:
                raise ValueError(f"Unexpected archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or member.name in result:
                raise ValueError(f"Link, special file or duplicate: {member.name}")
            result[member.name] = (archive.extractfile(member).read(), member.mode & 0o777)
    for required in ("LICENSE", "NOTICE", "DISCLAIMER", MANIFEST):
        if f"{name}/{required}" not in result:
            raise ValueError(f"Missing {required}")
    return result


def source(tag, name):
    data = git("archive", "--format=tar", f"--prefix={name}/", tag)
    inventory(data, name)
    return data


def download(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        destination = urllib.parse.urlparse(response.url)
        if (
            destination.scheme != "https"
            or destination.hostname not in ("downloads.apache.org", "dlcdn.apache.org")
            or not destination.path.startswith("/incubator/casbin/")
        ):
            raise ValueError("Download redirected outside the project's approved ASF release area")
        return response.read()


def verify_signature(key_data, target, signature):
    with tempfile.TemporaryDirectory() as scratch:
        keyhome = Path(scratch) / "gnupg"
        keyhome.mkdir(mode=0o700)
        keys = Path(scratch) / "KEYS"
        keys.write_bytes(key_data)
        subprocess.run(["gpg", "--batch", "--homedir", str(keyhome), "--import", str(keys)], check=True)
        subprocess.run(["gpg", "--batch", "--homedir", str(keyhome), "--verify", str(signature), str(target)], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["meta", "archive", "verify"])
    parser.add_argument("tag")
    parser.add_argument("output", nargs="?", default="dist-release")
    args = parser.parse_args()
    version, rc, name = metadata(args.tag)
    if args.command == "meta":
        print(f"version={version}\nis_rc={str(rc).lower()}\nname={name}")
        return
    output = Path(args.output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Refusing to replace existing release files; choose an empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    expected = source(args.tag, name)
    filename = name + ".tar.gz"
    target = output / filename
    if args.command == "archive":
        if not rc:
            raise ValueError("Final releases must reuse approved ASF originals, not rebuild source archives")
        target.write_bytes(gzip.compress(expected, mtime=0))
        (output / (filename + ".sha512")).write_text(hashlib.sha512(target.read_bytes()).hexdigest() + "  " + filename + "\n", encoding="ascii")
    else:
        if rc:
            raise ValueError("An RC cannot enter final publication")
        url = f"{ASF_BASE}/{COMPONENT}-{version}-incubating/{filename}"
        for suffix in ("", ".sha512", ".asc"):
            (output / (filename + suffix)).write_bytes(download(url + suffix))
        checksum = (output / (filename + ".sha512")).read_text().split()
        if len(checksum) != 2 or checksum[1].lstrip("*") != filename:
            raise ValueError("Unexpected checksum record")
        if hashlib.sha512(target.read_bytes()).hexdigest() != checksum[0].lower():
            raise ValueError("SHA-512 mismatch")
        verify_signature(download(ASF_BASE + "/KEYS"), target, output / (filename + ".asc"))
        if inventory(target.read_bytes(), name) != inventory(expected, name):
            raise ValueError("Approved source contents/modes differ from the selected Git tag")
        # Build package registries only from the approved source, never a fresh checkout.
        with tarfile.open(target) as archive:
            archive.extractall(output / "source", filter="data")
    print(f"Verified {target}; {'local unsigned candidate' if rc else 'approved ASF original'}")


if __name__ == "__main__":
    main()
