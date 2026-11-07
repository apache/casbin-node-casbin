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

import contextlib
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release


class ReleaseSafetyTest(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd()
        self.directory = tempfile.TemporaryDirectory()
        os.chdir(self.directory.name)
        subprocess.run(["git", "init", "-q"], check=True)
        for key, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid")):
            subprocess.run(["git", "config", key, value], check=True)
        text = ('{"name":"%s","version":"1.2.3"}\n' % release.EXPECTED_PACKAGE) if release.MANIFEST.endswith("json") else ('[project]\nname="%s"\nversion="1.2.3"\n' % release.EXPECTED_PACKAGE)
        Path(release.MANIFEST).write_text(text, encoding="utf8")
        for filename in ("LICENSE", "NOTICE", "DISCLAIMER", "README.md"):
            Path(filename).write_text("Fixture for command safety, not a legal compliance assessment.\n", encoding="utf8")
        self.commit()
        for tag in ("v1.2.3", "v1.2.3-rc1"):
            subprocess.run(["git", "tag", tag], check=True)
        self.name = release.metadata("v1.2.3")[2]
        # A different gzip compression level proves verify preserves originals.
        self.original = gzip.compress(release.source("v1.2.3", self.name), compresslevel=1, mtime=0)

    def tearDown(self):
        os.chdir(self.previous)
        self.directory.cleanup()

    def commit(self):
        subprocess.run(["git", "add", "-A"], check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], check=True)

    def invoke(self, *args):
        with patch.object(sys, "argv", ["release.py", *args]), contextlib.redirect_stdout(io.StringIO()):
            release.main()

    def downloaded(self, url):
        if url.endswith("KEYS"):
            return b"MOCK KEY: cryptographic verification is covered by later real RC checks"
        if url.endswith(".sha512"):
            return (hashlib.sha512(self.original).hexdigest() + "  " + self.name + ".tar.gz\n").encode()
        if url.endswith(".asc"):
            return b"MOCK SIGNATURE"
        return self.original

    def test_rejects_legacy_package_identity(self):
        manifest = Path(release.MANIFEST)
        manifest.write_text(manifest.read_text().replace(release.EXPECTED_PACKAGE, "legacy-package"), encoding="utf8")
        self.commit()
        subprocess.run(["git", "tag", "v1.2.3-rc9"], check=True)
        with self.assertRaisesRegex(ValueError, "identity"):
            release.metadata("v1.2.3-rc9")

    def test_strict_tags(self):
        for tag in ("master", "v1", "v1.2.3-rc0", "v1.2.3-beta1", "v1.2.3-rc1/x", "v1.2.3 "):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.metadata(tag)

    def test_version_must_be_committed(self):
        subprocess.run(["git", "tag", "v1.2.4-rc1"], check=True)
        with self.assertRaises(ValueError):
            release.metadata("v1.2.4-rc1")

    def test_reproducible_candidate(self):
        self.invoke("archive", "v1.2.3-rc1", "one")
        self.invoke("archive", "v1.2.3-rc1", "two")
        filename = self.name + ".tar.gz"
        self.assertEqual((Path("one") / filename).read_bytes(), (Path("two") / filename).read_bytes())

    def test_refuses_overwrite(self):
        Path("existing").mkdir()
        Path("existing/sentinel").write_bytes(b"preserve")
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3-rc1", "existing")
        self.assertEqual(Path("existing/sentinel").read_bytes(), b"preserve")

    def test_final_cannot_be_rebuilt(self):
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3", "final")

    def test_rc_cannot_be_promoted(self):
        with self.assertRaises(ValueError), patch.object(release, "download") as download:
            self.invoke("verify", "v1.2.3-rc1", "promotion")
        download.assert_not_called()

    def test_missing_legal_file(self):
        Path("NOTICE").unlink()
        self.commit()
        subprocess.run(["git", "tag", "v1.2.3-rc2"], check=True)
        with self.assertRaises(ValueError):
            self.invoke("archive", "v1.2.3-rc2", "missing")

    def test_rejects_unsafe_archive_entries(self):
        for path, link in (("../escape", False), (self.name + "/../escape", False), (self.name + "/link", True)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                entry = tarfile.TarInfo(path)
                if link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "../../escape"
                archive.addfile(entry)
            with self.subTest(path=path), self.assertRaises(ValueError):
                release.inventory(buffer.getvalue(), self.name)

    def test_preserves_original_bytes_after_mock_verification(self):
        with patch.object(release, "download", side_effect=self.downloaded), patch.object(release, "verify_signature") as gpg:
            self.invoke("verify", "v1.2.3", "approved")
        self.assertEqual(gpg.call_count, 1)
        self.assertEqual((Path("approved") / (self.name + ".tar.gz")).read_bytes(), self.original)
        self.assertTrue((Path("approved/source") / self.name / release.MANIFEST).is_file())

    def test_checksum_failure_stops_before_gpg_and_build(self):
        def bad(url):
            return ("0" * 128 + "  " + self.name + ".tar.gz\n").encode() if url.endswith(".sha512") else self.downloaded(url)

        with patch.object(release, "download", side_effect=bad), patch.object(release, "verify_signature") as gpg:
            with self.assertRaises(ValueError):
                self.invoke("verify", "v1.2.3", "bad-checksum")
        gpg.assert_not_called()
        self.assertFalse(Path("bad-checksum/source").exists())

    def test_signature_failure_stops_before_build(self):
        with patch.object(release, "download", side_effect=self.downloaded):
            with patch.object(release, "verify_signature", side_effect=subprocess.CalledProcessError(1, "gpg")):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke("verify", "v1.2.3", "bad-signature")
        self.assertFalse(Path("bad-signature/source").exists())

    def test_different_approved_source_is_rejected(self):
        Path("README.md").write_text("Changed source\n", encoding="utf8")
        self.commit()
        subprocess.run(["git", "tag", "-f", "v1.2.3"], check=True, stdout=subprocess.DEVNULL)
        with patch.object(release, "download", side_effect=self.downloaded), patch.object(release, "verify_signature"):
            with self.assertRaises(ValueError):
                self.invoke("verify", "v1.2.3", "different-source")
        self.assertFalse(Path("different-source/source").exists())

    def npm_fixture(self, change=None):
        Path("lib").mkdir(exist_ok=True)
        Path("lib/index.js").write_bytes(b"exports.fixture = true;\n")
        Path(release.MANIFEST).write_text('{"name":"fixture","version":"1.2.3","license":"Apache-2.0","main":"lib/index.js"}', encoding="utf8")
        files = {name: Path(name).read_bytes() for name in (release.MANIFEST,"LICENSE","NOTICE","DISCLAIMER","README.md","lib/index.js")}
        if change:
            change(files)
        with tarfile.open("fixture.tgz", "w:gz") as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo("package/" + name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

    def test_npm_preserves_source_legal_and_entry_files(self):
        self.npm_fixture()
        release.check_npm("fixture.tgz")

    def test_npm_rejects_missing_built_file(self):
        self.npm_fixture(lambda files: files.pop("lib/index.js"))
        with self.assertRaises(ValueError):
            release.check_npm("fixture.tgz")

    def test_npm_rejects_changed_dependency_metadata(self):
        self.npm_fixture(lambda files: files.update({release.MANIFEST: b'{"name":"fixture","version":"9.9.9"}'}))
        with self.assertRaises(ValueError):
            release.check_npm("fixture.tgz")

    def test_npm_rejects_changed_legal_file(self):
        self.npm_fixture(lambda files: files.update({"LICENSE":b"wrong"}))
        with self.assertRaises(ValueError):
            release.check_npm("fixture.tgz")

    def test_npm_rejects_path_traversal(self):
        self.npm_fixture(lambda files: files.update({"../outside":b"unsafe"}))
        with self.assertRaises(ValueError):
            release.check_npm("fixture.tgz")


if __name__ == "__main__":
    unittest.main()
