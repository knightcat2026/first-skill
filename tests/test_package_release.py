"""Publishing must never scoop up local phone reports, APKs or repository metadata."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location("package_release", Path(__file__).resolve().parents[1] / "tools" / "package_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phone-guard-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "项目 空格"
        self.root.mkdir()
        for name in release.FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source: " + name, encoding="utf-8")

    def test_only_allowlisted_sources_and_reproducible_archive(self):
        for name in ("private/audit.json", "phone.xml", "app.apk", ".git/config", "other.txt"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("SYNTHETIC PRIVATE CONTENT", encoding="utf-8")
        first = self.base / "first.zip"
        second = self.base / "second.zip"
        one = release.build_release(self.root, first)
        two = release.build_release(self.root, second)
        self.assertEqual(one["sha256"], two["sha256"])
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(set(archive.namelist()), {release.PREFIX + "/" + f for f in release.FILES})
            self.assertTrue(all(b"SYNTHETIC PRIVATE CONTENT" not in archive.read(n) for n in archive.namelist()))

    def test_missing_source_fails_before_creating_archive(self):
        (self.root / release.FILES[0]).unlink()
        output = self.base / "missing.zip"
        with self.assertRaises(ValueError):
            release.build_release(self.root, output)
        self.assertFalse(output.exists())

    def test_existing_output_and_in_repository_output_refused(self):
        outside = self.base / "existing.zip"
        outside.write_bytes(b"keep existing bytes")
        with self.assertRaises(FileExistsError):
            release.build_release(self.root, outside)
        self.assertEqual(outside.read_bytes(), b"keep existing bytes")
        with self.assertRaises(ValueError):
            release.build_release(self.root, self.root / "release.zip")


if __name__ == "__main__":
    unittest.main()
