import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).parents[1] / "scripts"


class ResultPathTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.research = self.root / "research"
        self.scripts = self.research / "scripts"
        self.attacks = self.research / "attacks"
        self.bin = self.root / "bin"
        for folder in (self.scripts, self.attacks, self.bin):
            folder.mkdir(parents=True)
        for name in ("run_all_attacks.sh", "collect_alerts_from_wazuh.sh"):
            shutil.copyfile(SCRIPTS / name, self.scripts / name)
            (self.scripts / name).chmod(0o755)
        (self.attacks / "01_stub.sh").write_text('#!/bin/bash\necho "harmless test scenario"\n')
        # The real collector runs against this fake transport, never a network.
        fake_curl = self.bin / "curl"
        fake_curl.write_text('''#!/bin/bash
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    printf '{"hits":{"hits":[]}}' > "$2"
    exit 0
  fi
  shift
done
exit 1
''')
        fake_curl.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        CURRENT_PHASE="1", COLLECT_IMMEDIATE="1",
                        WAZUH_INDEXER="https://stub.invalid", WAZUH_INDEXER_USER="test",
                        WAZUH_INDEXER_PASS="test")
        self.env.pop("RESULTS_DIR", None)
        self.env.pop("TARGET_IP", None)

    def run_scenario(self, setting, cwd, expected):
        if setting is not None:
            self.env["RESULTS_DIR"] = setting
        result = subprocess.run(["bash", str(self.scripts / "run_all_attacks.sh"), "127.0.0.1", "0"],
                                env=self.env, cwd=cwd, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("harmless test scenario", (expected / "phase1/logs-attacks/01_stub.log").read_text())
        self.assertTrue((expected / "phase1/alerts-from-wazuh/attack_01_alerts.json").is_file())

    def test_legacy_relative_setting_from_outside_project(self):
        self.run_scenario("../results", self.root, self.research / "results")
        self.assertFalse((self.root / "results").exists())

    def test_project_relative_setting_from_scripts(self):
        self.run_scenario("results", self.scripts, self.research / "results")
        self.assertFalse((self.attacks / "results").exists())

    def test_custom_relative_path_with_spaces(self):
        self.run_scenario("custom output", self.root, self.research / "custom output")

    def test_absolute_setting(self):
        destination = self.root / "absolute output"
        self.run_scenario(str(destination), self.root, destination)

    def test_default_setting(self):
        self.run_scenario(None, self.root, self.research / "results")

    def test_config_file_setting_matches_collector(self):
        (self.scripts / "config.env").write_text('RESULTS_DIR="../results"\n')
        self.run_scenario(None, self.root, self.research / "results")

    def test_missing_target_prints_usage_before_creating_results(self):
        result = subprocess.run(["bash", str(self.scripts / "run_all_attacks.sh")], env=self.env,
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertNotIn("unbound variable", result.stderr)
        self.assertFalse((self.research / "results").exists())


if __name__ == "__main__":
    unittest.main()
