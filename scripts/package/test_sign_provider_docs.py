import os
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("sign-provider-docs.py")


class SigningPipelineTests(unittest.TestCase):
    def test_embedded_signatures_and_subprocess_failure(self):
        with patch.dict(os.environ, {"PROVIDERS": "[]", "STACKQL_SIGNING_KID": "test"}):
            namespace = runpy.run_path(str(SCRIPT))
            with patch("subprocess.run") as run:
                namespace["sign_file"]("provider.yaml", "signed.yaml")
                self.assertEqual(
                    run.call_args.args[0][1:],
                    ["sign-doc", "-kid", "test", "-out", "signed.yaml", "provider.yaml"],
                )
                self.assertTrue(run.call_args.kwargs["check"])
                run.side_effect = subprocess.CalledProcessError(1, "pqsig")
                with self.assertRaises(subprocess.CalledProcessError):
                    namespace["sign_file"]("provider.yaml", "signed.yaml")

    def test_provider_and_all_services_are_signed_without_sidecars(self):
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as root:
            try:
                os.chdir(root)
                source = Path("providers/src/example/v1")
                (source / "services").mkdir(parents=True)
                (source / "provider.yaml").write_text("name: example\n", encoding="utf-8")
                (source / "services/one.yaml").write_text("openapi: 3.0.3\n", encoding="utf-8")
                (source / "services/two.yaml").write_text("openapi: 3.0.3\n", encoding="utf-8")
                with patch.dict(os.environ, {
                    "PROVIDERS": '[{"provider":"example","provider_dir":"example","source_version":"v1","target_version":"v2"}]',
                    "STACKQL_SIGNING_KID": "test",
                }), patch("subprocess.run") as run:
                    runpy.run_path(str(SCRIPT))
                    outputs = {call.args[0][-2] for call in run.call_args_list}
                    self.assertEqual(outputs, {
                        "signed/providers/src/example/v2/provider.yaml",
                        "signed/providers/src/example/v2/services/one.yaml",
                        "signed/providers/src/example/v2/services/two.yaml",
                    })
            finally:
                os.chdir(original)
