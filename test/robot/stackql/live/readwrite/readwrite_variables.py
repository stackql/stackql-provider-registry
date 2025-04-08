
import json

import os

from copy import deepcopy

_REPOSITORY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".."))
_CORE_REPOSITORY_ROOT = os.path.abspath(os.path.join(_REPOSITORY_ROOT, "stackql-core"))
_REGISTRY_PATH = os.path.abspath(os.path.join(_REPOSITORY_ROOT, "providers"))
_REGISTRY_NO_VERIFY_CFG_STR = f'{{ "url": "file://{_REGISTRY_PATH}", "verifyConfig": {{ "nopVerify": true }} }}'

_EMPTY_GCS_BUCKET_CHECK = """|------|----------------|----------------|
| name | softDeleteTime | hardDeleteTime |
|------|----------------|----------------|"""

def _get_expected_gcs_bucket_check(
    gcs_bucket_name: str,
    gcp_project: str
) -> str:
    """
    Expected GCS bucket check.
    """
    return '' + \
        '|------------------------|----------------|----------------|\n' + \
        '|          name          | softDeleteTime | hardDeleteTime |\n' + \
        '|------------------------|----------------|----------------|\n' + \
        '| stackql-demo-bucket-02 | null           | null           |\n' + \
        '|------------------------|----------------|----------------|' 


def get_variables(
  sundry_config: str # a json string with arbitrary config 
) -> dict:
    """
    Robot variables.
    """
    sundry_config_dict: dict = json.loads(sundry_config)
    adornment = deepcopy(sundry_config_dict)
    base_rv = {
        "sundry_config_dict": adornment,
        "GCS_BUCKET_NAME": sundry_config_dict["GCS_BUCKET_NAME"],
        "REPOSITORY_ROOT": _REPOSITORY_ROOT,
        "registry_path": _REGISTRY_PATH,
        "CORE_REPOSITORY_ROOT": _CORE_REPOSITORY_ROOT,
        "GCP_PROJECT": sundry_config_dict["GCP_PROJECT"],
        "EXPECTED_GCS_BUCKET_CHECK": _get_expected_gcs_bucket_check(
            sundry_config_dict["GCS_BUCKET_NAME"],
            sundry_config_dict["GCP_PROJECT"]
        ),
        "EXPECTED_EMPTY_GCS_BUCKET_CHECK": _EMPTY_GCS_BUCKET_CHECK,
        # "REGISTRY_NO_VERIFY_CFG_STR": _REGISTRY_NO_VERIFY_CFG_STR,
    }
    for k, v in base_rv.items():
        sundry_config_dict[k] = v
    return sundry_config_dict