
import json


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
        '| stackql-demo-bucket-01 | null           | null           |\n' + \
        '|------------------------|----------------|----------------|' 


def get_variables(
  sundry_config: str # a json string with arbitrary config 
) -> dict:
    """
    Robot variables.
    """
    sundry_config_dict: dict = json.loads(sundry_config)
    return {
        "sundry_config_dict": sundry_config_dict,
        "GCS_BUCKET_NAME": sundry_config_dict["GCS_BUCKET_NAME"],
        "GCP_PROJECT": sundry_config_dict["GCP_PROJECT"],
        "AWS_RECORD_SET_ID": sundry_config_dict["AWS_RECORD_SET_ID"],
        "AWS_RECORD_SET_REGION": sundry_config_dict["AWS_RECORD_SET_REGION"],

    }