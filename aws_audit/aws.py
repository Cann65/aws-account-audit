from __future__ import annotations

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.utils import log


def session(profile: str | None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def client(ses: boto3.Session, service: str, region: str | None = None):
    boto_cfg = BotoConfig(retries={"max_attempts": 8, "mode": "standard"})
    return ses.client(service, region_name=region, config=boto_cfg)


def get_account_id(ses: boto3.Session) -> str:
    try:
        sts = client(ses, "sts")
        return sts.get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as e:
        log().warning("Could not fetch account id via STS: %s", e)
        return "unknown"


def list_regions(ses: boto3.Session) -> list[str]:
    try:
        ec2 = client(ses, "ec2")
        resp = ec2.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in resp.get("Regions", [])]
    except (ClientError, BotoCoreError) as e:
        log().warning("Could not list regions; falling back to default region: %s", e)
        return []
