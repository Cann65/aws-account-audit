from unittest.mock import patch

import boto3
from botocore.stub import Stubber
from moto import mock_aws

from aws_audit.checks.ec2 import check_ec2_open_admin_ports
from aws_audit.checks.iam import check_iam_users_without_mfa
from aws_audit.checks.s3 import check_s3_public_access_block


@mock_aws
def test_iam_user_without_mfa_finding():
    ses = boto3.Session(region_name="us-east-1")
    iam = ses.client("iam")
    iam.create_user(UserName="alice")

    res = check_iam_users_without_mfa(ses)
    assert len(res.findings) == 1
    assert res.findings[0].resource_id == "alice"


@mock_aws
def test_ec2_open_admin_ports_finding():
    ses = boto3.Session(region_name="us-east-1")
    ec2 = ses.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="test-sg", Description="test", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    res = check_ec2_open_admin_ports(ses, region="us-east-1")
    assert any("0.0.0.0/0" in f.detail for f in res.findings)


@mock_aws
def test_s3_account_public_access_block_missing():
    ses = boto3.Session(region_name="us-east-1")
    s3control_client = ses.client("s3control", region_name="us-east-1")
    sts_client = ses.client("sts", region_name="us-east-1")

    s3_stub = Stubber(s3control_client)
    s3_stub.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        service_message="no config",
        http_status_code=404,
    )
    s3_stub.activate()

    sts_stub = Stubber(sts_client)
    sts_stub.add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
            "UserId": "AIDTEST",
        },
    )
    sts_stub.activate()

    def fake_client(_ses, service, region=None):
        if service == "s3control":
            return s3control_client
        if service == "sts":
            return sts_client
        raise ValueError(f"unexpected service {service}")

    with patch("aws_audit.checks.s3.client", side_effect=fake_client):
        res = check_s3_public_access_block(ses)

    assert any("Public Access Block not configured" in f.title for f in res.findings)

    s3_stub.deactivate()
    sts_stub.deactivate()
