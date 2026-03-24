"""
AWS helper utilities for resource enrichment, tagging lookups,
and common operations used across Lambda functions.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Clients (lazy-initialized)
# ---------------------------------------------------------------------------
_clients: dict[str, Any] = {}


def _get_client(service: str):
    if service not in _clients:
        _clients[service] = boto3.client(service)
    return _clients[service]


# ---------------------------------------------------------------------------
# Resource enrichment
# ---------------------------------------------------------------------------

def get_resource_tags(resource_arn: str) -> dict[str, str]:
    """Fetch tags for any taggable AWS resource."""
    try:
        client = _get_client("resourcegroupstaggingapi")
        resp = client.get_resources(ResourceARNList=[resource_arn])
        for mapping in resp.get("ResourceTagMappingList", []):
            return {t["Key"]: t["Value"] for t in mapping.get("Tags", [])}
    except ClientError as exc:
        logger.warning("Could not fetch tags for %s: %s", resource_arn, exc)
    return {}


def get_resource_details(resource_type: str, resource_id: str, region: str) -> dict:
    """
    Return enrichment metadata for a resource.
    Supports S3, EC2 security groups, IAM roles, and RDS instances.
    """
    enrichment: dict[str, Any] = {
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        if resource_type == "AwsS3Bucket":
            enrichment.update(_enrich_s3(resource_id))
        elif resource_type == "AwsEc2SecurityGroup":
            enrichment.update(_enrich_security_group(resource_id, region))
        elif resource_type == "AwsIamRole":
            enrichment.update(_enrich_iam_role(resource_id))
        elif resource_type == "AwsRdsDbInstance":
            enrichment.update(_enrich_rds(resource_id, region))
    except ClientError as exc:
        logger.warning("Enrichment failed for %s/%s: %s", resource_type, resource_id, exc)

    return enrichment


# ---------------------------------------------------------------------------
# Service-specific enrichment helpers
# ---------------------------------------------------------------------------

def _enrich_s3(bucket_name: str) -> dict:
    s3 = _get_client("s3")
    info: dict[str, Any] = {"bucket_name": bucket_name}

    # Public access block
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab.get("PublicAccessBlockConfiguration", {})
        info["public_access_block"] = config
        info["is_fully_blocked"] = all(config.values())
    except ClientError:
        info["is_fully_blocked"] = False

    # Encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        info["encryption_enabled"] = len(rules) > 0
        if rules:
            info["encryption_algorithm"] = (
                rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "unknown")
            )
    except ClientError:
        info["encryption_enabled"] = False

    # Versioning
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        info["versioning"] = ver.get("Status", "Disabled")
    except ClientError:
        info["versioning"] = "Unknown"

    return info


def _enrich_security_group(sg_id: str, region: str) -> dict:
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = resp["SecurityGroups"][0]

    open_to_world = []
    for rule in sg.get("IpPermissions", []):
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                open_to_world.append({
                    "protocol": rule.get("IpProtocol", "all"),
                    "from_port": rule.get("FromPort", 0),
                    "to_port": rule.get("ToPort", 65535),
                })

    return {
        "group_name": sg.get("GroupName"),
        "vpc_id": sg.get("VpcId"),
        "open_to_world_rules": open_to_world,
        "total_inbound_rules": len(sg.get("IpPermissions", [])),
        "total_outbound_rules": len(sg.get("IpPermissionsEgress", [])),
    }


def _enrich_iam_role(role_name: str) -> dict:
    iam = _get_client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]

    attached = iam.list_attached_role_policies(RoleName=role_name)
    inline = iam.list_role_policies(RoleName=role_name)

    has_admin = any(
        p["PolicyArn"].endswith("/AdministratorAccess")
        for p in attached.get("AttachedPolicies", [])
    )

    return {
        "role_name": role_name,
        "role_arn": role["Arn"],
        "create_date": role["CreateDate"].isoformat(),
        "attached_policies": [p["PolicyName"] for p in attached.get("AttachedPolicies", [])],
        "inline_policies": inline.get("PolicyNames", []),
        "has_admin_access": has_admin,
        "max_session_duration": role.get("MaxSessionDuration", 3600),
    }


def _enrich_rds(db_instance_id: str, region: str) -> dict:
    rds = boto3.client("rds", region_name=region)
    resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
    db = resp["DBInstances"][0]

    return {
        "db_instance_id": db_instance_id,
        "engine": db.get("Engine"),
        "engine_version": db.get("EngineVersion"),
        "publicly_accessible": db.get("PubliclyAccessible", False),
        "storage_encrypted": db.get("StorageEncrypted", False),
        "multi_az": db.get("MultiAZ", False),
        "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId"),
        "backup_retention_period": db.get("BackupRetentionPeriod", 0),
    }


# ---------------------------------------------------------------------------
# DynamoDB helpers
# ---------------------------------------------------------------------------

def store_finding(table_name: str, finding: dict) -> None:
    """Persist a processed finding to DynamoDB."""
    ddb = _get_client("dynamodb")
    ddb.put_item(
        TableName=table_name,
        Item=_to_dynamodb_item(finding),
    )


def get_finding_history(table_name: str, resource_id: str, limit: int = 20) -> list[dict]:
    """Retrieve past findings for a resource (newest first)."""
    ddb = _get_client("dynamodb")
    resp = ddb.query(
        TableName=table_name,
        KeyConditionExpression="resource_id = :rid",
        ExpressionAttributeValues={":rid": {"S": resource_id}},
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_from_dynamodb_item(i) for i in resp.get("Items", [])]


def _to_dynamodb_item(obj: dict) -> dict:
    """Naive Python dict → DynamoDB item conversion."""
    item = {}
    for k, v in obj.items():
        if isinstance(v, str):
            item[k] = {"S": v}
        elif isinstance(v, bool):
            item[k] = {"BOOL": v}
        elif isinstance(v, (int, float)):
            item[k] = {"N": str(v)}
        elif isinstance(v, list):
            item[k] = {"S": json.dumps(v)}
        elif isinstance(v, dict):
            item[k] = {"S": json.dumps(v)}
        elif v is None:
            item[k] = {"NULL": True}
    return item


def _from_dynamodb_item(item: dict) -> dict:
    """Naive DynamoDB item → Python dict conversion."""
    result = {}
    for k, v in item.items():
        if "S" in v:
            result[k] = v["S"]
        elif "N" in v:
            result[k] = float(v["N"]) if "." in v["N"] else int(v["N"])
        elif "BOOL" in v:
            result[k] = v["BOOL"]
        elif "NULL" in v:
            result[k] = None
    return result


# ---------------------------------------------------------------------------
# Notification helpers
# ---------------------------------------------------------------------------

def send_sns_notification(topic_arn: str, subject: str, message: str) -> str:
    """Publish a message to an SNS topic. Returns the MessageId."""
    sns = _get_client("sns")
    resp = sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=message,
    )
    return resp["MessageId"]
