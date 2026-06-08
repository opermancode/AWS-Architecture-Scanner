#!/usr/bin/env python3
"""
AWS Architecture Scanner
Scans all regions, discovers resources and their connections,
generates a visual HTML diagram + JSON report.
"""

import boto3
import json
import os
import sys
import argparse
from datetime import datetime
from botocore.exceptions import ClientError, NoRegionError
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
RESOURCE_TYPES = [
    "ec2", "vpc", "vpn", "rds", "s3", "lambda",
    "elbv2", "elb", "ecs", "eks", "igw",
    "nat", "subnet", "sg", "route_table",
    "cloudfront", "sns", "sqs", "dynamodb",
    "elasticache", "es", "redshift"
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def get_name_tag(tags):
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None

def short_id(resource_id):
    if not resource_id:
        return "unknown"
    return resource_id[-12:] if len(resource_id) > 12 else resource_id

def safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default

# ─────────────────────────────────────────────
# REGION SCANNER
# ─────────────────────────────────────────────
class RegionScanner:
    def __init__(self, session, region):
        self.session = session
        self.region = region
        self.resources = []
        self.connections = []

    def client(self, service):
        return self.session.client(service, region_name=self.region)

    def add(self, rtype, rid, name, meta=None, parent=None):
        r = {
            "id": rid,
            "type": rtype,
            "name": name or rid,
            "region": self.region,
            "meta": meta or {},
        }
        if parent:
            r["parent"] = parent
        self.resources.append(r)
        return rid

    def connect(self, src, dst, label=""):
        if src and dst and src != dst:
            self.connections.append({"from": src, "to": dst, "label": label})

    # ── VPCs ────────────────────────────────
    def scan_vpcs(self):
        try:
            ec2 = self.client("ec2")
            vpcs = ec2.describe_vpcs()["Vpcs"]
            for v in vpcs:
                vid = v["VpcId"]
                name = get_name_tag(v.get("Tags")) or vid
                self.add("vpc", vid, name, {
                    "cidr": v.get("CidrBlock"),
                    "default": v.get("IsDefault"),
                    "state": v.get("State")
                })
        except ClientError:
            pass

    # ── Subnets ─────────────────────────────
    def scan_subnets(self):
        try:
            ec2 = self.client("ec2")
            subnets = ec2.describe_subnets()["Subnets"]
            for s in subnets:
                sid = s["SubnetId"]
                name = get_name_tag(s.get("Tags")) or sid
                self.add("subnet", sid, name, {
                    "cidr": s.get("CidrBlock"),
                    "az": s.get("AvailabilityZone"),
                    "public": s.get("MapPublicIpOnLaunch")
                }, parent=s.get("VpcId"))
                self.connect(s.get("VpcId"), sid, "contains")
        except ClientError:
            pass

    # ── Internet Gateways ────────────────────
    def scan_igw(self):
        try:
            ec2 = self.client("ec2")
            igws = ec2.describe_internet_gateways()["InternetGateways"]
            for igw in igws:
                igw_id = igw["InternetGatewayId"]
                name = get_name_tag(igw.get("Tags")) or igw_id
                self.add("igw", igw_id, name, {})
                for att in igw.get("Attachments", []):
                    self.connect(att.get("VpcId"), igw_id, "internet")
        except ClientError:
            pass

    # ── NAT Gateways ─────────────────────────
    def scan_nat(self):
        try:
            ec2 = self.client("ec2")
            nats = ec2.describe_nat_gateways()["NatGateways"]
            for n in nats:
                if n.get("State") == "deleted":
                    continue
                nid = n["NatGatewayId"]
                name = get_name_tag(n.get("Tags")) or nid
                self.add("nat", nid, name, {
                    "state": n.get("State"),
                    "subnet": n.get("SubnetId")
                })
                self.connect(n.get("SubnetId"), nid, "nat")
                self.connect(n.get("VpcId"), nid, "contains")
        except ClientError:
            pass

    # ── Security Groups ──────────────────────
    def scan_security_groups(self):
        try:
            ec2 = self.client("ec2")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sgid = sg["GroupId"]
                name = sg.get("GroupName") or sgid
                self.add("sg", sgid, name, {
                    "description": sg.get("Description"),
                    "vpc": sg.get("VpcId")
                }, parent=sg.get("VpcId"))
        except ClientError:
            pass

    # ── EC2 Instances ────────────────────────
    def scan_ec2(self):
        try:
            ec2 = self.client("ec2")
            reservations = ec2.describe_instances()["Reservations"]
            for r in reservations:
                for inst in r["Instances"]:
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    iid = inst["InstanceId"]
                    name = get_name_tag(inst.get("Tags")) or iid
                    self.add("ec2", iid, name, {
                        "type": inst.get("InstanceType"),
                        "state": inst.get("State", {}).get("Name"),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "az": inst.get("Placement", {}).get("AvailabilityZone"),
                        "ami": inst.get("ImageId")
                    }, parent=inst.get("SubnetId") or inst.get("VpcId"))
                    self.connect(inst.get("SubnetId"), iid, "hosts")
                    self.connect(inst.get("VpcId"), iid, "contains")
                    for sg in inst.get("SecurityGroups", []):
                        self.connect(iid, sg.get("GroupId"), "sg")
        except ClientError:
            pass

    # ── VPN Connections ──────────────────────
    def scan_vpn(self):
        try:
            ec2 = self.client("ec2")
            vpns = ec2.describe_vpn_connections()["VpnConnections"]
            for v in vpns:
                if v.get("State") == "deleted":
                    continue
                vid = v["VpnConnectionId"]
                name = get_name_tag(v.get("Tags")) or vid
                tunnels = []
                for t in v.get("VgwTelemetry", []):
                    tunnels.append({
                        "ip": t.get("OutsideIpAddress"),
                        "status": t.get("Status"),
                        "last_change": str(t.get("LastStatusChange", ""))
                    })
                self.add("vpn", vid, name, {
                    "state": v.get("State"),
                    "type": v.get("Type"),
                    "tunnels": tunnels,
                    "cgw": v.get("CustomerGatewayId"),
                    "vgw": v.get("VpnGatewayId")
                })
                self.connect(v.get("VpnGatewayId"), vid, "vpn")
                self.connect(vid, v.get("CustomerGatewayId"), "to-onprem")
        except ClientError:
            pass

    # ── Customer Gateways ────────────────────
    def scan_cgw(self):
        try:
            ec2 = self.client("ec2")
            cgws = ec2.describe_customer_gateways()["CustomerGateways"]
            for c in cgws:
                if c.get("State") == "deleted":
                    continue
                cid = c["CustomerGatewayId"]
                name = get_name_tag(c.get("Tags")) or cid
                self.add("cgw", cid, name, {
                    "ip": c.get("IpAddress"),
                    "bgp_asn": c.get("BgpAsn"),
                    "state": c.get("State")
                })
        except ClientError:
            pass

    # ── Virtual Private Gateways ─────────────
    def scan_vgw(self):
        try:
            ec2 = self.client("ec2")
            vgws = ec2.describe_vpn_gateways()["VpnGateways"]
            for v in vgws:
                if v.get("State") == "deleted":
                    continue
                vid = v["VpnGatewayId"]
                name = get_name_tag(v.get("Tags")) or vid
                self.add("vgw", vid, name, {
                    "state": v.get("State"),
                    "type": v.get("Type")
                })
                for att in v.get("VpcAttachments", []):
                    self.connect(att.get("VpcId"), vid, "gateway")
        except ClientError:
            pass

    # ── RDS ──────────────────────────────────
    def scan_rds(self):
        try:
            rds = self.client("rds")
            dbs = rds.describe_db_instances()["DBInstances"]
            for db in dbs:
                did = db["DBInstanceIdentifier"]
                self.add("rds", did, did, {
                    "engine": db.get("Engine"),
                    "version": db.get("EngineVersion"),
                    "class": db.get("DBInstanceClass"),
                    "status": db.get("DBInstanceStatus"),
                    "multi_az": db.get("MultiAZ"),
                    "endpoint": db.get("Endpoint", {}).get("Address")
                }, parent=db.get("DBSubnetGroup", {}).get("VpcId"))
                vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
                self.connect(vpc_id, did, "database")
                for sg in db.get("VpcSecurityGroups", []):
                    self.connect(did, sg.get("VpcSecurityGroupId"), "sg")
        except ClientError:
            pass

    # ── S3 ───────────────────────────────────
    def scan_s3(self):
        if self.region != "us-east-1":
            return  # S3 is global, scan once
        try:
            s3 = self.client("s3")
            buckets = s3.list_buckets()["Buckets"]
            for b in buckets:
                name = b["Name"]
                location = safe(lambda: s3.get_bucket_location(Bucket=name)["LocationConstraint"] or "us-east-1", "unknown")
                self.add("s3", f"s3-{name}", name, {
                    "created": str(b.get("CreationDate", "")),
                    "region": location
                })
        except ClientError:
            pass

    # ── Lambda ───────────────────────────────
    def scan_lambda(self):
        try:
            lmb = self.client("lambda")
            paginator = lmb.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    fid = fn["FunctionArn"]
                    name = fn["FunctionName"]
                    vpc_config = fn.get("VpcConfig", {})
                    self.add("lambda", fid, name, {
                        "runtime": fn.get("Runtime"),
                        "memory": fn.get("MemorySize"),
                        "timeout": fn.get("Timeout"),
                        "handler": fn.get("Handler"),
                        "vpc": vpc_config.get("VpcId")
                    }, parent=vpc_config.get("VpcId"))
                    if vpc_config.get("VpcId"):
                        self.connect(vpc_config.get("VpcId"), fid, "lambda")
        except ClientError:
            pass

    # ── ELB (ALB/NLB) ───────────────────────
    def scan_elb(self):
        try:
            elb = self.client("elbv2")
            lbs = elb.describe_load_balancers()["LoadBalancers"]
            for lb in lbs:
                lid = lb["LoadBalancerArn"]
                name = lb["LoadBalancerName"]
                self.add("elb", lid, name, {
                    "type": lb.get("Type"),
                    "scheme": lb.get("Scheme"),
                    "state": lb.get("State", {}).get("Code"),
                    "dns": lb.get("DNSName"),
                    "vpc": lb.get("VpcId")
                }, parent=lb.get("VpcId"))
                self.connect(lb.get("VpcId"), lid, "load balancer")
        except ClientError:
            pass

    # ── ECS ──────────────────────────────────
    def scan_ecs(self):
        try:
            ecs = self.client("ecs")
            clusters = ecs.list_clusters()["clusterArns"]
            for arn in clusters:
                detail = ecs.describe_clusters(clusters=[arn])["clusters"]
                if not detail:
                    continue
                c = detail[0]
                cid = c["clusterArn"]
                name = c["clusterName"]
                self.add("ecs", cid, name, {
                    "status": c.get("status"),
                    "running_tasks": c.get("runningTasksCount"),
                    "active_services": c.get("activeServicesCount")
                })
        except ClientError:
            pass

    # ── EKS ──────────────────────────────────
    def scan_eks(self):
        try:
            eks = self.client("eks")
            clusters = eks.list_clusters()["clusters"]
            for name in clusters:
                detail = eks.describe_cluster(name=name)["cluster"]
                self.add("eks", f"eks-{name}", name, {
                    "status": detail.get("status"),
                    "version": detail.get("version"),
                    "vpc": detail.get("resourcesVpcConfig", {}).get("vpcId")
                }, parent=detail.get("resourcesVpcConfig", {}).get("vpcId"))
                vpc = detail.get("resourcesVpcConfig", {}).get("vpcId")
                if vpc:
                    self.connect(vpc, f"eks-{name}", "kubernetes")
        except ClientError:
            pass

    # ── DynamoDB ─────────────────────────────
    def scan_dynamodb(self):
        try:
            ddb = self.client("dynamodb")
            tables = ddb.list_tables()["TableNames"]
            for t in tables:
                detail = ddb.describe_table(TableName=t)["Table"]
                self.add("dynamodb", f"ddb-{t}", t, {
                    "status": detail.get("TableStatus"),
                    "items": detail.get("ItemCount"),
                    "size_bytes": detail.get("TableSizeBytes"),
                    "billing": detail.get("BillingModeSummary", {}).get("BillingMode")
                })
        except ClientError:
            pass

    # ── SNS ──────────────────────────────────
    def scan_sns(self):
        try:
            sns = self.client("sns")
            topics = sns.list_topics()["Topics"]
            for t in topics:
                arn = t["TopicArn"]
                name = arn.split(":")[-1]
                self.add("sns", arn, name, {"arn": arn})
        except ClientError:
            pass

    # ── SQS ──────────────────────────────────
    def scan_sqs(self):
        try:
            sqs = self.client("sqs")
            queues = sqs.list_queues().get("QueueUrls", [])
            for url in queues:
                name = url.split("/")[-1]
                self.add("sqs", f"sqs-{name}", name, {"url": url})
        except ClientError:
            pass

    # ── ElastiCache ──────────────────────────
    def scan_elasticache(self):
        try:
            ec = self.client("elasticache")
            clusters = ec.describe_cache_clusters()["CacheClusters"]
            for c in clusters:
                cid = c["CacheClusterId"]
                self.add("elasticache", cid, cid, {
                    "engine": c.get("Engine"),
                    "node_type": c.get("CacheNodeType"),
                    "status": c.get("CacheClusterStatus"),
                    "num_nodes": c.get("NumCacheNodes")
                })
        except ClientError:
            pass

    # ── CloudFront ───────────────────────────
    def scan_cloudfront(self):
        if self.region != "us-east-1":
            return  # CloudFront is global
        try:
            cf = self.client("cloudfront")
            dists = cf.list_distributions().get("DistributionList", {}).get("Items", [])
            for d in dists:
                did = d["Id"]
                name = d.get("Comment") or did
                self.add("cloudfront", did, name, {
                    "domain": d.get("DomainName"),
                    "status": d.get("Status"),
                    "enabled": d.get("Enabled")
                })
        except ClientError:
            pass

    # ── MAIN SCAN ────────────────────────────
    def scan(self):
        scanners = [
            self.scan_vpcs,
            self.scan_subnets,
            self.scan_igw,
            self.scan_nat,
            self.scan_security_groups,
            self.scan_cgw,
            self.scan_vgw,
            self.scan_vpn,
            self.scan_ec2,
            self.scan_rds,
            self.scan_s3,
            self.scan_lambda,
            self.scan_elb,
            self.scan_ecs,
            self.scan_eks,
            self.scan_dynamodb,
            self.scan_sns,
            self.scan_sqs,
            self.scan_elasticache,
            self.scan_cloudfront,
        ]
        for fn in scanners:
            try:
                fn()
            except Exception as e:
                pass
        return self.resources, self.connections


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
class AWSScanner:
    def __init__(self, access_key, secret_key, session_token=None):
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name="us-east-1"
        )

    def get_all_regions(self):
        try:
            ec2 = self.session.client("ec2", region_name="us-east-1")
            regions = ec2.describe_regions()["Regions"]
            return [r["RegionName"] for r in regions]
        except Exception as e:
            print(f"  ⚠️  Could not fetch regions: {e}")
            return ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]

    def has_resources(self, region):
        """Quick check if region has any EC2 or VPC resources"""
        try:
            ec2 = self.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs()["Vpcs"]
            # skip regions with only default VPC and no instances
            instances = ec2.describe_instances()["Reservations"]
            return len(vpcs) > 1 or len(instances) > 0
        except Exception:
            return False

    def scan(self):
        all_resources = []
        all_connections = []
        account_id = "unknown"

        try:
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account", "unknown")
            print(f"\n✅ Connected to AWS Account: {account_id}")
        except Exception as e:
            print(f"\n❌ Auth failed: {e}")
            sys.exit(1)

        print("\n🔍 Fetching all regions...")
        regions = self.get_all_regions()
        print(f"   Found {len(regions)} regions")

        print("\n🔍 Scanning regions for resources (skipping empty ones)...\n")

        active_regions = []
        for region in regions:
            sys.stdout.write(f"   Checking {region}... ")
            sys.stdout.flush()
            if self.has_resources(region):
                print("✅ Has resources")
                active_regions.append(region)
            else:
                print("⬜ Empty (skipping)")

        print(f"\n📦 Scanning {len(active_regions)} active regions in parallel...\n")

        def scan_region(region):
            scanner = RegionScanner(self.session, region)
            resources, connections = scanner.scan()
            print(f"   ✅ {region}: {len(resources)} resources, {len(connections)} connections")
            return resources, connections

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scan_region, r): r for r in active_regions}
            for future in as_completed(futures):
                try:
                    resources, connections = future.result()
                    all_resources.extend(resources)
                    all_connections.extend(connections)
                except Exception as e:
                    print(f"   ⚠️  Error: {e}")

        return {
            "account_id": account_id,
            "scanned_at": datetime.utcnow().isoformat(),
            "active_regions": active_regions,
            "total_resources": len(all_resources),
            "total_connections": len(all_connections),
            "resources": all_resources,
            "connections": all_connections
        }


# ─────────────────────────────────────────────
# HTML GENERATOR
# ─────────────────────────────────────────────
def generate_html(data, output_path):
    json_data = json.dumps(data)
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS Architecture — {data['account_id']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');

  :root {{
    --bg: #0a0e1a;
    --surface: #111827;
    --surface2: #1a2235;
    --border: #1e3a5f;
    --accent: #00d4ff;
    --accent2: #7c3aed;
    --accent3: #10b981;
    --warn: #f59e0b;
    --danger: #ef4444;
    --text: #e2e8f0;
    --muted: #64748b;
    --grid: rgba(0, 212, 255, 0.03);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    height: 100vh;
    overflow: hidden;
    background-image:
      linear-gradient(var(--grid) 1px, transparent 1px),
      linear-gradient(90deg, var(--grid) 1px, transparent 1px);
    background-size: 40px 40px;
  }}

  /* HEADER */
  #header {{
    position: fixed; top: 0; left: 0; right: 0; z-index: 100;
    background: rgba(10,14,26,0.95);
    border-bottom: 1px solid var(--border);
    backdrop-filter: blur(10px);
    padding: 12px 20px;
    display: flex; align-items: center; gap: 16px;
  }}
  #header h1 {{
    font-size: 18px; font-weight: 800; letter-spacing: -0.5px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    flex: 1;
  }}
  .badge {{
    padding: 4px 10px; border-radius: 6px; font-family: 'JetBrains Mono', monospace;
    font-size: 11px; font-weight: 600; border: 1px solid;
  }}
  .badge-blue {{ border-color: var(--accent); color: var(--accent); background: rgba(0,212,255,0.08); }}
  .badge-green {{ border-color: var(--accent3); color: var(--accent3); background: rgba(16,185,129,0.08); }}
  .badge-purple {{ border-color: var(--accent2); color: var(--accent2); background: rgba(124,58,237,0.08); }}

  /* SIDEBAR */
  #sidebar {{
    position: fixed; top: 53px; left: 0; bottom: 0; width: 260px; z-index: 90;
    background: rgba(17,24,39,0.97);
    border-right: 1px solid var(--border);
    backdrop-filter: blur(10px);
    overflow-y: auto;
    padding: 12px 0;
  }}
  #sidebar::-webkit-scrollbar {{ width: 4px; }}
  #sidebar::-webkit-scrollbar-track {{ background: transparent; }}
  #sidebar::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

  .sidebar-section {{ padding: 8px 16px 4px; }}
  .sidebar-label {{
    font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--muted); margin-bottom: 6px;
  }}
  .filter-btn {{
    display: flex; align-items: center; gap: 8px;
    width: 100%; padding: 6px 10px; border-radius: 6px;
    border: none; background: transparent; cursor: pointer;
    color: var(--text); font-family: 'Syne', sans-serif;
    font-size: 12px; font-weight: 600; text-align: left;
    transition: all 0.15s;
  }}
  .filter-btn:hover {{ background: var(--surface2); }}
  .filter-btn.active {{ background: var(--surface2); color: var(--accent); }}
  .filter-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
  .filter-count {{
    margin-left: auto; font-family: 'JetBrains Mono', monospace;
    font-size: 10px; color: var(--muted);
    background: var(--surface2); padding: 1px 6px; border-radius: 4px;
  }}

  /* CANVAS AREA */
  #canvas-area {{
    position: fixed; top: 53px; left: 260px; right: 0; bottom: 0;
    overflow: hidden; cursor: grab;
  }}
  #canvas-area:active {{ cursor: grabbing; }}
  #canvas {{
    position: absolute; top: 0; left: 0;
    transform-origin: 0 0;
  }}

  /* NODES */
  .node {{
    position: absolute;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 14px;
    min-width: 140px;
    max-width: 200px;
    cursor: pointer;
    transition: border-color 0.2s, box-shadow 0.2s, transform 0.1s;
    user-select: none;
  }}
  .node:hover {{
    border-color: var(--accent);
    box-shadow: 0 0 20px rgba(0,212,255,0.15);
    transform: translateY(-1px);
    z-index: 10 !important;
  }}
  .node.selected {{
    border-color: var(--accent);
    box-shadow: 0 0 30px rgba(0,212,255,0.25);
    z-index: 20 !important;
  }}
  .node-icon {{ font-size: 20px; margin-bottom: 4px; }}
  .node-name {{
    font-size: 12px; font-weight: 700; color: var(--text);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }}
  .node-type {{
    font-size: 10px; color: var(--muted); font-family: 'JetBrains Mono', monospace;
    margin-top: 2px;
  }}
  .node-region {{
    font-size: 9px; color: var(--muted); margin-top: 4px;
    display: flex; align-items: center; gap: 4px;
  }}
  .status-dot {{ width: 6px; height: 6px; border-radius: 50%; }}
  .status-up {{ background: var(--accent3); }}
  .status-down {{ background: var(--danger); }}
  .status-unknown {{ background: var(--muted); }}

  /* EDGE SVG */
  #edges-svg {{
    position: absolute; top: 0; left: 0;
    pointer-events: none; overflow: visible;
  }}
  .edge {{ stroke: var(--border); stroke-width: 1.5; fill: none; opacity: 0.6; }}
  .edge-label {{ font-size: 9px; fill: var(--muted); font-family: 'JetBrains Mono', monospace; }}

  /* DETAIL PANEL */
  #detail-panel {{
    position: fixed; top: 53px; right: 0; bottom: 0; width: 300px;
    background: rgba(17,24,39,0.97);
    border-left: 1px solid var(--border);
    backdrop-filter: blur(10px);
    transform: translateX(100%);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    z-index: 95; overflow-y: auto; padding: 20px;
  }}
  #detail-panel.open {{ transform: translateX(0); }}
  #detail-panel::-webkit-scrollbar {{ width: 4px; }}
  #detail-panel::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 2px; }}

  .detail-type {{
    font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--accent); margin-bottom: 8px;
  }}
  .detail-name {{
    font-size: 18px; font-weight: 800; margin-bottom: 16px;
    line-height: 1.2;
  }}
  .detail-row {{
    display: flex; justify-content: space-between; align-items: flex-start;
    padding: 8px 0; border-bottom: 1px solid var(--surface2);
    gap: 12px;
  }}
  .detail-key {{
    font-size: 11px; color: var(--muted); flex-shrink: 0;
    font-family: 'JetBrains Mono', monospace;
  }}
  .detail-val {{
    font-size: 11px; color: var(--text); text-align: right;
    word-break: break-all; font-family: 'JetBrains Mono', monospace;
  }}
  .detail-connections {{ margin-top: 16px; }}
  .detail-connections h4 {{
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted); margin-bottom: 8px;
  }}
  .conn-item {{
    display: flex; align-items: center; gap: 8px;
    padding: 6px 8px; border-radius: 6px; margin-bottom: 4px;
    background: var(--surface2); font-size: 11px; cursor: pointer;
    transition: background 0.15s;
  }}
  .conn-item:hover {{ background: var(--border); }}

  /* CONTROLS */
  #controls {{
    position: fixed; bottom: 24px; right: 24px; z-index: 100;
    display: flex; flex-direction: column; gap: 6px;
  }}
  .ctrl-btn {{
    width: 36px; height: 36px; border-radius: 8px;
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); cursor: pointer; font-size: 16px;
    display: flex; align-items: center; justify-content: center;
    transition: all 0.15s; font-family: monospace;
  }}
  .ctrl-btn:hover {{ border-color: var(--accent); color: var(--accent); }}

  /* SEARCH */
  #search-wrap {{
    position: fixed; top: 65px; left: 270px; z-index: 95;
  }}
  #search {{
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: 8px 14px; border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
    width: 220px; outline: none; transition: border-color 0.15s;
  }}
  #search:focus {{ border-color: var(--accent); }}
  #search::placeholder {{ color: var(--muted); }}

  /* STATS BAR */
  #stats-bar {{
    position: fixed; bottom: 0; left: 260px; right: 0; z-index: 90;
    background: rgba(10,14,26,0.9); border-top: 1px solid var(--border);
    padding: 6px 16px; display: flex; gap: 24px; align-items: center;
    font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted);
  }}
  .stat-item {{ display: flex; gap: 6px; align-items: center; }}
  .stat-val {{ color: var(--accent); font-weight: 600; }}

  /* REGION GROUPS */
  .region-group {{
    position: absolute;
    border: 1px dashed rgba(0,212,255,0.15);
    border-radius: 16px;
    background: rgba(0,212,255,0.02);
  }}
  .region-label {{
    position: absolute; top: -10px; left: 16px;
    font-size: 10px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: rgba(0,212,255,0.4);
    background: var(--bg); padding: 0 6px;
  }}

  /* LOADING */
  #loading {{
    position: fixed; inset: 0; z-index: 999;
    background: var(--bg); display: flex; flex-direction: column;
    align-items: center; justify-content: center; gap: 16px;
  }}
  .loader {{
    width: 48px; height: 48px; border-radius: 50%;
    border: 3px solid var(--surface2);
    border-top-color: var(--accent);
    animation: spin 0.8s linear infinite;
  }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .loader-text {{ font-size: 14px; color: var(--muted); }}

  .close-btn {{
    position: absolute; top: 16px; right: 16px;
    background: transparent; border: none; color: var(--muted);
    cursor: pointer; font-size: 18px; transition: color 0.15s;
  }}
  .close-btn:hover {{ color: var(--text); }}
</style>
</head>
<body>

<div id="loading">
  <div class="loader"></div>
  <div class="loader-text">Building architecture diagram...</div>
</div>

<div id="header">
  <h1>☁️ AWS Architecture Map</h1>
  <span class="badge badge-blue" id="hdr-account">Account: loading...</span>
  <span class="badge badge-green" id="hdr-resources">0 resources</span>
  <span class="badge badge-purple" id="hdr-regions">0 regions</span>
  <span style="font-size:11px;color:var(--muted);font-family:monospace" id="hdr-time"></span>
</div>

<div id="sidebar">
  <div class="sidebar-section">
    <div class="sidebar-label">Filter by Type</div>
    <button class="filter-btn active" onclick="filterType('all')">
      <span class="filter-dot" style="background:var(--accent)"></span>
      All Resources
      <span class="filter-count" id="cnt-all">0</span>
    </button>
  </div>
  <div class="sidebar-section" id="type-filters"></div>
  <div class="sidebar-section" style="margin-top:8px">
    <div class="sidebar-label">Filter by Region</div>
    <div id="region-filters"></div>
  </div>
</div>

<input id="search" placeholder="🔍 Search resources..." oninput="doSearch(this.value)">

<div id="canvas-area">
  <div id="canvas">
    <svg id="edges-svg"></svg>
  </div>
</div>

<div id="detail-panel">
  <button class="close-btn" onclick="closeDetail()">✕</button>
  <div id="detail-content"></div>
</div>

<div id="controls">
  <button class="ctrl-btn" onclick="zoom(0.2)" title="Zoom in">+</button>
  <button class="ctrl-btn" onclick="zoom(-0.2)" title="Zoom out">−</button>
  <button class="ctrl-btn" onclick="resetView()" title="Reset view">⊙</button>
  <button class="ctrl-btn" onclick="exportJSON()" title="Export JSON">↓</button>
</div>

<div id="stats-bar">
  <div class="stat-item">Resources: <span class="stat-val" id="stat-res">0</span></div>
  <div class="stat-item">Connections: <span class="stat-val" id="stat-conn">0</span></div>
  <div class="stat-item">Regions: <span class="stat-val" id="stat-reg">0</span></div>
  <div class="stat-item">Visible: <span class="stat-val" id="stat-vis">0</span></div>
</div>

<script>
const RAW_DATA = {json_data};

// ── ICONS & COLORS ──────────────────────────
const TYPE_CONFIG = {{
  vpc:          {{ icon: '🏗️',  color: '#3b82f6', label: 'VPC' }},
  subnet:       {{ icon: '🔷',  color: '#6366f1', label: 'Subnet' }},
  igw:          {{ icon: '🌐',  color: '#06b6d4', label: 'Internet GW' }},
  nat:          {{ icon: '🔀',  color: '#0ea5e9', label: 'NAT GW' }},
  sg:           {{ icon: '🛡️',  color: '#8b5cf6', label: 'Security Group' }},
  ec2:          {{ icon: '💻',  color: '#10b981', label: 'EC2' }},
  rds:          {{ icon: '🗄️',  color: '#f59e0b', label: 'RDS' }},
  s3:           {{ icon: '🪣',  color: '#ef4444', label: 'S3' }},
  lambda:       {{ icon: 'λ',   color: '#f97316', label: 'Lambda' }},
  elb:          {{ icon: '⚖️',  color: '#14b8a6', label: 'Load Balancer' }},
  ecs:          {{ icon: '📦',  color: '#84cc16', label: 'ECS' }},
  eks:          {{ icon: '☸️',  color: '#06b6d4', label: 'EKS' }},
  dynamodb:     {{ icon: '⚡',  color: '#a78bfa', label: 'DynamoDB' }},
  sns:          {{ icon: '📣',  color: '#fb923c', label: 'SNS' }},
  sqs:          {{ icon: '📬',  color: '#fbbf24', label: 'SQS' }},
  elasticache:  {{ icon: '⚙️',  color: '#34d399', label: 'ElastiCache' }},
  cloudfront:   {{ icon: '🚀',  color: '#60a5fa', label: 'CloudFront' }},
  vpn:          {{ icon: '🔐',  color: '#c084fc', label: 'VPN' }},
  cgw:          {{ icon: '🏢',  color: '#94a3b8', label: 'Customer GW' }},
  vgw:          {{ icon: '🔌',  color: '#7dd3fc', label: 'Virtual GW' }},
}};

function typeConf(t) {{
  return TYPE_CONFIG[t] || {{ icon: '📌', color: '#64748b', label: t.toUpperCase() }};
}}

// ── STATE ────────────────────────────────────
let scale = 1, panX = 20, panY = 20;
let isDragging = false, dragStart = {{ x: 0, y: 0 }}, panStart = {{ x: 0, y: 0 }};
let selectedNode = null;
let activeTypeFilter = 'all';
let activeRegionFilter = 'all';
let searchTerm = '';
let nodePositions = {{}};
let draggingNode = null;
let nodeDragStart = {{ x: 0, y: 0, nx: 0, ny: 0 }};

// ── LAYOUT ───────────────────────────────────
function layoutNodes(resources) {{
  const byRegion = {{}};
  resources.forEach(r => {{
    if (!byRegion[r.region]) byRegion[r.region] = [];
    byRegion[r.region].push(r);
  }});

  let globalX = 60;
  const positions = {{}};

  Object.entries(byRegion).forEach(([region, nodes]) => {{
    // group by type within region
    const byType = {{}};
    nodes.forEach(n => {{
      if (!byType[n.type]) byType[n.type] = [];
      byType[n.type].push(n);
    }});

    let regionY = 60;
    const regionStartX = globalX;

    Object.entries(byType).forEach(([type, typeNodes]) => {{
      typeNodes.forEach((node, i) => {{
        positions[node.id] = {{
          x: globalX + (i % 4) * 200,
          y: regionY + Math.floor(i / 4) * 130
        }};
      }});
      const rows = Math.ceil(typeNodes.length / 4);
      regionY += rows * 130 + 20;
    }});

    const regionWidth = Math.min(nodes.length, 4) * 200 + 100;
    globalX += regionWidth + 80;
  }});

  return positions;
}}

// ── RENDER ───────────────────────────────────
function getVisibleResources() {{
  return RAW_DATA.resources.filter(r => {{
    if (activeTypeFilter !== 'all' && r.type !== activeTypeFilter) return false;
    if (activeRegionFilter !== 'all' && r.region !== activeRegionFilter) return false;
    if (searchTerm) {{
      const q = searchTerm.toLowerCase();
      return r.name.toLowerCase().includes(q) ||
             r.id.toLowerCase().includes(q) ||
             r.type.toLowerCase().includes(q) ||
             r.region.toLowerCase().includes(q);
    }}
    return true;
  }});
}}

function render() {{
  const canvas = document.getElementById('canvas');
  const svg = document.getElementById('edges-svg');

  // Clear nodes (keep svg)
  Array.from(canvas.children).forEach(c => {{
    if (c.id !== 'edges-svg') c.remove();
  }});
  svg.innerHTML = '';

  const visible = getVisibleResources();
  const visibleIds = new Set(visible.map(r => r.id));

  // Update positions for new nodes
  visible.forEach(r => {{
    if (!nodePositions[r.id]) {{
      nodePositions[r.id] = {{ x: 100 + Math.random() * 800, y: 100 + Math.random() * 600 }};
    }}
  }});

  // Draw edges first
  const visibleConns = RAW_DATA.connections.filter(c => visibleIds.has(c.from) && visibleIds.has(c.to));
  visibleConns.forEach(conn => {{
    const from = nodePositions[conn.from];
    const to = nodePositions[conn.to];
    if (!from || !to) return;

    const fx = from.x + 100, fy = from.y + 45;
    const tx = to.x + 100, ty = to.y + 45;
    const mx = (fx + tx) / 2, my = (fy + ty) / 2 - 30;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('class', 'edge');
    path.setAttribute('d', `M ${{fx}} ${{fy}} Q ${{mx}} ${{my}} ${{tx}} ${{ty}}`);
    svg.appendChild(path);

    if (conn.label) {{
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', mx);
      text.setAttribute('y', my - 4);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('class', 'edge-label');
      text.textContent = conn.label;
      svg.appendChild(text);
    }}
  }});

  // Draw nodes
  visible.forEach(r => {{
    const pos = nodePositions[r.id];
    const conf = typeConf(r.type);
    const node = document.createElement('div');
    node.className = 'node' + (selectedNode === r.id ? ' selected' : '');
    node.id = `node-${{r.id}}`;
    node.style.left = pos.x + 'px';
    node.style.top = pos.y + 'px';
    node.style.zIndex = selectedNode === r.id ? 20 : 1;
    node.style.borderColor = selectedNode === r.id ? conf.color : '';

    const status = r.meta?.state || r.meta?.status || '';
    const isUp = ['running','available','active','up','enabled','Up'].includes(status);
    const isDown = ['stopped','down','Down','failed','error'].includes(status);
    const statusClass = isUp ? 'status-up' : isDown ? 'status-down' : 'status-unknown';

    node.innerHTML = `
      <div class="node-icon">${{conf.icon}}</div>
      <div class="node-name" title="${{r.name}}">${{r.name}}</div>
      <div class="node-type">${{conf.label}}</div>
      <div class="node-region">
        <span class="status-dot ${{statusClass}}"></span>
        ${{r.region}}
      </div>
    `;

    // Click to select
    node.addEventListener('click', (e) => {{
      e.stopPropagation();
      selectedNode = r.id;
      showDetail(r);
      render();
    }});

    // Drag node
    node.addEventListener('mousedown', (e) => {{
      if (e.button !== 0) return;
      e.stopPropagation();
      draggingNode = r.id;
      nodeDragStart = {{
        x: e.clientX, y: e.clientY,
        nx: nodePositions[r.id].x,
        ny: nodePositions[r.id].y
      }};
    }});

    canvas.appendChild(node);
  }});

  // Update stats
  document.getElementById('stat-vis').textContent = visible.length;
  document.getElementById('stat-res').textContent = RAW_DATA.resources.length;
  document.getElementById('stat-conn').textContent = RAW_DATA.connections.length;
  document.getElementById('stat-reg').textContent = RAW_DATA.active_regions?.length || 0;
}};

// ── DETAIL PANEL ─────────────────────────────
function showDetail(r) {{
  const panel = document.getElementById('detail-panel');
  const content = document.getElementById('detail-content');
  const conf = typeConf(r.type);

  const conns = RAW_DATA.connections.filter(c => c.from === r.id || c.to === r.id);

  let metaHtml = '';
  if (r.meta) {{
    Object.entries(r.meta).forEach(([k, v]) => {{
      if (v === null || v === undefined || v === '') return;
      if (Array.isArray(v)) {{
        v.forEach((item, i) => {{
          if (typeof item === 'object') {{
            Object.entries(item).forEach(([ik, iv]) => {{
              if (iv) metaHtml += `<div class="detail-row"><span class="detail-key">tunnel${{i+1}}.${{ik}}</span><span class="detail-val">${{iv}}</span></div>`;
            }});
          }}
        }});
        return;
      }}
      metaHtml += `<div class="detail-row"><span class="detail-key">${{k}}</span><span class="detail-val">${{v}}</span></div>`;
    }});
  }}

  let connHtml = '';
  conns.slice(0, 10).forEach(c => {{
    const otherId = c.from === r.id ? c.to : c.from;
    const other = RAW_DATA.resources.find(x => x.id === otherId);
    const dir = c.from === r.id ? '→' : '←';
    const otherConf = typeConf(other?.type || '');
    connHtml += `<div class="conn-item" onclick="selectNode('${{otherId}}')">${{dir}} ${{otherConf.icon}} ${{other?.name || otherId}} <span style="color:var(--muted);margin-left:auto;font-size:9px">${{c.label}}</span></div>`;
  }});

  content.innerHTML = `
    <div class="detail-type">${{conf.icon}} ${{conf.label}}</div>
    <div class="detail-name">${{r.name}}</div>
    <div class="detail-row"><span class="detail-key">id</span><span class="detail-val">${{r.id}}</span></div>
    <div class="detail-row"><span class="detail-key">region</span><span class="detail-val">${{r.region}}</span></div>
    ${{metaHtml}}
    ${{conns.length ? `<div class="detail-connections"><h4>Connections (${{conns.length}})</h4>${{connHtml}}</div>` : ''}}
  `;

  panel.classList.add('open');
}}

function closeDetail() {{
  document.getElementById('detail-panel').classList.remove('open');
  selectedNode = null;
  render();
}}

function selectNode(id) {{
  const r = RAW_DATA.resources.find(x => x.id === id);
  if (r) {{ selectedNode = id; showDetail(r); render(); }}
}}

// ── FILTERS ──────────────────────────────────
function buildFilters() {{
  const typeCounts = {{}};
  RAW_DATA.resources.forEach(r => {{
    typeCounts[r.type] = (typeCounts[r.type] || 0) + 1;
  }});
  document.getElementById('cnt-all').textContent = RAW_DATA.resources.length;

  const typeEl = document.getElementById('type-filters');
  Object.entries(typeCounts).sort((a,b) => b[1]-a[1]).forEach(([type, count]) => {{
    const conf = typeConf(type);
    const btn = document.createElement('button');
    btn.className = 'filter-btn';
    btn.innerHTML = `<span class="filter-dot" style="background:${{conf.color}}"></span>${{conf.label}}<span class="filter-count">${{count}}</span>`;
    btn.onclick = () => filterType(type);
    typeEl.appendChild(btn);
  }});

  const regionEl = document.getElementById('region-filters');
  const regions = [...new Set(RAW_DATA.resources.map(r => r.region))].sort();
  regions.forEach(region => {{
    const count = RAW_DATA.resources.filter(r => r.region === region).length;
    const btn = document.createElement('button');
    btn.className = 'filter-btn';
    btn.innerHTML = `<span class="filter-dot" style="background:var(--accent3)"></span>${{region}}<span class="filter-count">${{count}}</span>`;
    btn.onclick = () => filterRegion(region);
    regionEl.appendChild(btn);
  }});
}}

function filterType(type) {{
  activeTypeFilter = type;
  document.querySelectorAll('#type-filters .filter-btn, .filter-btn:first-of-type').forEach(b => b.classList.remove('active'));
  event.target.closest('.filter-btn').classList.add('active');
  render();
}}

function filterRegion(region) {{
  activeRegionFilter = activeRegionFilter === region ? 'all' : region;
  render();
}}

function doSearch(val) {{
  searchTerm = val;
  render();
}}

// ── PAN & ZOOM ───────────────────────────────
function applyTransform() {{
  document.getElementById('canvas').style.transform = `translate(${{panX}}px, ${{panY}}px) scale(${{scale}})`;
}}

function zoom(delta) {{
  scale = Math.max(0.2, Math.min(3, scale + delta));
  applyTransform();
}}

function resetView() {{
  scale = 0.8; panX = 20; panY = 20;
  applyTransform();
}}

// ── CANVAS DRAG ──────────────────────────────
const canvasArea = document.getElementById('canvas-area');

canvasArea.addEventListener('mousedown', (e) => {{
  if (draggingNode) return;
  isDragging = true;
  dragStart = {{ x: e.clientX, y: e.clientY }};
  panStart = {{ x: panX, y: panY }};
}});

window.addEventListener('mousemove', (e) => {{
  if (draggingNode) {{
    const dx = (e.clientX - nodeDragStart.x) / scale;
    const dy = (e.clientY - nodeDragStart.y) / scale;
    nodePositions[draggingNode] = {{
      x: nodeDragStart.nx + dx,
      y: nodeDragStart.ny + dy
    }};
    render();
    return;
  }}
  if (!isDragging) return;
  panX = panStart.x + (e.clientX - dragStart.x);
  panY = panStart.y + (e.clientY - dragStart.y);
  applyTransform();
}});

window.addEventListener('mouseup', () => {{
  isDragging = false;
  draggingNode = null;
}});

canvasArea.addEventListener('wheel', (e) => {{
  e.preventDefault();
  zoom(e.deltaY > 0 ? -0.1 : 0.1);
}}, {{ passive: false }});

canvasArea.addEventListener('click', (e) => {{
  if (e.target === canvasArea || e.target === document.getElementById('canvas')) {{
    closeDetail();
  }}
}});

// ── EXPORT ───────────────────────────────────
function exportJSON() {{
  const blob = new Blob([JSON.stringify(RAW_DATA, null, 2)], {{type:'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `aws-architecture-${{RAW_DATA.account_id}}.json`;
  a.click();
}}

// ── INIT ─────────────────────────────────────
window.addEventListener('load', () => {{
  document.getElementById('hdr-account').textContent = 'Account: ' + RAW_DATA.account_id;
  document.getElementById('hdr-resources').textContent = RAW_DATA.total_resources + ' resources';
  document.getElementById('hdr-regions').textContent = (RAW_DATA.active_regions?.length || 0) + ' regions';
  document.getElementById('hdr-time').textContent = 'Scanned: ' + new Date(RAW_DATA.scanned_at).toLocaleString();

  // Auto layout
  nodePositions = layoutNodes(RAW_DATA.resources);

  buildFilters();
  render();
  resetView();
  document.getElementById('loading').style.display = 'none';
}});
</script>
</body>
</html>"""

    with open(output_path, 'w') as f:
        f.write(html)
    print(f"\n✅ HTML diagram saved: {output_path}")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AWS Architecture Scanner — scans all regions and generates visual diagram + JSON report"
    )
    parser.add_argument("--access-key", "-a", required=True, help="AWS Access Key ID")
    parser.add_argument("--secret-key", "-s", required=True, help="AWS Secret Access Key")
    parser.add_argument("--session-token", "-t", default=None, help="AWS Session Token (optional, for temp credentials)")
    parser.add_argument("--output", "-o", default="aws-architecture", help="Output file prefix (default: aws-architecture)")
    args = parser.parse_args()

    print("=" * 60)
    print("  AWS Architecture Scanner")
    print("=" * 60)

    scanner = AWSScanner(args.access_key, args.secret_key, args.session_token)
    data = scanner.scan()

    # Save JSON report
    json_path = f"{args.output}-report.json"
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n✅ JSON report saved: {json_path}")

    # Save HTML diagram
    html_path = f"{args.output}-diagram.html"
    generate_html(data, html_path)

    print("\n" + "=" * 60)
    print(f"  ✅ Scan Complete!")
    print(f"  📊 Total Resources : {data['total_resources']}")
    print(f"  🔗 Total Connections: {data['total_connections']}")
    print(f"  🌍 Active Regions  : {len(data['active_regions'])}")
    print(f"  📁 JSON Report     : {json_path}")
    print(f"  🌐 HTML Diagram    : {html_path}")
    print("=" * 60)
    print(f"\n  Open {html_path} in your browser to view the diagram!\n")


if __name__ == "__main__":
    main()
