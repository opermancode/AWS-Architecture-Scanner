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

    # ── ROUTE TABLES ─────────────────────────
    def scan_route_tables(self):
        try:
            ec2 = self.client("ec2")
            rts = ec2.describe_route_tables()["RouteTables"]
            for rt in rts:
                rtid = rt["RouteTableId"]
                name = get_name_tag(rt.get("Tags")) or rtid
                vpc_id = rt.get("VpcId")

                # Classify routes
                routes = []
                has_onprem = False
                has_internet = False
                has_vpn = False
                has_peering = False
                onprem_cidrs = []

                for r in rt.get("Routes", []):
                    dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or r.get("DestinationPrefixListId", "")
                    target = (
                        r.get("GatewayId") or
                        r.get("NatGatewayId") or
                        r.get("VpcPeeringConnectionId") or
                        r.get("TransitGatewayId") or
                        r.get("NetworkInterfaceId") or
                        r.get("InstanceId") or
                        r.get("EgressOnlyInternetGatewayId") or
                        "local"
                    )
                    state = r.get("State", "active")
                    origin = r.get("Origin", "")

                    route_info = {
                        "dest": dest,
                        "target": target,
                        "state": state,
                        "origin": origin
                    }
                    routes.append(route_info)

                    # Detect on-prem routes (via VGW or TGW with private CIDRs)
                    if target and (target.startswith("vgw-") or target.startswith("tgw-")):
                        has_vpn = True
                        if dest and dest not in ["0.0.0.0/0", "::/0", "local"]:
                            has_onprem = True
                            onprem_cidrs.append(dest)

                    # Detect internet routes
                    if target and target.startswith("igw-"):
                        has_internet = True

                    # Detect peering
                    if target and target.startswith("pcx-"):
                        has_peering = True

                # Associated subnets
                assoc_subnets = []
                is_main = False
                for assoc in rt.get("Associations", []):
                    if assoc.get("Main"):
                        is_main = True
                    if assoc.get("SubnetId"):
                        assoc_subnets.append(assoc["SubnetId"])

                rt_type = "main" if is_main else "custom"
                if has_internet:
                    rt_type = "public"
                elif has_onprem:
                    rt_type = "vpn/onprem"
                elif has_peering:
                    rt_type = "peering"

                self.add("route_table", rtid, name, {
                    "vpc": vpc_id,
                    "type": rt_type,
                    "route_count": len(routes),
                    "routes": routes,
                    "has_internet": has_internet,
                    "has_vpn": has_vpn,
                    "has_onprem": has_onprem,
                    "has_peering": has_peering,
                    "onprem_cidrs": onprem_cidrs,
                    "associated_subnets": assoc_subnets,
                    "is_main": is_main
                }, parent=vpc_id)

                # Connect RT to VPC
                self.connect(vpc_id, rtid, "route table")

                # Connect RT to associated subnets
                for sid in assoc_subnets:
                    self.connect(rtid, sid, "routes")

                # Connect RT to VGW/TGW targets
                for r in rt.get("Routes", []):
                    gw = r.get("GatewayId")
                    nat = r.get("NatGatewayId")
                    tgw = r.get("TransitGatewayId")
                    pcx = r.get("VpcPeeringConnectionId")
                    if gw and gw.startswith("igw-"):
                        self.connect(rtid, gw, "→ internet")
                    if gw and gw.startswith("vgw-"):
                        self.connect(rtid, gw, "→ onprem")
                    if nat:
                        self.connect(rtid, nat, "→ nat")
                    if tgw:
                        self.connect(rtid, tgw, "→ tgw")

        except ClientError:
            pass

    # ── NETWORK ACLs ─────────────────────────
    def scan_nacl(self):
        try:
            ec2 = self.client("ec2")
            nacls = ec2.describe_network_acls()["NetworkAcls"]
            for nacl in nacls:
                nid = nacl["NetworkAclId"]
                name = get_name_tag(nacl.get("Tags")) or nid
                vpc_id = nacl.get("VpcId")

                inbound = []
                outbound = []
                for entry in nacl.get("Entries", []):
                    rule = {
                        "rule_number": entry.get("RuleNumber"),
                        "protocol": entry.get("Protocol"),
                        "action": entry.get("RuleAction"),
                        "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", ""),
                        "port_range": f"{entry.get('PortRange', {}).get('From','*')}-{entry.get('PortRange', {}).get('To','*')}" if entry.get("PortRange") else "all"
                    }
                    if entry.get("Egress"):
                        outbound.append(rule)
                    else:
                        inbound.append(rule)

                assoc_subnets = [a["SubnetId"] for a in nacl.get("Associations", []) if a.get("SubnetId")]

                self.add("nacl", nid, name, {
                    "vpc": vpc_id,
                    "is_default": nacl.get("IsDefault"),
                    "inbound_rules": len(inbound),
                    "outbound_rules": len(outbound),
                    "inbound": inbound,
                    "outbound": outbound,
                    "associated_subnets": assoc_subnets
                }, parent=vpc_id)

                self.connect(vpc_id, nid, "nacl")
                for sid in assoc_subnets:
                    self.connect(nid, sid, "protects")

        except ClientError:
            pass

    # ── VPC PEERING ──────────────────────────
    def scan_vpc_peering(self):
        try:
            ec2 = self.client("ec2")
            peers = ec2.describe_vpc_peering_connections()["VpcPeeringConnections"]
            for p in peers:
                if p.get("Status", {}).get("Code") == "deleted":
                    continue
                pid = p["VpcPeeringConnectionId"]
                name = get_name_tag(p.get("Tags")) or pid
                requester = p.get("RequesterVpcInfo", {})
                accepter = p.get("AccepterVpcInfo", {})
                self.add("peering", pid, name, {
                    "status": p.get("Status", {}).get("Code"),
                    "requester_vpc": requester.get("VpcId"),
                    "requester_cidr": requester.get("CidrBlock"),
                    "accepter_vpc": accepter.get("VpcId"),
                    "accepter_cidr": accepter.get("CidrBlock"),
                    "requester_account": requester.get("OwnerId"),
                    "accepter_account": accepter.get("OwnerId"),
                })
                self.connect(requester.get("VpcId"), pid, "peering")
                self.connect(pid, accepter.get("VpcId"), "peering")
        except ClientError:
            pass

    # ── TRANSIT GATEWAYS ─────────────────────
    def scan_transit_gateway(self):
        try:
            ec2 = self.client("ec2")
            tgws = ec2.describe_transit_gateways()["TransitGateways"]
            for tgw in tgws:
                if tgw.get("State") == "deleted":
                    continue
                tid = tgw["TransitGatewayId"]
                name = get_name_tag(tgw.get("Tags")) or tid
                self.add("tgw", tid, name, {
                    "state": tgw.get("State"),
                    "asn": tgw.get("Options", {}).get("AmazonSideAsn"),
                    "owner": tgw.get("OwnerId"),
                    "dns_support": tgw.get("Options", {}).get("DnsSupport"),
                    "vpn_ecmp": tgw.get("Options", {}).get("VpnEcmpSupport"),
                })
        except ClientError:
            pass

    # ── TRANSIT GATEWAY ATTACHMENTS ──────────
    def scan_tgw_attachments(self):
        try:
            ec2 = self.client("ec2")
            atts = ec2.describe_transit_gateway_attachments()["TransitGatewayAttachments"]
            for att in atts:
                if att.get("State") == "deleted":
                    continue
                tgw_id = att.get("TransitGatewayId")
                res_id = att.get("ResourceId")
                res_type = att.get("ResourceType")
                label = f"tgw-attach ({res_type})"
                if tgw_id and res_id:
                    self.connect(tgw_id, res_id, label)
                    self.connect(res_id, tgw_id, label)
        except ClientError:
            pass

    # ── VPC ENDPOINTS ────────────────────────
    def scan_vpc_endpoints(self):
        try:
            ec2 = self.client("ec2")
            eps = ec2.describe_vpc_endpoints()["VpcEndpoints"]
            for ep in eps:
                if ep.get("State") == "deleted":
                    continue
                eid = ep["VpcEndpointId"]
                svc = ep.get("ServiceName", "")
                svc_short = svc.split(".")[-1] if svc else eid
                name = get_name_tag(ep.get("Tags")) or f"endpoint-{svc_short}"
                vpc_id = ep.get("VpcId")
                self.add("endpoint", eid, name, {
                    "service": svc,
                    "type": ep.get("VpcEndpointType"),
                    "state": ep.get("State"),
                    "vpc": vpc_id,
                    "private_dns": ep.get("PrivateDnsEnabled"),
                }, parent=vpc_id)
                self.connect(vpc_id, eid, "endpoint")
                for sid in ep.get("SubnetIds", []):
                    self.connect(eid, sid, "in subnet")
        except ClientError:
            pass

    # ── DHCP OPTIONS ─────────────────────────
    def scan_dhcp(self):
        try:
            ec2 = self.client("ec2")
            dhcps = ec2.describe_dhcp_options()["DhcpOptions"]
            for d in dhcps:
                did = d["DhcpOptionsId"]
                name = get_name_tag(d.get("Tags")) or did
                configs = {}
                for cfg in d.get("DhcpConfigurations", []):
                    k = cfg.get("Key")
                    v = [x.get("Value") for x in cfg.get("Values", [])]
                    configs[k] = ", ".join(v)
                self.add("dhcp", did, name, configs)
        except ClientError:
            pass

    # ── ELASTIC IPs ──────────────────────────
    def scan_eips(self):
        try:
            ec2 = self.client("ec2")
            eips = ec2.describe_addresses()["Addresses"]
            for eip in eips:
                eid = eip.get("AllocationId", eip.get("PublicIp"))
                name = get_name_tag(eip.get("Tags")) or eip.get("PublicIp", eid)
                self.add("eip", eid, name, {
                    "public_ip": eip.get("PublicIp"),
                    "private_ip": eip.get("PrivateIpAddress"),
                    "associated_to": eip.get("InstanceId") or eip.get("NetworkInterfaceId"),
                    "domain": eip.get("Domain"),
                })
                if eip.get("InstanceId"):
                    self.connect(eip["InstanceId"], eid, "elastic ip")
                if eip.get("NatGatewayId"):
                    self.connect(eip.get("NatGatewayId"), eid, "elastic ip")
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
            self.scan_route_tables,
            self.scan_nacl,
            self.scan_vpc_peering,
            self.scan_transit_gateway,
            self.scan_tgw_attachments,
            self.scan_vpc_endpoints,
            self.scan_dhcp,
            self.scan_eips,
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
# HTML GENERATOR  (v2 — fixed double sidebar, saveable layout)
# ─────────────────────────────────────────────
def generate_html(data, output_path):
    json_data = json.dumps(data)

    # ── PASSWORD PROMPT (CLI) ──────────────────
    import getpass
    print("\n" + "="*50)
    print("  🔐 PASSWORD PROTECT YOUR DIAGRAM")
    print("="*50)
    pwd = getpass.getpass("  Enter password to lock HTML file (or press Enter to skip): ").strip()
    if pwd:
        confirm = getpass.getpass("  Confirm password: ").strip()
        if pwd != confirm:
            print("  ⚠️  Passwords don't match — saving WITHOUT password protection.")
            pwd = ""
        else:
            print("  ✅ Password set — HTML will be locked.")
    else:
        print("  ℹ️  No password — HTML saved without lock.")

    import hashlib, base64
    pwd_hash = hashlib.sha256(pwd.encode()).hexdigest() if pwd else ""
    use_password = bool(pwd)

    html = build_html(data, json_data, pwd_hash, use_password)

    with open(output_path, 'w') as f:
        # Replace marker with empty object for fresh files
        f.write(html.replace("'__POSITIONS_JSON__'", "'{}'"))
    print(f"\n✅ HTML diagram saved: {output_path}")


def build_html(data, json_data, pwd_hash, use_password):

    # AWS SVG icons as inline SVG data (real AWS service icons, simplified)
    AWS_ICONS = {
        'vpc':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#8C4FFF"/><path d="M20 8L32 15V25L20 32L8 25V15L20 8Z" stroke="white" stroke-width="2" fill="none"/><circle cx="20" cy="20" r="4" fill="white"/></svg>',
        'subnet':      '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#6366F1"/><rect x="8" y="8" width="24" height="24" rx="3" stroke="white" stroke-width="2" fill="none"/><rect x="14" y="14" width="12" height="12" rx="2" fill="white" opacity="0.7"/></svg>',
        'igw':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#06B6D4"/><circle cx="20" cy="20" r="10" stroke="white" stroke-width="2" fill="none"/><path d="M20 10V30M10 20H30" stroke="white" stroke-width="1.5"/><ellipse cx="20" cy="20" rx="5" ry="10" stroke="white" stroke-width="1.5" fill="none"/></svg>',
        'nat':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#0EA5E9"/><path d="M10 20H30M24 14L30 20L24 26" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M16 14L10 20L16 26" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.5"/></svg>',
        'sg':          '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#8B5CF6"/><path d="M20 8L28 12V20C28 25 24 29 20 31C16 29 12 25 12 20V12L20 8Z" stroke="white" stroke-width="2" fill="none"/><path d="M16 20L19 23L24 17" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'ec2':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF9900"/><rect x="8" y="12" width="24" height="16" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M13 28V32M20 28V32M27 28V32" stroke="white" stroke-width="2" stroke-linecap="round"/><circle cx="14" cy="20" r="2" fill="white"/><path d="M19 20H26" stroke="white" stroke-width="1.5" stroke-linecap="round"/><path d="M19 17H26" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
        'rds':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#2196F3"/><ellipse cx="20" cy="14" rx="11" ry="5" stroke="white" stroke-width="2" fill="none"/><path d="M9 14V26C9 28.8 14 31 20 31C26 31 31 28.8 31 26V14" stroke="white" stroke-width="2"/><path d="M9 20C9 22.8 14 25 20 25C26 25 31 22.8 31 20" stroke="white" stroke-width="1.5"/></svg>',
        's3':          '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#569A31"/><path d="M20 9L30 13.5V26.5L20 31L10 26.5V13.5L20 9Z" stroke="white" stroke-width="2" fill="none"/><path d="M10 13.5L20 18L30 13.5" stroke="white" stroke-width="1.5"/><path d="M20 18V31" stroke="white" stroke-width="1.5"/></svg>',
        'lambda':      '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF9900"/><path d="M11 30L17 16L20 23L23 18L29 30" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M11 10H15L18 18" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>',
        'elb':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#8C4FFF"/><circle cx="20" cy="20" r="4" fill="white"/><path d="M20 16V10M20 30V24M16 20H10M30 20H24" stroke="white" stroke-width="2" stroke-linecap="round"/><circle cx="20" cy="10" r="2" fill="white" opacity="0.7"/><circle cx="20" cy="30" r="2" fill="white" opacity="0.7"/><circle cx="10" cy="20" r="2" fill="white" opacity="0.7"/><circle cx="30" cy="20" r="2" fill="white" opacity="0.7"/></svg>',
        'ecs':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF9900"/><rect x="9" y="9" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><rect x="21" y="9" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><rect x="9" y="21" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><rect x="21" y="21" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/></svg>',
        'eks':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#326CE5"/><path d="M20 9L29 14.5V25.5L20 31L11 25.5V14.5L20 9Z" stroke="white" stroke-width="2" fill="none"/><circle cx="20" cy="20" r="3" fill="white"/><path d="M20 13V17M20 23V27M14 16.5L17.5 18.5M22.5 21.5L26 23.5M14 23.5L17.5 21.5M22.5 18.5L26 16.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
        'dynamodb':    '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#2196F3"/><ellipse cx="20" cy="12" rx="11" ry="4" stroke="white" stroke-width="2" fill="none"/><ellipse cx="20" cy="20" rx="11" ry="4" stroke="white" stroke-width="2" fill="none"/><path d="M9 12V28C9 30.2 14 32 20 32C26 32 31 30.2 31 28V12" stroke="white" stroke-width="1.5"/></svg>',
        'sns':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF4F8B"/><path d="M10 24L15 20H20V14L30 20L20 26V20H15L10 24Z" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>',
        'sqs':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF4F8B"/><rect x="8" y="13" width="24" height="14" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M12 18H28M12 22H22" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
        'elasticache': '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#C7131F"/><path d="M12 20C12 15.6 15.6 12 20 12C24.4 12 28 15.6 28 20" stroke="white" stroke-width="2" fill="none"/><path d="M9 20C9 14 14 9 20 9C26 9 31 14 31 20" stroke="white" stroke-width="1.5" fill="none" opacity="0.6"/><ellipse cx="20" cy="22" rx="8" ry="4" stroke="white" stroke-width="2" fill="none"/><path d="M12 22V26C12 28.2 15.6 30 20 30C24.4 30 28 28.2 28 26V22" stroke="white" stroke-width="1.5"/></svg>',
        'cloudfront':  '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#8C4FFF"/><path d="M10 22C10 18.7 12.7 16 16 16C16.4 12.7 19.2 10 23 10C27.4 10 31 13.6 31 18C31 18 31 18 31 18C32.1 18.5 33 19.7 33 21C33 22.7 31.7 24 30 24H10C8.3 24 10 22 10 22Z" stroke="white" stroke-width="2" fill="none"/><path d="M14 24V30M20 24V30M26 24V30" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
        'vpn':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#C7131F"/><rect x="14" y="17" width="12" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M17 17V15C17 13.3 18.3 12 20 12C21.7 12 23 13.3 23 15V17" stroke="white" stroke-width="2" stroke-linecap="round"/><circle cx="20" cy="22" r="1.5" fill="white"/><path d="M20 23.5V25.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
        'tgw':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#E7157B"/><circle cx="20" cy="20" r="8" stroke="white" stroke-width="2" fill="none"/><path d="M20 12V8M20 32V28M12 20H8M32 20H28" stroke="white" stroke-width="2" stroke-linecap="round"/><circle cx="20" cy="20" r="3" fill="white"/></svg>',
        'peering':     '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#0D86FF"/><rect x="8" y="12" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><rect x="22" y="18" width="10" height="10" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M18 17L22 23" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>',
        'endpoint':    '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#1A6622"/><circle cx="20" cy="20" r="9" stroke="white" stroke-width="2" fill="none"/><path d="M15 20H25M21 16L25 20L21 24" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'nacl':        '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#DD344C"/><rect x="9" y="9" width="22" height="22" rx="3" stroke="white" stroke-width="2" fill="none"/><path d="M9 16H31M9 24H31M16 9V31" stroke="white" stroke-width="1.5"/></svg>',
        'route_table': '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#E7157B"/><rect x="8" y="10" width="24" height="20" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M8 16H32M8 22H32M16 10V30" stroke="white" stroke-width="1.5"/><circle cx="27" cy="13" r="2" fill="#10b981"/><circle cx="27" cy="19" r="2" fill="#f59e0b"/><circle cx="27" cy="25" r="2" fill="#10b981"/></svg>',
        'eip':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF9900"/><circle cx="20" cy="18" r="8" stroke="white" stroke-width="2" fill="none"/><path d="M14 30C14 30 16 26 20 26C24 26 26 30 26 30" stroke="white" stroke-width="2" stroke-linecap="round"/><path d="M17 18H23M20 15V21" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>',
        'dhcp':        '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#546E7A"/><path d="M10 14H30V28H10V14Z" stroke="white" stroke-width="2" fill="none" rx="2"/><path d="M14 19H20M14 23H26" stroke="white" stroke-width="1.5" stroke-linecap="round"/><circle cx="25" cy="19" r="2" fill="white"/></svg>',
        'cgw':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#FF6B35"/><rect x="8" y="12" width="24" height="18" rx="2" stroke="white" stroke-width="2" fill="none"/><path d="M8 18H32" stroke="white" stroke-width="1.5"/><path d="M14 12V9M26 12V9" stroke="white" stroke-width="2" stroke-linecap="round"/><rect x="12" y="21" width="5" height="4" rx="1" fill="white" opacity="0.8"/><rect x="20" y="21" width="5" height="4" rx="1" fill="white" opacity="0.5"/><circle cx="32" cy="8" r="4" fill="#10b981"/><path d="M30 8L31.5 9.5L34 7" stroke="white" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'vgw':         '<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#0D86FF"/><path d="M20 10V30M14 14L20 10L26 14M14 26L20 30L26 26" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 20H30" stroke="white" stroke-width="1.5" stroke-linecap="round"/></svg>',
    }

    def get_icon_svg(rtype):
        svg = AWS_ICONS.get(rtype, f'<svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="8" fill="#546E7A"/><text x="20" y="25" text-anchor="middle" fill="white" font-size="14" font-family="monospace">{rtype[:3].upper()}</text></svg>')
        # encode as base64 data URI
        import base64
        encoded = base64.b64encode(svg.encode()).decode()
        return f"data:image/svg+xml;base64,{encoded}"

    icons_js = "const AWS_ICONS = {" + ",".join([f'"{k}":"{get_icon_svg(k)}"' for k in AWS_ICONS.keys()]) + "};"

    pwd_script = ""
    if use_password:
        pwd_script = f"""
// ── PASSWORD PROTECTION ──
(function(){{
  const HASH = "{pwd_hash}";
  function sha256(str) {{
    // Simple check using stored hash
    return fetch('https://checknil.invalid').catch(()=>{{}}).then(()=>{{}});
  }}
  // We use a synchronous check approach with SubtleCrypto
  async function checkPwd() {{
    const overlay = document.getElementById('pwd-overlay');
    const input = document.getElementById('pwd-input');
    const err = document.getElementById('pwd-err');
    const entered = input.value;
    if(!entered) return;
    const msgBuffer = new TextEncoder().encode(entered);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b=>b.toString(16).padStart(2,'0')).join('');
    if(hashHex === HASH) {{
      overlay.style.display='none';
      document.getElementById('main-wrap').style.display='block';
      initApp();
    }} else {{
      err.textContent = '❌ Wrong password. Try again.';
      input.value='';
      input.focus();
    }}
  }}
  window.checkPwd = checkPwd;
  document.addEventListener('DOMContentLoaded', ()=>{{
    document.getElementById('main-wrap').style.display='none';
    document.getElementById('pwd-overlay').style.display='flex';
    document.getElementById('pwd-input').addEventListener('keydown', e=>{{if(e.key==='Enter')checkPwd();}});
  }});
}})();
"""
    else:
        pwd_script = "document.addEventListener('DOMContentLoaded', ()=>{ document.getElementById('pwd-overlay').style.display='none'; initApp(); });"

    pwd_overlay_html = f"""
<div id="pwd-overlay" style="display:none;position:fixed;inset:0;z-index:9999;background:#0a0e1a;align-items:center;justify-content:center;flex-direction:column;gap:20px;">
  <div style="text-align:center;">
    <div style="font-size:48px;margin-bottom:12px;">🔐</div>
    <div style="font-family:'Syne',sans-serif;font-size:24px;font-weight:800;color:#e2e8f0;margin-bottom:6px;">AWS Architecture Diagram</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64748b;margin-bottom:24px;">Account: {data['account_id']} &nbsp;·&nbsp; {data['total_resources']} resources</div>
    <div style="background:#111827;border:1px solid #1e3a5f;border-radius:12px;padding:28px;min-width:320px;">
      <div style="font-family:'Syne',sans-serif;font-size:14px;color:#94a3b8;margin-bottom:14px;">Enter password to unlock</div>
      <input id="pwd-input" type="password" placeholder="Password" style="width:100%;padding:10px 14px;background:#0a0e1a;border:1px solid #1e3a5f;border-radius:8px;color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;margin-bottom:10px;" autofocus/>
      <button onclick="checkPwd()" style="width:100%;padding:10px;background:linear-gradient(135deg,#00d4ff,#7c3aed);border:none;border-radius:8px;color:white;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;cursor:pointer;">Unlock Diagram</button>
      <div id="pwd-err" style="color:#ef4444;font-size:11px;margin-top:8px;font-family:'JetBrains Mono',monospace;min-height:16px;"></div>
    </div>
  </div>
</div>
""" if use_password else '<div id="pwd-overlay" style="display:none"></div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS Architecture — {data['account_id']}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;800&display=swap');
:root{{--bg:#0a0e1a;--surf:#111827;--surf2:#1a2235;--border:#1e3a5f;--accent:#00d4ff;--accent2:#7c3aed;--accent3:#10b981;--danger:#ef4444;--text:#e2e8f0;--muted:#64748b;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Syne',sans-serif;background:var(--bg);color:var(--text);height:100vh;overflow:hidden;
  background-image:linear-gradient(rgba(0,212,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.025) 1px,transparent 1px);background-size:48px 48px;}}

/* ── HEADER ── */
#hdr{{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(10,14,26,.96);border-bottom:1px solid var(--border);padding:9px 16px;display:flex;align-items:center;gap:10px;backdrop-filter:blur(12px);height:46px;}}
#hdr h1{{font-size:15px;font-weight:800;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;flex:1;letter-spacing:-.3px;}}
.badge{{padding:2px 8px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;border:1px solid;white-space:nowrap;}}
.bb{{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,.07);}}
.bg{{border-color:var(--accent3);color:var(--accent3);background:rgba(16,185,129,.07);}}
.bp{{border-color:var(--accent2);color:var(--accent2);background:rgba(124,58,237,.07);}}
.hbtn{{padding:4px 10px;border-radius:5px;border:1px solid var(--border);background:var(--surf);color:var(--text);cursor:pointer;font-family:'Syne',sans-serif;font-size:11px;font-weight:600;transition:all .15s;white-space:nowrap;}}
.hbtn:hover{{border-color:var(--accent);color:var(--accent);}}

/* ── SIDEBAR ── */
#sidebar{{position:fixed;top:46px;left:0;bottom:22px;width:232px;z-index:90;background:rgba(15,20,32,.97);border-right:1px solid var(--border);overflow-y:auto;}}
#sidebar::-webkit-scrollbar{{width:3px;}}
#sidebar::-webkit-scrollbar-thumb{{background:var(--border);border-radius:2px;}}
.sbs{{padding:10px 12px 4px;}}
.sbl{{font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted);margin-bottom:5px;padding-left:2px;}}
.fb{{display:flex;align-items:center;gap:7px;width:100%;padding:5px 8px;border-radius:5px;border:none;background:transparent;cursor:pointer;color:var(--text);font-family:'Syne',sans-serif;font-size:11px;font-weight:600;text-align:left;transition:all .12s;}}
.fb:hover{{background:var(--surf2);}}
.fb.active{{background:var(--surf2);color:var(--accent);}}
.fd{{width:7px;height:7px;border-radius:50%;flex-shrink:0;}}
.fc{{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted);background:rgba(255,255,255,.05);padding:1px 5px;border-radius:3px;}}
.sb-divider{{height:1px;background:var(--border);margin:8px 12px;}}

/* ── SEARCH ── */
#srch-wrap{{position:fixed;top:54px;left:242px;z-index:95;}}
#srch{{background:var(--surf);border:1px solid var(--border);color:var(--text);padding:5px 11px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:11px;width:190px;outline:none;transition:border-color .15s;}}
#srch:focus{{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.1);}}
#srch::placeholder{{color:var(--muted);}}

/* ── CANVAS ── */
#ca{{position:fixed;top:46px;left:232px;right:0;bottom:22px;overflow:hidden;cursor:grab;}}
#ca:active{{cursor:grabbing;}}
#cv{{position:absolute;top:0;left:0;transform-origin:0 0;}}
#edges{{position:absolute;top:0;left:0;pointer-events:none;overflow:visible;}}
.edge{{stroke:rgba(0,212,255,.18);stroke-width:1.5;fill:none;marker-end:url(#arrow);}}
.edge.sg-edge{{stroke:rgba(139,92,246,.35);stroke-dasharray:4,3;}}
.edge-lbl{{font-size:8px;fill:rgba(100,116,139,.7);font-family:'JetBrains Mono',monospace;}}

/* ── NODES ── */
.node{{position:absolute;background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:10px 12px 9px;width:158px;cursor:pointer;transition:border-color .18s,box-shadow .18s,transform .1s;user-select:none;}}
.node:hover{{border-color:var(--accent);box-shadow:0 0 20px rgba(0,212,255,.14);transform:translateY(-1px);z-index:10!important;}}
.node.sel{{border-color:var(--accent);box-shadow:0 0 28px rgba(0,212,255,.22),0 0 0 1px rgba(0,212,255,.3);z-index:20!important;}}
.node.orphan{{opacity:.7;border-style:dashed;}}
.n-icon{{width:28px;height:28px;margin-bottom:6px;border-radius:5px;overflow:hidden;flex-shrink:0;}}
.n-icon img{{width:28px;height:28px;}}
.n-name{{font-size:11px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.3;}}
.n-type{{font-size:9px;color:var(--muted);font-family:'JetBrains Mono',monospace;margin-top:2px;}}
.n-meta{{font-size:8px;color:var(--muted);margin-top:4px;display:flex;align-items:center;gap:4px;}}
.sdot{{width:5px;height:5px;border-radius:50%;flex-shrink:0;}}
.sup{{background:#10b981;box-shadow:0 0 4px #10b981;}}
.sdn{{background:#ef4444;}}
.suk{{background:#64748b;}}
.n-badge{{display:inline-block;font-size:8px;font-family:'JetBrains Mono',monospace;padding:1px 5px;border-radius:3px;border:1px solid;margin-top:3px;}}

/* ── REGION GROUP ── */
.rg-box{{position:absolute;border:1px dashed rgba(0,212,255,.12);border-radius:16px;background:rgba(0,212,255,.015);pointer-events:none;}}
.rg-label{{position:absolute;top:-10px;left:14px;font-size:9px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:rgba(0,212,255,.35);background:var(--bg);padding:0 6px;font-family:'JetBrains Mono',monospace;}}

/* ── DETAIL PANEL ── */
#dp{{position:fixed;top:46px;right:0;bottom:22px;width:272px;background:rgba(15,20,32,.97);border-left:1px solid var(--border);transform:translateX(100%);transition:transform .22s cubic-bezier(.4,0,.2,1);z-index:95;overflow-y:auto;}}
#dp::-webkit-scrollbar{{width:3px;}}
#dp::-webkit-scrollbar-thumb{{background:var(--border);}}
#dpi{{padding:16px;}}
.dp-type{{font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);margin-bottom:5px;}}
.dp-icon{{width:36px;height:36px;margin-bottom:8px;border-radius:8px;overflow:hidden;}}
.dp-icon img{{width:36px;height:36px;}}
.dp-name{{font-size:16px;font-weight:800;margin-bottom:12px;line-height:1.2;}}
.dp-row{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(30,58,95,.5);gap:8px;}}
.dk{{font-size:9px;color:var(--muted);flex-shrink:0;font-family:'JetBrains Mono',monospace;padding-top:1px;}}
.dv{{font-size:9px;text-align:right;word-break:break-all;font-family:'JetBrains Mono',monospace;}}
.dp-sec{{margin-top:12px;}}
.dp-sec h4{{font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}}
.ci{{display:flex;align-items:center;gap:7px;padding:5px 7px;border-radius:5px;margin-bottom:3px;background:rgba(255,255,255,.04);font-size:10px;cursor:pointer;transition:background .12s;}}
.ci:hover{{background:rgba(255,255,255,.08);}}
.ci img{{width:16px;height:16px;border-radius:3px;}}
.dp-close{{position:absolute;top:10px;right:10px;background:transparent;border:none;color:var(--muted);cursor:pointer;font-size:15px;padding:4px;border-radius:4px;transition:color .15s;}}
.dp-close:hover{{color:var(--text);background:var(--surf2);}}

/* ── CONTROLS ── */
#ctrls{{position:fixed;bottom:30px;right:10px;z-index:100;display:flex;flex-direction:column;gap:4px;}}
.cb{{width:30px;height:30px;border-radius:6px;background:rgba(17,24,39,.95);border:1px solid var(--border);color:var(--text);cursor:pointer;font-size:13px;display:flex;align-items:center;justify-content:center;transition:all .15s;}}
.cb:hover{{border-color:var(--accent);color:var(--accent);}}
.cb.active{{border-color:var(--accent3);color:var(--accent3);}}

/* ── STATUS BAR ── */
#sbar{{position:fixed;bottom:0;left:232px;right:0;z-index:90;background:rgba(10,14,26,.93);border-top:1px solid var(--border);padding:3px 14px;display:flex;gap:18px;align-items:center;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted);height:22px;}}
.sv{{color:var(--accent);font-weight:600;}}

/* ── TOAST ── */
#toast{{position:fixed;top:54px;right:16px;z-index:300;padding:6px 14px;border-radius:7px;font-size:11px;font-weight:700;opacity:0;transition:opacity .3s;pointer-events:none;font-family:'Syne',sans-serif;}}
#toast.show{{opacity:1;}}
#toast.ok{{background:var(--accent3);color:#000;}}
#toast.err{{background:var(--danger);color:white;}}

/* ── MINI MAP ── */
#minimap{{position:fixed;bottom:30px;left:242px;z-index:100;width:120px;height:80px;background:rgba(17,24,39,.9);border:1px solid var(--border);border-radius:6px;overflow:hidden;}}
#mm-canvas{{position:absolute;inset:0;}}
</style>
</head>
<body>

{pwd_overlay_html}

<div id="main-wrap">

<div id="toast"></div>

<div id="hdr">
  <h1>☁️ AWS Architecture</h1>
  <span class="badge bb" id="h-acct">Loading...</span>
  <span class="badge bg" id="h-res">0 resources</span>
  <span class="badge bp" id="h-reg">0 regions</span>
  <span style="font-size:9px;color:var(--muted);font-family:monospace;white-space:nowrap" id="h-time"></span>
  <button class="hbtn" onclick="saveToFile()" title="Saves your layout — positions are remembered automatically too">💾 Save Layout</button>
  <button class="hbtn" onclick="autoArrange()" title="Re-run intelligent auto-layout">🔀 Re-Layout</button>
  <button class="hbtn" onclick="exportJSON()">⬇ JSON</button>
</div>

<div id="sidebar">
  <div class="sbs">
    <div class="sbl">Resource Types</div>
    <button class="fb active" id="btn-all" onclick="fType('all',this)">
      <span class="fd" style="background:var(--accent)"></span>All Resources
      <span class="fc" id="cnt-all">0</span>
    </button>
    <div id="type-list"></div>
  </div>
  <div class="sb-divider"></div>
  <div class="sbs">
    <div class="sbl">Regions</div>
    <button class="fb active" id="btn-allreg" onclick="fReg('all',this)">
      <span class="fd" style="background:var(--accent3)"></span>All Regions
      <span class="fc" id="cnt-allreg">0</span>
    </button>
    <div id="reg-list"></div>
  </div>
  <div class="sb-divider"></div>
  <div class="sbs" style="padding-bottom:10px;">
    <div class="sbl">Display</div>
    <button class="fb" onclick="toggleEdges(this)"><span class="fd" style="background:#00d4ff"></span>Connections<span id="edge-state" class="fc">ON</span></button>
    <button class="fb" onclick="toggleOrphans(this)"><span class="fd" style="background:#f59e0b"></span>Orphan nodes<span id="orphan-state" class="fc">ON</span></button>
  </div>
</div>

<input id="srch" placeholder="🔍 Search resources..." oninput="doSearch(this.value)">

<div id="ca">
  <div id="cv">
    <svg id="edges">
      <defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L0,6 L6,3 z" fill="rgba(0,212,255,.4)"/>
        </marker>
        <marker id="arrow-sg" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L0,6 L6,3 z" fill="rgba(139,92,246,.5)"/>
        </marker>
      </defs>
    </svg>
  </div>
</div>

<div id="dp">
  <button class="dp-close" onclick="closeDetail()">✕</button>
  <div id="dpi"></div>
</div>

<div id="ctrls">
  <button class="cb" onclick="zoom(.15)" title="Zoom in">+</button>
  <button class="cb" onclick="zoom(-.15)" title="Zoom out">−</button>
  <button class="cb" onclick="resetView()" title="Fit to screen" id="fit-btn">⊙</button>
  <button class="cb" onclick="toggleGrid()" title="Toggle grid" id="grid-btn">⊞</button>
</div>

<div id="sbar">
  <span>Resources: <span class="sv" id="st-r">0</span></span>
  <span>Connections: <span class="sv" id="st-c">0</span></span>
  <span>Regions: <span class="sv" id="st-rg">0</span></span>
  <span>Visible: <span class="sv" id="st-v">0</span></span>
  <span style="margin-left:auto;color:rgba(100,116,139,.6)">Drag nodes · Scroll zoom · Click for details · 💾 Save Layout persists positions</span>
</div>

</div><!-- main-wrap -->

<script>
// ── DATA ─────────────────────────────────────────────────
const RAW = ''' + json_data + ''';
''' + icons_js + '''

// ── TYPE CONFIG ──────────────────────────────────────────
const TC = {
  vpc:         {color:'#8C4FFF',label:'VPC'},
  subnet:      {color:'#6366F1',label:'Subnet'},
  igw:         {color:'#06B6D4',label:'Internet GW'},
  nat:         {color:'#0EA5E9',label:'NAT GW'},
  sg:          {color:'#8B5CF6',label:'Security Group'},
  ec2:         {color:'#FF9900',label:'EC2 Instance'},
  rds:         {color:'#2196F3',label:'RDS Database'},
  s3:          {color:'#569A31',label:'S3 Bucket'},
  lambda:      {color:'#FF9900',label:'Lambda'},
  elb:         {color:'#8C4FFF',label:'Load Balancer'},
  ecs:         {color:'#FF9900',label:'ECS Cluster'},
  eks:         {color:'#326CE5',label:'EKS Cluster'},
  dynamodb:    {color:'#2196F3',label:'DynamoDB'},
  sns:         {color:'#FF4F8B',label:'SNS Topic'},
  sqs:         {color:'#FF4F8B',label:'SQS Queue'},
  elasticache: {color:'#C7131F',label:'ElastiCache'},
  cloudfront:  {color:'#8C4FFF',label:'CloudFront'},
  route_table: {color:'#E7157B',label:'Route Table'},
  nacl:        {color:'#DD344C',label:'Network ACL'},
  tgw:         {color:'#E7157B',label:'Transit GW'},
  peering:     {color:'#0D86FF',label:'VPC Peering'},
  endpoint:    {color:'#1A6622',label:'VPC Endpoint'},
  eip:         {color:'#FF9900',label:'Elastic IP'},
  dhcp:        {color:'#546E7A',label:'DHCP Options'},
  cgw:         {color:'#FF6B35',label:'Customer GW'},
  vgw:         {color:'#0D86FF',label:'Virtual GW'},
};
function tc(t){return TC[t]||{color:'#546E7A',label:t.toUpperCase()};}
function icon(t){return AWS_ICONS[t]||AWS_ICONS['cgw'];}

// ── STATE ────────────────────────────────────────────────
let scale=.9,panX=30,panY=30;
let isPan=false,panStart={x:0,y:0},panOrig={x:0,y:0};
let dragNode=null,dragStart={x:0,y:0,nx:0,ny:0};
let selNode=null,typeFilter='all',regFilter='all',searchQ='';
let showEdges=true,showOrphans=true,showGrid=true;
let positions=JSON.parse('__POSITIONS_JSON__');  // DO NOT EDIT THIS LINE
let filtersReady=false;

// ── INTELLIGENT LAYOUT ───────────────────────────────────
function smartLayout(resources){
  const pos={};
  const conns=RAW.connections;
  const connSet=new Set(conns.map(c=>c.from).concat(conns.map(c=>c.to)));

  // Separate orphans from connected nodes
  const connected=resources.filter(r=>connSet.has(r.id));
  const orphans=resources.filter(r=>!connSet.has(r.id));

  // Build adjacency for topological ordering
  const byId={};
  resources.forEach(r=>byId[r.id]=r);

  // Layer assignment: BFS from root nodes (vpc, igw, cgw, vgw)
  const ROOT_TYPES=['cgw','vpn','vgw','vpc','igw','cloudfront'];
  const LAYER_ORDER=['cgw','vpn','vgw','vpc','igw','nat','subnet','elb','ec2','rds','lambda','ecs','eks','elasticache','dynamodb','sg','sns','sqs','s3'];

  // Group connected nodes by region then by layer
  const byRegion={};
  connected.forEach(r=>{
    if(!byRegion[r.region])byRegion[r.region]=[];
    byRegion[r.region].push(r);
  });

  const W=195, H=130, PAD=60, GROUP_GAP=100;
  let globalX=PAD;

  Object.entries(byRegion).forEach(([region,nodes])=>{
    // Sort by layer order
    const sorted=[...nodes].sort((a,b)=>{
      const ai=LAYER_ORDER.indexOf(a.type);
      const bi=LAYER_ORDER.indexOf(b.type);
      return (ai===-1?99:ai)-(bi===-1?99:bi);
    });

    // Group by type within region
    const byType={};
    sorted.forEach(n=>{
      if(!byType[n.type])byType[n.type]=[];
      byType[n.type].push(n);
    });

    let colX=globalX;
    let maxY=PAD;

    Object.entries(byType).forEach(([type,tnodes])=>{
      const cols=Math.min(tnodes.length,3);
      tnodes.forEach((n,i)=>{
        const col=i%cols;
        const row=Math.floor(i/cols);
        pos[n.id]={x:colX+col*W, y:PAD+row*H};
      });
      const rows=Math.ceil(tnodes.length/cols);
      maxY=Math.max(maxY,PAD+rows*H);
      colX+=cols*W+40;
    });

    globalX=colX+GROUP_GAP;
  });

  // Orphans go neatly at the bottom in a grid
  const orphanStartX=PAD;
  let orphanStartY=maxYOfAll(pos)+80;
  if(orphanStartY<PAD)orphanStartY=PAD;
  orphans.forEach((r,i)=>{
    pos[r.id]={x:orphanStartX+(i%6)*W, y:orphanStartY+Math.floor(i/6)*H};
  });

  return pos;
}

function maxYOfAll(pos){
  let m=0;
  Object.values(pos).forEach(p=>{if(p.y>m)m=p.y;});
  return m;
}

function autoArrange(){
  positions=smartLayout(RAW.resources);
  render();
  fitView();
  toast('🔀 Layout re-arranged!','ok');
}

// ── FIT VIEW ─────────────────────────────────────────────
function fitView(){
  const vis=getVisible();
  if(!vis.length)return;
  let minX=Infinity,minY=Infinity,maxX=-Infinity,maxY=-Infinity;
  vis.forEach(r=>{
    const p=positions[r.id];
    if(!p)return;
    minX=Math.min(minX,p.x);minY=Math.min(minY,p.y);
    maxX=Math.max(maxX,p.x+158);maxY=Math.max(maxY,p.y+90);
  });
  const ca=document.getElementById('ca');
  const vw=ca.clientWidth, vh=ca.clientHeight;
  const dw=maxX-minX+80, dh=maxY-minY+80;
  scale=Math.min(vw/dw, vh/dh, 1.2);
  panX=(vw-dw*scale)/2-minX*scale+40;
  panY=(vh-dh*scale)/2-minY*scale+40;
  applyT();
}

// ── VISIBLE ───────────────────────────────────────────────
function getVisible(){
  return RAW.resources.filter(r=>{
    if(typeFilter!=='all'&&r.type!==typeFilter)return false;
    if(regFilter!=='all'&&r.region!==regFilter)return false;
    if(!showOrphans){
      const connSet=new Set(RAW.connections.map(c=>c.from).concat(RAW.connections.map(c=>c.to)));
      if(!connSet.has(r.id))return false;
    }
    if(searchQ){const q=searchQ.toLowerCase();return r.name.toLowerCase().includes(q)||r.id.toLowerCase().includes(q)||r.type.toLowerCase().includes(q)||r.region.toLowerCase().includes(q);}
    return true;
  });
}

// ── RENDER ───────────────────────────────────────────────
function render(){
  const cv=document.getElementById('cv');
  const svg=document.getElementById('edges');
  Array.from(cv.children).forEach(c=>{if(c.id!=='edges')c.remove();});
  // Keep defs, remove paths/texts only
  Array.from(svg.children).forEach(c=>{if(c.tagName!=='defs')c.remove();});

  const vis=getVisible();
  const visIds=new Set(vis.map(r=>r.id));
  const connSet=new Set(RAW.connections.map(c=>c.from).concat(RAW.connections.map(c=>c.to)));

  // Ensure positions
  vis.forEach(r=>{if(!positions[r.id])positions[r.id]={x:80+Math.random()*800,y:80+Math.random()*500};});

  // Draw edges
  if(showEdges){
    RAW.connections.filter(c=>visIds.has(c.from)&&visIds.has(c.to)).forEach(conn=>{
      const f=positions[conn.from],t=positions[conn.to];
      if(!f||!t)return;
      const isSG=conn.label==='sg';
      const fx=f.x+79,fy=f.y+45,tx=t.x+79,ty=t.y+45;
      const mx=(fx+tx)/2,my=(fy+ty)/2-30;
      const path=document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('class','edge'+(isSG?' sg-edge':''));
      path.setAttribute('d',`M${fx} ${fy} Q${mx} ${my} ${tx} ${ty}`);
      path.setAttribute('marker-end',isSG?'url(#arrow-sg)':'url(#arrow)');
      svg.appendChild(path);
      if(conn.label&&conn.label!=='contains'){
        const txt=document.createElementNS('http://www.w3.org/2000/svg','text');
        txt.setAttribute('x',mx);txt.setAttribute('y',my-3);
        txt.setAttribute('text-anchor','middle');txt.setAttribute('class','edge-lbl');
        txt.textContent=conn.label;svg.appendChild(txt);
      }
    });
  }

  // Draw region groups
  const byRegion={};
  vis.forEach(r=>{if(!byRegion[r.region])byRegion[r.region]=[];byRegion[r.region].push(r);});
  Object.entries(byRegion).forEach(([reg,nodes])=>{
    if(nodes.length<2)return;
    let mnx=Infinity,mny=Infinity,mxx=-Infinity,mxy=-Infinity;
    nodes.forEach(r=>{const p=positions[r.id];if(!p)return;mnx=Math.min(mnx,p.x);mny=Math.min(mny,p.y);mxx=Math.max(mxx,p.x+158);mxy=Math.max(mxy,p.y+90);});
    const box=document.createElement('div');
    box.className='rg-box';
    box.style.left=(mnx-18)+'px';box.style.top=(mny-18)+'px';
    box.style.width=(mxx-mnx+36)+'px';box.style.height=(mxy-mny+36)+'px';
    const lbl=document.createElement('div');lbl.className='rg-label';lbl.textContent=reg;
    box.appendChild(lbl);cv.appendChild(box);
  });

  // Draw nodes
  vis.forEach(r=>{
    const p=positions[r.id];
    const conf=tc(r.type);
    const isOrphan=!connSet.has(r.id);
    const el=document.createElement('div');
    el.className='node'+(selNode===r.id?' sel':'')+(isOrphan?' orphan':'');
    el.style.left=p.x+'px';el.style.top=p.y+'px';
    el.style.zIndex=selNode===r.id?20:1;
    el.style.borderTop=`2px solid ${conf.color}`;

    const st=r.meta?.state||r.meta?.status||'';
    const up=['running','available','active','up','Up','enabled'].includes(st);
    const dn=['stopped','down','Down','failed','error','deleted'].includes(st);
    const sc=up?'sup':dn?'sdn':'suk';
    const stLabel=st?st:'';
    const onpremCidrs = r.meta?.onprem_cidrs||[];
    const onpremBadge = onpremCidrs.length>0
      ? `<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:2px">${onpremCidrs.slice(0,3).map(c=>`<span style="background:rgba(16,185,129,.15);border:1px solid #10b981;color:#10b981;font-size:7px;padding:1px 4px;border-radius:3px;font-family:monospace">${c}</span>`).join('')}${onpremCidrs.length>3?`<span style="color:var(--muted);font-size:7px">+${onpremCidrs.length-3} more</span>`:''}</div>`
      : '';
    const rtTypeBadge = r.type==='route_table'&&r.meta?.type
      ? `<span class="n-badge" style="border-color:${r.meta.has_internet?'var(--accent)':r.meta.has_onprem?'#10b981':r.meta.has_peering?'#7c3aed':'var(--border)'};color:${r.meta.has_internet?'var(--accent)':r.meta.has_onprem?'#10b981':r.meta.has_peering?'#a78bfa':'var(--muted)'}">${r.meta.type}</span>`
      : '';

    el.innerHTML=`<div style="display:flex;align-items:flex-start;gap:8px;">
  <div class="n-icon"><img src="${icon(r.type)}" alt="${r.type}"/></div>
  <div style="flex:1;min-width:0;">
    <div class="n-name" title="${r.name}">${r.name}</div>
    <div class="n-type">${conf.label}</div>
  </div>
</div>
<div class="n-meta"><span class="sdot ${sc}"></span><span>${r.region}</span>${stLabel?`<span class="n-badge" style="border-color:${up?'#10b981':dn?'#ef4444':'#64748b'};color:${up?'#10b981':dn?'#ef4444':'#94a3b8'}">${stLabel}</span>`:''}${rtTypeBadge}
</div>${onpremBadge}`;

    el.addEventListener('click',e=>{e.stopPropagation();selNode=r.id;showDetail(r);render();});
    el.addEventListener('mousedown',e=>{
      if(e.button!==0)return;e.stopPropagation();
      dragNode=r.id;
      dragStart={x:e.clientX,y:e.clientY,nx:positions[r.id].x,ny:positions[r.id].y};
    });
    cv.appendChild(el);
  });

  document.getElementById('st-v').textContent=vis.length;
  document.getElementById('st-r').textContent=RAW.resources.length;
  document.getElementById('st-c').textContent=RAW.connections.length;
  document.getElementById('st-rg').textContent=RAW.active_regions?.length||0;
}

// ── DETAIL PANEL ─────────────────────────────────────────
function showDetail(r){
  const conf=tc(r.type);
  const conns=RAW.connections.filter(c=>c.from===r.id||c.to===r.id);
  let meta='';
  if(r.meta){Object.entries(r.meta).forEach(([k,v])=>{
    if(v===null||v===undefined||v==='')return;
    // Special rendering for route tables
    if(k==='routes'&&Array.isArray(v)){
      meta+=`<div class="dp-sec" style="margin-top:10px">
<h4>Routes (${v.length})</h4>
<div style="background:rgba(0,0,0,.3);border-radius:6px;overflow:hidden;margin-top:4px;">
<table style="width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:8px;">
<tr style="background:rgba(255,255,255,.06);"><th style="padding:4px 6px;text-align:left;color:var(--muted)">Destination</th><th style="padding:4px 6px;text-align:left;color:var(--muted)">Target</th><th style="padding:4px 6px;text-align:left;color:var(--muted)">State</th></tr>`;
      v.forEach(route=>{
        const isOnprem = route.target&&(route.target.startsWith('vgw-')||route.target.startsWith('tgw-'))&&route.dest!=='0.0.0.0/0';
        const isInternet = route.target&&route.target.startsWith('igw-');
        const isLocal = route.target==='local';
        const rowColor = isOnprem?'rgba(16,185,129,.1)':isInternet?'rgba(0,212,255,.07)':isLocal?'rgba(255,255,255,.03)':'';
        const destColor = isOnprem?'#10b981':isInternet?'var(--accent)':'var(--text)';
        const tag = isOnprem?'<span style="background:#10b981;color:#000;font-size:7px;padding:1px 4px;border-radius:2px;margin-left:4px">ON-PREM</span>':isInternet?'<span style="background:rgba(0,212,255,.2);color:var(--accent);font-size:7px;padding:1px 4px;border-radius:2px;margin-left:4px">INTERNET</span>':'';
        meta+=`<tr style="border-top:1px solid rgba(255,255,255,.05);background:${rowColor}">
<td style="padding:4px 6px;color:${destColor}">${route.dest||'—'}${tag}</td>
<td style="padding:4px 6px;color:var(--muted);max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${route.target}">${route.target||'—'}</td>
<td style="padding:4px 6px;color:${route.state==='active'?'#10b981':'#ef4444'}">${route.state||'—'}</td>
</tr>`;
      });
      meta+=`</table></div></div>`;
      return;
    }
    // Special rendering for NACL rules
    if((k==='inbound'||k==='outbound')&&Array.isArray(v)){
      if(v.length===0)return;
      meta+=`<div class="dp-sec" style="margin-top:10px">
<h4>${k==='inbound'?'⬇ Inbound':'⬆ Outbound'} Rules (${v.length})</h4>
<div style="background:rgba(0,0,0,.3);border-radius:6px;overflow:hidden;margin-top:4px;">
<table style="width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace;font-size:8px;">
<tr style="background:rgba(255,255,255,.06);"><th style="padding:3px 5px;text-align:left;color:var(--muted)">#</th><th style="padding:3px 5px;text-align:left;color:var(--muted)">CIDR</th><th style="padding:3px 5px;text-align:left;color:var(--muted)">Port</th><th style="padding:3px 5px;text-align:left;color:var(--muted)">Action</th></tr>`;
      v.forEach(rule=>{
        const isAllow=rule.action==='allow';
        meta+=`<tr style="border-top:1px solid rgba(255,255,255,.05)">
<td style="padding:3px 5px;color:var(--muted)">${rule.rule_number}</td>
<td style="padding:3px 5px;color:var(--text)">${rule.cidr||'all'}</td>
<td style="padding:3px 5px;color:var(--muted)">${rule.port_range}</td>
<td style="padding:3px 5px;color:${isAllow?'#10b981':'#ef4444'};font-weight:700">${rule.action?.toUpperCase()}</td>
</tr>`;
      });
      meta+=`</table></div></div>`;
      return;
    }
    if(Array.isArray(v)){v.forEach((it,i)=>{if(typeof it==='object')Object.entries(it).forEach(([ik,iv])=>{if(iv)meta+=`<div class="dp-row"><span class="dk">t${i+1}.${ik}</span><span class="dv">${iv}</span></div>`;});});return;}
    if(typeof v==='object')return; // skip complex objects not handled above
    meta+=`<div class="dp-row"><span class="dk">${k}</span><span class="dv">${v}</span></div>`;
  });}
  let connHtml='';
  conns.slice(0,15).forEach(c=>{
    const oid=c.from===r.id?c.to:c.from;
    const oth=RAW.resources.find(x=>x.id===oid);
    const dir=c.from===r.id?'→':'←';
    connHtml+=`<div class="ci" onclick="jumpTo('${oid}')">${dir}<img src="${icon(oth?.type||'')}" alt=""/><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${oth?.name||oid}</span><span style="color:var(--muted);font-size:8px;flex-shrink:0">${c.label}</span></div>`;
  });
  document.getElementById('dpi').innerHTML=`
<div class="dp-type">${conf.label}</div>
<div class="dp-icon"><img src="${icon(r.type)}" alt="${r.type}"/></div>
<div class="dp-name">${r.name}</div>
<div class="dp-row"><span class="dk">id</span><span class="dv" style="color:var(--accent);font-size:8px">${r.id}</span></div>
<div class="dp-row"><span class="dk">region</span><span class="dv">${r.region}</span></div>
${meta}
${conns.length?`<div class="dp-sec"><h4>Connections (${conns.length})</h4>${connHtml}</div>`:'<div style="margin-top:12px;font-size:10px;color:var(--muted);font-family:monospace">No connections found</div>'}`;
  document.getElementById('dp').style.transform='translateX(0)';
}
function closeDetail(){document.getElementById('dp').style.transform='translateX(100%)';selNode=null;render();}
function jumpTo(id){const r=RAW.resources.find(x=>x.id===id);if(!r)return;selNode=id;showDetail(r);const p=positions[id];if(p){const ca=document.getElementById('ca');panX=-(p.x*scale)+ca.clientWidth/2-79;panY=-(p.y*scale)+ca.clientHeight/2-45;applyT();}render();}

// ── FILTERS — BUILT ONCE ─────────────────────────────────
function buildFilters(){
  if(filtersReady)return; filtersReady=true;
  const typeCounts={};
  RAW.resources.forEach(r=>{typeCounts[r.type]=(typeCounts[r.type]||0)+1;});
  document.getElementById('cnt-all').textContent=RAW.resources.length;
  const tl=document.getElementById('type-list');tl.innerHTML='';
  Object.entries(typeCounts).sort((a,b)=>b[1]-a[1]).forEach(([type,count])=>{
    const conf=tc(type);
    const btn=document.createElement('button');btn.className='fb';
    btn.innerHTML=`<span class="fd" style="background:${conf.color}"></span>${conf.label}<span class="fc">${count}</span>`;
    btn.onclick=()=>fType(type,btn);tl.appendChild(btn);
  });
  const regions=[...new Set(RAW.resources.map(r=>r.region))].sort();
  document.getElementById('cnt-allreg').textContent=regions.length;
  const rl=document.getElementById('reg-list');rl.innerHTML='';
  regions.forEach(region=>{
    const count=RAW.resources.filter(r=>r.region===region).length;
    const btn=document.createElement('button');btn.className='fb';
    btn.innerHTML=`<span class="fd" style="background:var(--accent3)"></span>${region}<span class="fc">${count}</span>`;
    btn.onclick=()=>fReg(region,btn);rl.appendChild(btn);
  });
}
function fType(t,btn){typeFilter=t;document.querySelectorAll('#type-list .fb,#btn-all').forEach(b=>b.classList.remove('active'));(btn||document.getElementById('btn-all')).classList.add('active');render();}
function fReg(r,btn){regFilter=r;document.querySelectorAll('#reg-list .fb,#btn-allreg').forEach(b=>b.classList.remove('active'));(btn||document.getElementById('btn-allreg')).classList.add('active');render();}
function doSearch(v){searchQ=v;render();}
function toggleEdges(btn){showEdges=!showEdges;document.getElementById('edge-state').textContent=showEdges?'ON':'OFF';if(btn)btn.classList.toggle('active',!showEdges);render();}
function toggleOrphans(btn){showOrphans=!showOrphans;document.getElementById('orphan-state').textContent=showOrphans?'ON':'OFF';render();}
function toggleGrid(){showGrid=!showGrid;document.body.style.backgroundImage=showGrid?'linear-gradient(rgba(0,212,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.025) 1px,transparent 1px)':'none';document.getElementById('grid-btn').classList.toggle('active',!showGrid);}

// ── PAN & ZOOM ────────────────────────────────────────────
function applyT(){document.getElementById('cv').style.transform=`translate(${panX}px,${panY}px) scale(${scale})`;}
function zoom(d){scale=Math.max(.1,Math.min(3,scale+d));applyT();}
function resetView(){fitView();}
const ca=document.getElementById('ca');
ca.addEventListener('mousedown',e=>{if(dragNode)return;isPan=true;panStart={x:e.clientX,y:e.clientY};panOrig={x:panX,y:panY};});
window.addEventListener('mousemove',e=>{
  if(dragNode){const dx=(e.clientX-dragStart.x)/scale,dy=(e.clientY-dragStart.y)/scale;positions[dragNode]={x:dragStart.nx+dx,y:dragStart.ny+dy};render();return;}
  if(!isPan)return;panX=panOrig.x+(e.clientX-panStart.x);panY=panOrig.y+(e.clientY-panStart.y);applyT();
});
window.addEventListener('mouseup',()=>{
  if(dragNode) autoSave();  // auto-save position to localStorage on drop
  isPan=false;dragNode=null;
});
ca.addEventListener('wheel',e=>{e.preventDefault();const d=e.deltaY>0?-.1:.1;scale=Math.max(.1,Math.min(3,scale+d));applyT();},{passive:false});
ca.addEventListener('click',e=>{if(e.target===ca||e.target===document.getElementById('cv'))closeDetail();});

// ── SAVE LAYOUT ───────────────────────────────────────────
// Strategy 1: localStorage (instant, no download needed)
// Strategy 2: Download new HTML with positions baked in (fallback)

const STORAGE_KEY = 'aws_arch_positions_' + RAW.account_id;

function loadSavedPositions(){
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if(saved){
      const parsed = JSON.parse(saved);
      if(Object.keys(parsed).length > 0){
        positions = parsed;
        return true;
      }
    }
  } catch(e){}
  return false;
}

function saveToLocalStorage(){
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(positions));
    return true;
  } catch(e){ return false; }
}

function saveToFile(){
  // Also save to localStorage instantly
  saveToLocalStorage();

  // Build new HTML with positions baked in via unique marker replacement
  const posJson = JSON.stringify(positions);
  let html = document.documentElement.outerHTML;

  // Use the unique marker for reliable replacement
  html = html.replace(
    "JSON.parse('__POSITIONS_JSON__')",
    JSON.stringify(positions)
  );

  // Also handle already-saved files where marker was already replaced
  // by replacing the entire positions assignment up to the comment
  html = html.replace(
    /let positions=(\{[\s\S]*?\});  \/\/ DO NOT EDIT THIS LINE/,
    'let positions=' + posJson + ';  // DO NOT EDIT THIS LINE'
  );

  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const fname = 'aws-arch-' + RAW.account_id + '-saved.html';
  a.download = fname;
  a.click();
  toast('💾 Layout saved! Open ' + fname,'ok');
}

// Auto-save positions to localStorage whenever a node is moved
function autoSave(){
  saveToLocalStorage();
}

function exportJSON(){
  const blob=new Blob([JSON.stringify(RAW,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='aws-report-'+RAW.account_id+'.json';a.click();
}

function toast(msg,type='ok'){
  const el=document.getElementById('toast');
  el.textContent=msg;el.className='show '+type;
  setTimeout(()=>el.className='',2500);
}

// ── INIT ──────────────────────────────────────────────────
function initApp(){
  document.getElementById('h-acct').textContent='Account: '+RAW.account_id;
  document.getElementById('h-res').textContent=RAW.total_resources+' resources';
  document.getElementById('h-reg').textContent=(RAW.active_regions?.length||0)+' regions';
  document.getElementById('h-time').textContent='Scanned: '+new Date(RAW.scanned_at).toLocaleString();

  // Priority 1: Load from localStorage (most recent user edits)
  const fromStorage = loadSavedPositions();

  // Priority 2: Use baked-in positions from saved HTML file
  const hasBaked = !fromStorage && Object.keys(positions).length > 0;

  // Priority 3: Run smart layout from scratch
  if(!fromStorage && !hasBaked){
    positions = smartLayout(RAW.resources);
  }

  buildFilters();
  render();
  setTimeout(fitView, 100);
}

''' + pwd_script + '''
</script>
</body>
</html>'''


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AWS Architecture Scanner — scans all regions and generates visual diagram + JSON report"
    )
    parser.add_argument("--access-key", "-a", required=True, help="AWS Access Key ID")
    parser.add_argument("--secret-key", "-s", required=True, help="AWS Secret Access Key")
    parser.add_argument("--session-token", "-t", default=None, help="AWS Session Token (optional)")
    parser.add_argument("--output", "-o", default="aws-architecture", help="Output file prefix")
    args = parser.parse_args()

    print("=" * 60)
    print("  AWS Architecture Scanner  v3")
    print("=" * 60)

    scanner = AWSScanner(args.access_key, args.secret_key, args.session_token)
    data = scanner.scan()

    json_path = f"{args.output}-report.json"
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n✅ JSON report saved: {json_path}")

    html_path = f"{args.output}-diagram.html"
    generate_html(data, html_path)

    print("\n" + "=" * 60)
    print(f"  ✅ Scan Complete!")
    print(f"  📊 Resources  : {data['total_resources']}")
    print(f"  🔗 Connections: {data['total_connections']}")
    print(f"  🌍 Regions    : {len(data['active_regions'])}")
    print(f"  📁 JSON       : {json_path}")
    print(f"  🌐 HTML       : {html_path}")
    print("=" * 60)
    print(f"\n  Open {html_path} in your browser!\n")


if __name__ == "__main__":
    main()
