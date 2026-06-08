# AWS Architecture Scanner

Scans your entire AWS account across all regions, discovers all resources and their connections, and generates:
- 📊 **Interactive HTML diagram** — visual architecture map in your browser
- 📁 **JSON report** — full machine-readable data of all resources

<img width="1440" height="900" alt="Screenshot 2026-06-08 at 12 44 44 PM" src="https://github.com/user-attachments/assets/ed8226ee-913f-4adb-9dee-ba4e313c5852" />

---

## What It Scans

| Service | Resources |
|---------|-----------|
| EC2 | Instances, Security Groups |
| VPC | VPCs, Subnets, Internet GWs, NAT GWs, Route Tables |
| VPN | Site-to-Site VPN Connections, Customer GWs, Virtual GWs |
| RDS | DB Instances |
| S3 | Buckets (global) |
| Lambda | Functions |
| ELB | Application & Network Load Balancers |
| ECS | Clusters |
| EKS | Kubernetes Clusters |
| DynamoDB | Tables |
| SNS | Topics |
| SQS | Queues |
| ElastiCache | Clusters |
| CloudFront | Distributions (global) |

---

## Setup
#Provide the ReadOnlyAccess for the user, Which user access key you are using

### 1. Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Run the scanner

```bash
python3 scanner.py \
  --access-key YOUR_AWS_ACCESS_KEY_ID \
  --secret-key YOUR_AWS_SECRET_ACCESS_KEY
```

With session token (for temporary credentials):
```bash
python3 scanner.py \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --session-token YOUR_SESSION_TOKEN
```

Custom output file name:
```bash
python3 scanner.py \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --output my-company-aws
```

---

## Output Files

After running you will get:
- `aws-architecture-diagram.html` → Open in browser for visual diagram
- `aws-architecture-report.json` → Full JSON data

---

## Using the Diagram

| Action | How |
|--------|-----|
| Pan around | Click and drag background |
| Zoom in/out | Scroll wheel or +/− buttons |
| Move a node | Click and drag any resource box |
| See details | Click any resource box |
| Filter by type | Use left sidebar buttons |
| Filter by region | Use left sidebar region list |
| Search | Type in search box |
| Export JSON | Click ↓ button (bottom right) |
| Reset view | Click ⊙ button |

---

## AWS Permissions Required

Your AWS credentials need read-only access. Attach the `ReadOnlyAccess` managed policy, or use these specific permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "lambda:List*",
        "elasticloadbalancing:Describe*",
        "ecs:List*",
        "ecs:Describe*",
        "eks:List*",
        "eks:Describe*",
        "dynamodb:List*",
        "dynamodb:Describe*",
        "sns:List*",
        "sqs:List*",
        "elasticache:Describe*",
        "cloudfront:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Example Run Output

```
============================================================
  AWS Architecture Scanner
============================================================

✅ Connected to AWS Account: 123456789012

🔍 Fetching all regions...
   Found 20 regions

🔍 Scanning regions for resources (skipping empty ones)...
   Checking us-east-1... ✅ Has resources
   Checking us-west-2... ✅ Has resources
   Checking ap-south-1... ✅ Has resources
   Checking eu-west-1... ⬜ Empty (skipping)
   ...

📦 Scanning 3 active regions in parallel...
   ✅ us-east-1: 45 resources, 38 connections
   ✅ us-west-2: 12 resources, 9 connections
   ✅ ap-south-1: 28 resources, 22 connections

✅ JSON report saved: aws-architecture-report.json
✅ HTML diagram saved: aws-architecture-diagram.html

============================================================
  ✅ Scan Complete!
  📊 Total Resources : 85
  🔗 Total Connections: 69
  🌍 Active Regions  : 3
  📁 JSON Report     : aws-architecture-report.json
  🌐 HTML Diagram    : aws-architecture-diagram.html
============================================================

  Open aws-architecture-diagram.html in your browser!
```
