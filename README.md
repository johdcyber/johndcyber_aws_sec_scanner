
# Johndcyber AWS Security Scanner

## Description

`johndcyber_aws_scanner` is an integrated security scanner for AWS environments that combines the strengths of multiple security tools, including Prowler, ScoutSuite, CloudMapper, CloudSploit, and Trivy. It consolidates their findings into a single HTML report and uploads it to an S3 bucket.

## Features

- Runs Prowler for CIS benchmark checks
- Runs ScoutSuite for detailed configuration analysis
- Runs CloudMapper for AWS environment visualization and auditing
- Runs CloudSploit for robust security and compliance monitoring
- Runs Trivy for vulnerability scanning of containers and other artifacts
- Runs JohnDCyber's IAM SCanner to identify overly permissive IAM policies,Roles,and Users
- Generates a consolidated HTML report
- Outputs report to a local directory named `scan_results` with timestamped filenames
- Uploads the report to an S3 bucket
- Provides detailed logging and error handling
- Supports multiple AWS authentication methods (profile, role assumption)
- Supports scanning multiple AWS accounts

## Prerequisites

- Docker
- AWS CLI configured with necessary permissions

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/johndcyber_aws_scanner.git
    cd johndcyber_aws_scanner
    ```

2. Build the Docker image:
    ```sh
    docker build -t johndcyber_aws_scanner .
    ```

## Usage

### To run the scanner and upload the report to an S3 bucket:
```sh
docker run --rm -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME>
```

### To specify an AWS profile:
```sh
docker run --rm -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> -p <AWS_PROFILE>
```

### To assume an AWS role:
```sh
docker run --rm -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> -r <ROLE_ARN>
```

### To scan multiple AWS accounts, specify the account IDs:
```sh
docker run --rm -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> -a <ACCOUNT_IDS>
```

### To run specific scanners, use the -s option:
```sh
docker run --rm -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> -s <SCANNERS>
```

### Permissions
The following AWS permissions are needed to run this tool and upload the report to S3:

- s3:PutObject
- s3:PutObjectAcl
- config:DescribeConfigRules
- config:GetComplianceDetailsByConfigRule
- guardduty:GetFindings
- inspector:ListFindings
- securityhub:GetFindings

### Help
For a detailed feature list and usage help, use the -h or --help flag:
```sh
docker run johndcyber_aws_scanner -h
```

### License
This project is licensed under the MIT License.

## requirements.txt
```plaintext
boto3
jinja2
```

## Run the Scanner
```sh
docker run -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> [-p <AWS_PROFILE>] [-r <ROLE_ARN>] [-a <ACCOUNT_IDS>] [-s <SCANNERS>]
```

### Options
- -b, --bucket: S3 bucket to upload the report (required)
- -p, --profile: AWS CLI profile to use for credentials (optional)
- -r, --role-arn: ARN of the role to assume for scanning (optional)
- -a, --account-ids: AWS account IDs to scan (optional)
- -s, --scanners: Scanners to run (optional, default: all scanners)

### Example
```sh
docker run -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME> -p default -s prowler scoutsuite
```

### Run the Docker container
```sh
docker run -v ~/.aws:/root/.aws johndcyber_aws_scanner <S3_BUCKET_NAME>
```

### Run the container and save results locally
```sh
docker run -v ~/.aws:/root/.aws -v $(pwd)/johndcyber_aws_scan_results:/app/johndcyber_aws_scan_results johndcyber_aws_scanner <S3_BUCKET_NAME>
```
