import os
import subprocess
import json
import boto3
import logging
import argparse
from jinja2 import Template
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def assume_role(role_arn, session_name="AwsSecurityScannerSession"):
    client = boto3.client('sts')
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    credentials = response['Credentials']
    return credentials

def set_aws_credentials(credentials):
    os.environ['AWS_ACCESS_KEY_ID'] = credentials['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN'] = credentials['SessionToken']

def get_aws_account_id():
    client = boto3.client('sts')
    account_id = client.get_caller_identity()["Account"]
    return account_id

def run_prowler():
    try:
        logger.info("Running Prowler...")
        subprocess.run(['prowler', '-M', 'json'], check=True)
        with open('prowler-output.json') as f:
            prowler_results = json.load(f)
        return prowler_results
    except Exception as e:
        logger.error(f"Failed to run Prowler: {e}")
        return {}

def run_scoutsuite():
    try:
        logger.info("Running ScoutSuite...")
        subprocess.run(['scout', 'scan', '-p', 'aws'], check=True)
        with open('scoutsuite-results/scoutsuite_results_aws.json') as f:
            scoutsuite_results = json.load(f)
        return scoutsuite_results
    except Exception as e:
        logger.error(f"Failed to run ScoutSuite: {e}")
        return {}

def run_cloudmapper():
    try:
        logger.info("Running CloudMapper...")
        subprocess.run(['cloudmapper', 'collect'], check=True)
        subprocess.run(['cloudmapper', 'report', '--output', 'cloudmapper-report.html'], check=True)
        with open('cloudmapper-report.html') as f:
            cloudmapper_results = f.read()
        return cloudmapper_results
    except Exception as e:
        logger.error(f"Failed to run CloudMapper: {e}")
        return ""

def run_cloudsploit():
    try:
        logger.info("Running CloudSploit...")
        subprocess.run(['cloudsploit', 'scan', '-c', 'aws', '--output-format', 'json'], check=True)
        with open('cloudsploit-results.json') as f:
            cloudsploit_results = json.load(f)
        return cloudsploit_results
    except Exception as e:
        logger.error(f"Failed to run CloudSploit: {e}")
        return {}

def run_trivy():
    try:
        logger.info("Running Trivy...")
        subprocess.run(['trivy', 'fs', '--format', 'json', '--output', 'trivy-results.json', '.'], check=True)
        with open('trivy-results.json') as f:
            trivy_results = json.load(f)
        return trivy_results
    except Exception as e:
        logger.error(f"Failed to run Trivy: {e}")
        return {}

def generate_html_report(results, output_path):
    logger.info("Generating HTML report...")
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            h1, h2 { color: #2E4053; }
            pre { background: #F4F4F4; padding: 10px; border: 1px solid #DDDDDD; }
            .scanner-section { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <h1>AWS Security Scan Report</h1>
        {% for scanner, result in results.items() %}
        <div class="scanner-section">
            <h2>{{ scanner }}</h2>
            <pre>{{ result | tojson(indent=2) }}</pre>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    t = Template(template)
    html_content = t.render(results=results)
    with open(output_path, 'w') as f:
        f.write(html_content)
    logger.info(f"HTML report generated successfully at {output_path}.")

def upload_to_s3(file_name, bucket, object_name=None):
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name or file_name)
        logger.info(f"Uploaded {file_name} to S3 bucket {bucket}.")
    except Exception as e:
        logger.error(f"Failed to upload {file_name} to S3: {str(e)}")
        return None
    return response

def main():
    parser = argparse.ArgumentParser(description="Johndcyber AWS Security Scanner")
    parser.add_argument("-b", "--bucket", required=True, help="S3 bucket to upload the report")
    parser.add_argument("-p", "--profile", help="AWS CLI profile to use for credentials")
    parser.add_argument("-r", "--role-arn", help="ARN of the role to assume for scanning")
    parser.add_argument("-a", "--account-ids", nargs='*', help="AWS account IDs to scan", required=False)
    parser.add_argument("-s", "--scanners", nargs='+', choices=['prowler', 'scoutsuite', 'cloudmapper', 'cloudsploit', 'trivy'], help="Scanners to run", required=False)
    args = parser.parse_args()

    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    if args.role_arn:
        credentials = assume_role(args.role_arn)
        set_aws_credentials(credentials)

    account_id = get_aws_account_id()
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_directory = "scan_results"
    os.makedirs(output_directory, exist_ok=True)
    output_file = f"{output_directory}/johndcyber_scanner_{account_id}_{timestamp}.html"

    try:
        results = {}

        if not args.scanners:
            args.scanners = ['prowler', 'scoutsuite', 'cloudmapper', 'cloudsploit', 'trivy']

        if 'prowler' in args.scanners:
            results['Prowler'] = run_prowler()
        if 'scoutsuite' in args.scanners:
            results['ScoutSuite'] = run_scoutsuite()
        if 'cloudmapper' in args.scanners:
            results['CloudMapper'] = run_cloudmapper()
        if 'cloudsploit' in args.scanners:
            results['CloudSploit'] = run_cloudsploit()
        if 'trivy' in args.scanners:
            results['Trivy'] = run_trivy()

        generate_html_report(results, output_file)
        upload_to_s3(output_file, args.bucket)
    except (NoCredentialsError, PartialCredentialsError) as e:
        logger.error(f"AWS credentials not found: {e}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
