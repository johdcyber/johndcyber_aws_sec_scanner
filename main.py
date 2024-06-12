import subprocess
import logging
import json

logger = logging.getLogger(__name__)

def run_prowler():
    try:
        logger.info("Running Prowler...")
        subprocess.run(['prowler', '-M', 'json', '-n'], check=True)
        with open('prowler-output.json') as f:
            prowler_results = json.load(f)
        return prowler_results
    except Exception as e:
        logger.error(f"Failed to run Prowler: {e}")
        return {}

def run_scoutsuite():
    try:
        logger.info("Running ScoutSuite...")
        subprocess.run(['scoutsuite', 'scan', '--json-file', 'scoutsuite-results.json'], check=True)
        with open('scoutsuite-results.json') as f:
            scoutsuite_results = json.load(f)
        return scoutsuite_results
    except Exception as e:
        logger.error(f"Failed to run ScoutSuite: {e}")
        return {}

def run_cloudmapper():
    try:
        logger.info("Running CloudMapper...")
        subprocess.run(['cloudmapper', 'collect', '--output', 'cloudmapper-results'], check=True)
        with open('cloudmapper-results/report.json') as f:
            cloudmapper_results = json.load(f)
        return cloudmapper_results
    except Exception as e:
        logger.error(f"Failed to run CloudMapper: {e}")
        return {}

def run_cloudsploit():
    try:
        logger.info("Running CloudSploit...")
        subprocess.run(['cloudsploit', 'scan', '--config', 'cloudsploit-config', '--output-format', 'json'], check=True)
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
