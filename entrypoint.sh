#!/bin/bash

LOG_FILE="/app/johndcyber_aws_scan_results/scan_log.txt"
START_TIME=$(date +%s)

# Function to log messages
log_message() {
    local MESSAGE=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $MESSAGE" | tee -a $LOG_FILE
}

# Function to calculate and display ETA
calculate_eta() {
    local CURRENT_TIME=$(date +%s)
    local ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
    local PROGRESS=$1
    local TOTAL_STEPS=$2
    local ESTIMATED_TOTAL_TIME=$((ELAPSED_TIME * TOTAL_STEPS / PROGRESS))
    local ETA=$((ESTIMATED_TOTAL_TIME - ELAPSED_TIME))
    echo "Progress: $PROGRESS/$TOTAL_STEPS. Estimated time remaining: $ETA seconds."
}

log_message "Starting AWS Security Scanner..."

# Ensure AWS credentials are available
if [ ! -f ~/.aws/credentials ]; then
    log_message "AWS credentials not found in ~/.aws/credentials."
    exit 1
fi

# Create output directories
mkdir -p /app/johndcyber_aws_scan_results/cloudmapper
mkdir -p /app/johndcyber_aws_scan_results/scoutsuite
mkdir -p /app/johndcyber_aws_scan_results/prowler
mkdir -p /app/johndcyber_aws_scan_results/trivy

# Define total steps
TOTAL_STEPS=4
CURRENT_STEP=0

# Start Prowler scan
log_message "Starting Prowler scan..."
cd /opt/prowler
./prowler -M csv &>/app/johndcyber_aws_scan_results/prowler/prowler-report.csv &
PROWLER_PID=$!
CURRENT_STEP=$((CURRENT_STEP + 1))
calculate_eta $CURRENT_STEP $TOTAL_STEPS

# Start Trivy scan
log_message "Starting Trivy scan..."
/opt/trivy/trivy fs / --output /app/johndcyber_aws_scan_results/trivy/trivy-report.txt &
TRIVY_PID=$!
CURRENT_STEP=$((CURRENT_STEP + 1))
calculate_eta $CURRENT_STEP $TOTAL_STEPS

# Start CloudMapper scan
log_message "Starting CloudMapper scan..."
cd /opt/cloudmapper
python cloudmapper.py configure add-account --config config.json --name my_account --id $AWS_ACCOUNT_ID
python cloudmapper.py collect --account my_account
python cloudmapper.py prepare --account my_account
python cloudmapper.py report --account my_account &>/app/johndcyber_aws_scan_results/cloudmapper/report.html &
CLOUDMAPPER_PID=$!
CURRENT_STEP=$((CURRENT_STEP + 1))
calculate_eta $CURRENT_STEP $TOTAL_STEPS

# Start ScoutSuite scan
log_message "Starting ScoutSuite scan..."
cd /opt/scoutsuite
python scout.py aws --report-dir /opt/scoutsuite/reports &
SCOUTSUITE_PID=$!
CURRENT_STEP=$((CURRENT_STEP + 1))
calculate_eta $CURRENT_STEP $TOTAL_STEPS

#startingIAM_SCANNER
echo "Starting Johndcybers_IAM_SCANNER scan..."
cd /opt/iam_scanner
python iam_scanner.py -r us-east-1 -o /app/johndcyber_aws_scan_results/iam_scanner/results.json
IAM_SCANNER_PID=$!
CURRENT_STEP=$((CURRENT_STEP + 1))
calculate_eta $CURRENT_STEP $TOTAL_STEPS
echo "IAM_SCANNER scan completed."

# Wait for all scans to complete
log_message "Waiting for all scans to complete..."
wait $PROWLER_PID
log_message "Prowler scan completed."
wait $TRIVY_PID
log_message "Trivy scan completed."
wait $CLOUDMAPPER_PID
log_message "CloudMapper scan completed."
wait $SCOUTSUITE_PID
log_message "ScoutSuite scan completed."
wait $IAM_SCANNER_PID
log_message "IAM_SCANNER scan completed."

# Copy results to output directories
log_message "Copying results to output directories..."
cp -r /opt/prowler/output/* /app/johndcyber_aws_scan_results/prowler/
cp -r /opt/cloudmapper/report/* /app/johndcyber_aws_scan_results/cloudmapper/
cp -r /opt/scoutsuite/reports/* /app/johndcyber_aws_scan_results/scoutsuite/
cp -r /opt/iam_scanner/* /app/johndcyber_aws_scan_results/iam_scanner/

log_message "All scans completed and results saved to /app/johndcyber_aws_scan_results."

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
log_message "Total time taken: $TOTAL_TIME seconds."
