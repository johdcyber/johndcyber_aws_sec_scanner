FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y git curl npm autoconf libtool unzip && \
    apt-get clean

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws/

# Install CloudMapper
RUN git clone https://github.com/duo-labs/cloudmapper.git /opt/cloudmapper && \
    cd /opt/cloudmapper && \
    pip install -r requirements.txt

# Install ScoutSuite
RUN git clone https://github.com/nccgroup/ScoutSuite.git /opt/scoutsuite && \
    cd /opt/scoutsuite && \
    pip install -r requirements.txt

# Install Prowler
RUN git clone https://github.com/prowler-cloud/prowler.git /opt/prowler

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Install IAM_SCANNER
RUN git clone https://github.com/johdcyber/IAM_SCANNER.git /opt/iam_scanner && \
    pip install boto3 pandas

COPY entrypoint.sh /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
