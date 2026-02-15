#!/bin/bash
# MCP Security Operations Suite — Environment Setup
# This script creates a .env template with all required variables.
# Fill in your values, then source it before starting MCP servers.

set -euo pipefail

ENV_FILE=".env"

if [ -f "$ENV_FILE" ]; then
    echo "⚠  .env file already exists. Backing up to .env.backup"
    cp "$ENV_FILE" "${ENV_FILE}.backup"
fi

cat > "$ENV_FILE" << 'ENVTEMPLATE'
# ============================================
# MCP Security Operations Suite — Environment
# ============================================
# Fill in ONLY the tools you plan to use.
# Leave others commented out or empty.

# --- SIEM & Monitoring ---

# Microsoft Sentinel
#AZURE_TENANT_ID=
#AZURE_CLIENT_ID=
#AZURE_CLIENT_SECRET=
#AZURE_SUBSCRIPTION_ID=
#SENTINEL_WORKSPACE_ID=
#SENTINEL_RESOURCE_GROUP=
#SENTINEL_WORKSPACE_NAME=

# Splunk
#SPLUNK_URL=https://splunk.company.com:8089
#SPLUNK_TOKEN=

# Elasticsearch
#ELASTICSEARCH_URL=https://elastic.company.com:9200
#ELASTICSEARCH_API_KEY=

# Datadog
#DD_API_KEY=
#DD_APP_KEY=
#DD_SITE=datadoghq.com

# --- Vulnerability Scanning ---

# Semgrep
#SEMGREP_APP_TOKEN=

# Snyk
#SNYK_TOKEN=
#SNYK_ORG_ID=

# GitHub (GHAS)
#GITHUB_TOKEN=ghp_xxxxxxxxxxxx
#GITHUB_OWNER=your-org

# StackHawk
#STACKHAWK_API_KEY=

# --- Threat Intelligence ---

# GreyNoise
#GREYNOISE_API_KEY=

# OpenCTI
#OPENCTI_URL=https://opencti.company.com
#OPENCTI_TOKEN=

# VirusTotal
#VT_API_KEY=

# --- Cloud Security ---

# Prowler (AWS)
#AWS_ACCESS_KEY_ID=
#AWS_SECRET_ACCESS_KEY=
#AWS_DEFAULT_REGION=us-east-1

# Cloudflare
#CLOUDFLARE_API_TOKEN=
#CLOUDFLARE_ACCOUNT_ID=

# --- Secrets & Identity ---

# HashiCorp Vault
#VAULT_ADDR=https://vault.company.com
#VAULT_TOKEN=

# Vault Radar (HCP)
#HCP_CLIENT_ID=
#HCP_CLIENT_SECRET=
#HCP_PROJECT_ID=

# Okta
#OKTA_ORG_URL=https://company.okta.com
#OKTA_API_TOKEN=

# --- Compliance ---

# Drata
#DRATA_API_KEY=

# Vanta
#VANTA_API_TOKEN=

# --- Ticketing & Notifications ---

# Jira
#JIRA_URL=https://company.atlassian.net
#JIRA_EMAIL=service-account@company.com
#JIRA_API_TOKEN=

# Slack
#SLACK_BOT_TOKEN=xoxb-xxxxxxxxxxxx
#SLACK_TEAM_ID=
ENVTEMPLATE

echo "✅ Created $ENV_FILE template"
echo ""
echo "Next steps:"
echo "  1. Edit $ENV_FILE and fill in credentials for your tools"
echo "  2. Uncomment only the variables you need"
echo "  3. Run: source $ENV_FILE"
echo "  4. IMPORTANT: Add .env to .gitignore!"
echo ""

# Add .env to .gitignore if not already there
if [ -f ".gitignore" ]; then
    if ! grep -q "^\.env$" .gitignore; then
        echo ".env" >> .gitignore
        echo "📝 Added .env to .gitignore"
    fi
else
    echo ".env" > .gitignore
    echo "📝 Created .gitignore with .env entry"
fi
