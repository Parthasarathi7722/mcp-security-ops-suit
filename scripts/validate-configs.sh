#!/bin/bash
# MCP Security Operations Suite — Config Validator
# Validates MCP config JSON files for syntax and required fields.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0
CHECKED=0

echo "🔍 Validating MCP configurations..."
echo ""

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    echo "Install: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

# Validate individual config files
for config in mcp-configs/**/*.json; do
    if [ ! -f "$config" ]; then
        continue
    fi

    CHECKED=$((CHECKED + 1))
    BASENAME=$(basename "$config")
    DIRNAME=$(dirname "$config" | xargs basename)

    # Check JSON syntax
    if ! jq empty "$config" 2>/dev/null; then
        echo -e "${RED}✗ $DIRNAME/$BASENAME — Invalid JSON syntax${NC}"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    # Check required fields
    NAME=$(jq -r '.name // empty' "$config")
    if [ -z "$NAME" ]; then
        echo -e "${RED}✗ $DIRNAME/$BASENAME — Missing 'name' field${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    COMMAND=$(jq -r '.config.command // empty' "$config")
    if [ -z "$COMMAND" ]; then
        echo -e "${RED}✗ $DIRNAME/$BASENAME — Missing 'config.command' field${NC}"
        ERRORS=$((ERRORS + 1))
    fi

    # Check for security notes
    SECURITY=$(jq -r '.security_notes // empty' "$config")
    if [ -z "$SECURITY" ]; then
        echo -e "${YELLOW}⚠ $DIRNAME/$BASENAME — Missing 'security_notes' field${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # Check for setup steps
    SETUP=$(jq -r '.setup_steps // empty' "$config")
    if [ -z "$SETUP" ]; then
        echo -e "${YELLOW}⚠ $DIRNAME/$BASENAME — Missing 'setup_steps' field${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi

    # All good
    if [ -n "$NAME" ] && [ -n "$COMMAND" ]; then
        echo -e "${GREEN}✓ $DIRNAME/$BASENAME — $NAME${NC}"
    fi
done

# Validate master config
echo ""
echo "🔍 Validating mcp_config.json..."
if [ -f "mcp_config.json" ]; then
    if jq empty mcp_config.json 2>/dev/null; then
        SERVER_COUNT=$(jq '[.mcpServers | keys[] | select(startswith("__") | not)] | length' mcp_config.json)
        echo -e "${GREEN}✓ mcp_config.json — Valid JSON, $SERVER_COUNT servers configured${NC}"
    else
        echo -e "${RED}✗ mcp_config.json — Invalid JSON syntax${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}⚠ mcp_config.json not found${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Results: $CHECKED configs checked"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}   ✓ $((CHECKED - ERRORS)) passed${NC}"
else
    echo -e "${RED}   ✗ $ERRORS errors${NC}"
fi
if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}   ⚠ $WARNINGS warnings${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit $ERRORS
