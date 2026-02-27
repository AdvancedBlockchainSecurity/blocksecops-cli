#!/usr/bin/env bash
# Apogee pre-commit hook
# Scans staged smart contract files for security vulnerabilities

set -e

# Configuration (can be overridden with environment variables)
APOGEE_FAIL_ON="${APOGEE_FAIL_ON:-high}"
APOGEE_TIMEOUT="${APOGEE_TIMEOUT:-300}"
APOGEE_OUTPUT="${APOGEE_OUTPUT:-table}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if 0xapogee is installed
if ! command -v 0xapogee &> /dev/null; then
    echo -e "${RED}Error: 0xapogee CLI is not installed${NC}"
    echo "Install with: pip install 0xapogee-cli"
    exit 1
fi

# Check if authenticated
if ! 0xapogee auth status &> /dev/null; then
    echo -e "${YELLOW}Warning: Not authenticated with Apogee${NC}"
    echo "Run: 0xapogee auth login"
    exit 0  # Don't block commit if not authenticated
fi

# Get staged files with smart contract extensions
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sol|vy|rs)$' || true)

if [ -z "$STAGED_FILES" ]; then
    # No smart contract files staged
    exit 0
fi

echo -e "${GREEN}Apogee: Scanning staged smart contracts...${NC}"
echo ""

# Count files
FILE_COUNT=$(echo "$STAGED_FILES" | wc -l | tr -d ' ')
echo "Found $FILE_COUNT smart contract file(s) to scan:"
echo "$STAGED_FILES" | sed 's/^/  - /'
echo ""

# Track if any scan fails
SCAN_FAILED=0
CRITICAL_FOUND=0
HIGH_FOUND=0

# Scan each file
for FILE in $STAGED_FILES; do
    if [ -f "$FILE" ]; then
        echo -e "Scanning: ${YELLOW}$FILE${NC}"

        # Run scan and capture exit code
        if 0xapogee scan run "$FILE" \
            --output "$APOGEE_OUTPUT" \
            --fail-on "$APOGEE_FAIL_ON" \
            2>&1; then
            echo -e "${GREEN}  No critical/high vulnerabilities found${NC}"
        else
            EXIT_CODE=$?
            if [ $EXIT_CODE -eq 1 ]; then
                echo -e "${RED}  Vulnerabilities found at or above $APOGEE_FAIL_ON severity${NC}"
                SCAN_FAILED=1
            else
                echo -e "${RED}  Scan error (exit code: $EXIT_CODE)${NC}"
                # Don't fail on scan errors, just warn
            fi
        fi
        echo ""
    fi
done

if [ $SCAN_FAILED -eq 1 ]; then
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}Commit blocked: Security vulnerabilities found${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Options:"
    echo "  1. Fix the vulnerabilities and try again"
    echo "  2. Run with --no-verify to skip this check (not recommended)"
    echo "     git commit --no-verify -m 'your message'"
    echo "  3. Adjust the severity threshold with APOGEE_FAIL_ON=critical"
    echo ""
    exit 1
fi

echo -e "${GREEN}All security checks passed!${NC}"
exit 0
