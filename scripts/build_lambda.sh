#!/bin/bash
# Build script for Lambda function packaging
# Installs Python dependencies into the Lambda source directory
# so CDK can bundle them into the deployment asset.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LAMBDA_DIR="$PROJECT_ROOT/lambda/process_findings"

echo "Installing Lambda dependencies into $LAMBDA_DIR ..."
pip install -r "$LAMBDA_DIR/requirements.txt" -t "$LAMBDA_DIR" --upgrade --quiet

echo "Done. Lambda is ready for deployment."
echo ""
echo "Next steps:"
echo "  cd infrastructure"
echo "  cdk deploy"
