#!/bin/sh

"$@"
EXIT_CODE=$?
npx playwright merge-reports --config=playwright-merge.config.ts blob-report/
exit $EXIT_CODE
