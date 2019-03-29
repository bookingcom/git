#!/bin/sh

test_description="Tests core.validateAbbrev performance"

. ./perf-lib.sh

test_perf_large_repo

test_perf 'git log --oneline --raw --parents' '
	git -c core.abbrev=15 -c core.validateAbbrev=false log --oneline --raw --parents >/dev/null
'

test_done
