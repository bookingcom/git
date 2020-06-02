#!/bin/sh

test_description="Tests performance of hash-object"
. ./perf-lib.sh

test_perf_fresh_repo

test_lazy_prereq SHA1SUM_AND_SANE_DD_AND_URANDOM '
	>empty &&
	sha1sum empty >empty.sha1sum &&
	grep -q -w da39a3ee5e6b4b0d3255bfef95601890afd80709 empty.sha1sum &&
	dd if=/dev/urandom of=random.test bs=1024 count=1 &&
	stat -c %s random.test >random.size &&
	grep -q -x 1024 random.size
'

if test_have_prereq !SHA1SUM_AND_SANE_DD_AND_URANDOM
then
	skip_all='failed prereq check for sha1sum/dd/stat'
	test_perf 'dummy p0013 test (skipped all tests)' 'true'
	test_done
fi

test_expect_success 'setup 64MB file.random file' '
	dd if=/dev/urandom of=file.random count=$((64*1024)) bs=1024
'

test_perf 'sha1sum(1) on file.random (for comparison)' '
	sha1sum file.random
'

for threshold in 32M 64M
do
	for write in '' ' -w'
	do
		for literally in ' --literally -t commit' ''
		do
			test_perf "'git hash-object$write$literally <file>' with threshold=$threshold" "
				git -c core.bigFileThreshold=$threshold hash-object$write$literally file.random
			"

			test_perf "'git hash-object$write$literally --stdin < <file>' with threshold=$threshold" "
				git -c core.bigFileThreshold=$threshold hash-object$write$literally --stdin <file.random
			"

			test_perf "'echo <file> | git hash-object$write$literally --stdin-paths' threshold=$threshold" "
				echo file.random | git -c core.bigFileThreshold=$threshold hash-object$write$literally --stdin-paths
			"
		done
	done
done

test_done
