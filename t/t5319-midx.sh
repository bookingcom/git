#!/bin/sh

test_description='multi-pack-indexes'
. ./test-lib.sh

test_expect_success 'write midx with no pakcs' '
	git midx --object-dir=. write
'

test_done
