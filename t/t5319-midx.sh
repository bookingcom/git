#!/bin/sh

test_description='multi-pack-indexes'
. ./test-lib.sh

midx_read_expect() {
	cat >expect <<- EOF
	header: 4d494458 1 1 0 0
	object_dir: .
	EOF
	git midx read --object-dir=. >actual &&
	test_cmp expect actual
}

test_expect_success 'write midx with no packs' '
	git midx --object-dir=. write &&
	test_path_is_file pack/multi-pack-index &&
	midx_read_expect
'

test_done
