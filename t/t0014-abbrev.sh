#!/bin/sh

test_description='test core.abbrev and related features'

. ./test-lib.sh

tr_d_n() {
	tr -d '\n'
}

cut_tr_d_n_field_n() {
	cut -d " " -f $1 | tr_d_n
}

nocaret() {
	sed 's/\^//'
}

sed_g_tr_d_n() {
	sed 's/.*g//' | tr_d_n
}

test_expect_success 'setup' '
	test_commit A &&
	git tag -a -mannotated A.annotated &&
	test_commit B &&
	test_commit C &&
	mkdir X Y &&
	touch X/file1 Y/file2
'

test_expect_success 'the FALLBACK_DEFAULT_ABBREV is 7' '
	git log -1 --pretty=format:%h >log &&
	test_byte_count = 7 log
'

test_expect_success 'abbrev empty value handling differs ' '
	test_must_fail git -c core.abbrev= log -1 --pretty=format:%h 2>stderr &&
	test_i18ngrep "bad numeric config value.*invalid unit" stderr &&

	test_must_fail git branch -v --abbrev= 2>stderr &&
	test_i18ngrep "expects a value" stderr &&

	test_must_fail git log --abbrev= -1 --pretty=format:%h 2>stderr &&
	test_i18ngrep "expects a value" stderr &&

	test_must_fail git diff --raw --abbrev= HEAD~ 2>stderr &&
	test_i18ngrep "expects a value" stderr &&

	test_must_fail git diff --raw --abbrev= --no-index X Y 2>stderr &&
	test_i18ngrep "expects a value" stderr
'

test_expect_success 'abbrev non-integer value handling differs ' '
	test_must_fail git -c core.abbrev=XYZ log -1 --pretty=format:%h 2>stderr &&
	test_i18ngrep "bad numeric config value.*invalid unit" stderr &&

	test_must_fail git branch -v --abbrev=XYZ 2>stderr &&
	test_i18ngrep "expects a numerical value" stderr &&

	test_must_fail git log --abbrev=XYZ -1 --pretty=format:%h 2>stderr &&
	test_i18ngrep "expects a numerical value" stderr &&

	test_must_fail git diff --raw --abbrev=XYZ HEAD~ 2>stderr &&
	test_i18ngrep "expects a numerical value" stderr &&

	test_must_fail git diff --raw --abbrev=XYZ --no-index X Y 2>stderr &&
	test_i18ngrep "expects a numerical value" stderr
'

for i in -41 +41
do
	test_expect_success "core.abbrev value $i out of range errors out" "
		test_must_fail git -c core.abbrev=$i log -1 --pretty=format:%h 2>stderr &&
		test_i18ngrep 'impossibly out of range' stderr
	"
done

for i in -39 -20 -10 -3
do
	test_expect_success "negative -31..-3 --abbrev=$i mean --abbrev=4" "
		git log --abbrev=$i -1 --pretty=format:%h >log &&
		test_byte_count = 4 log
	"
done

for i in -9001 -41 +41 +9001
do
	test_expect_success "core.abbrev=$i and --abbrev=$i values out of range error out" "
		test_must_fail git -c core.abbrev=$i branch -v 2>stderr &&
		test_i18ngrep 'impossibly out of range' stderr &&
		test_must_fail git branch -v --abbrev=$i 2>stderr &&
		test_i18ngrep 'impossibly out of range' stderr
	"
done

for i in 0 1 2 3 4
do
	test_expect_success "non-negative --abbrev=$i value <MINIMUM_ABBREV falls back on MINIMUM_ABBREV" "
		git log --abbrev=$i -1 --pretty=format:%h >log &&
		test_byte_count = 4 log
	"
done

for i in 41 9001
do
	test_expect_success "non-negative --abbrev=$i value >MINIMUM_ABBREV falls back on 40" "
		git log --abbrev=$i -1 --pretty=format:%h >log &&
		test_byte_count = 40 log
	"
done

for i in $(test_seq 4 40)
do
	test_expect_success "core.abbrev=$i and --abbrev=$i in combination within the valid range" "
		# Both core.abbrev=X and --abbrev=X do the same thing
		# in isolation
		git -c core.abbrev=$i log -1 --pretty=format:%h >log &&
		test_byte_count = $i log &&
		git log --abbrev=$i -1 --pretty=format:%h >log &&
		test_byte_count = $i log &&

		# core.abbrev=+N is the same as core.abbrev=7+N
		git -c core.abbrev=+$i log -1 --pretty=format:%h >log &&
		if test \$((7 + $i)) -gt 40
		then
			test_byte_count = 40 log
		else
			test_byte_count = \$((7 + $i)) log
		fi &&

		# --abbrev=+N is the same as --abbrev=7+N
		git log --abbrev=+$i -1 --pretty=format:%h >log &&
		if test \$((7 + $i)) -gt 40
		then
			test_byte_count = 40 log
		else
			test_byte_count = \$((7 + $i)) log
		fi &&

		# The --abbrev option should take priority over
		# core.abbrev
		git -c core.abbrev=20 log --abbrev=$i -1 --pretty=format:%h >log &&
		test_byte_count = $i log
	"
done

for i in $(test_seq 4 40)
do
	for opt in --porcelain --line-porcelain
	do
		test_expect_success "blame $opt ignores core.abbrev=$i and --abbrev=$i" "
			git -c core.abbrev=$i blame $opt A.t | head -n 1 | cut_tr_d_n_field_n 1 >blame &&
			test_byte_count = 40 blame &&
			git blame $opt --abbrev=$i A.t | head -n 1 | cut_tr_d_n_field_n 1 >blame &&
			test_byte_count = 40 blame
		"
	done


	test_expect_success "blame core.abbrev=$i and --abbrev=$i with boundary" "
		# See the blame documentation for why this is off-by-one
		git -c core.abbrev=$i blame A.t | cut_tr_d_n_field_n 1 | nocaret >blame &&
		if test $i -eq 40
		then
			test_byte_count = 39 blame
		else
			test_byte_count = $i blame
		fi &&
		git blame --abbrev=$i A.t | cut_tr_d_n_field_n 1 | nocaret >blame &&
		if test $i -eq 40
		then
			test_byte_count = 39 blame
		else
			test_byte_count = $i blame
		fi
	"

	test_expect_success "blame core.abbrev=$i and --abbrev=$i without boundary" "
		git -c core.abbrev=$i blame B.t | cut_tr_d_n_field_n 1 | nocaret >blame &&
		if test $i -eq 40
		then
			test_byte_count = $i blame
		else
			test_byte_count = \$(($i + 1)) blame
		fi &&
		git blame --abbrev=$i B.t | cut_tr_d_n_field_n 1 | nocaret >blame &&
		if test $i -eq 40
		then
			test_byte_count = $i blame
		else
			test_byte_count = \$(($i + 1)) blame
		fi
	"
done

test_expect_success 'blame core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 blame A.t | cut_tr_d_n_field_n 1 >blame &&
	test_byte_count = 9 blame &&

	git -c core.abbrev=-1 blame A.t | cut_tr_d_n_field_n 1 >blame &&
	test_byte_count = 7 blame &&

	git blame --abbrev=+1 A.t | cut_tr_d_n_field_n 1 >blame &&
	test_byte_count = 9 blame &&

	git blame --abbrev=-1 A.t | cut_tr_d_n_field_n 1 >blame &&
	test_byte_count = 7 blame
'

for i in $(test_seq 4 40)
do
	test_expect_success "branch core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i branch -v | cut_tr_d_n_field_n 3 >branch &&
		test_byte_count = $i branch &&

		git branch --abbrev=$i -v | cut_tr_d_n_field_n 3 >branch &&
		test_byte_count = $i branch
	"
done

test_expect_success 'branch core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 branch -v | cut_tr_d_n_field_n 3 >branch &&
	test_byte_count = 8 branch &&

	git -c core.abbrev=-1 branch -v | cut_tr_d_n_field_n 3 >branch &&
	test_byte_count = 6 branch &&

	git branch -v --abbrev=+1 | cut_tr_d_n_field_n 3 >branch &&
	test_byte_count = 8 branch &&

	git branch -v --abbrev=-1 | cut_tr_d_n_field_n 3 >branch &&
	test_byte_count = 6 branch
'

test_expect_success 'describe core.abbrev and --abbrev special cases' '
	# core.abbrev=0 behaves as usual...
	test_must_fail git -c core.abbrev=0 describe &&

	# ...but --abbrev=0 is special-cased to print the nearest tag,
	# not fall back on "4" like git-log.
	echo A.annotated >expected &&
	git describe --abbrev=0 >actual &&
	test_cmp expected actual
'

for i in $(test_seq 4 40)
do
	test_expect_success "describe core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i describe | sed_g_tr_d_n >describe &&
		test_byte_count = $i describe &&
		git describe --abbrev=$i | sed_g_tr_d_n >describe &&
		test_byte_count = $i describe
	"
done

test_expect_success 'describe core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=-1 describe | sed_g_tr_d_n >describe &&
	test_byte_count = 6 describe &&

	git -c core.abbrev=+1 describe | sed_g_tr_d_n >describe &&
	test_byte_count = 8 describe &&

	git describe --abbrev=-1 | sed_g_tr_d_n >describe &&
	test_byte_count = 6 describe &&

	git describe --abbrev=+1 | sed_g_tr_d_n >describe &&
	test_byte_count = 8 describe
'

for i in $(test_seq 4 40)
do
	test_expect_success "log core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i log --pretty=format:%h -1 | tr_d_n >log &&
		test_byte_count = $i log &&
		git log --abbrev=$i --pretty=format:%h -1 | tr_d_n >log &&
		test_byte_count = $i log
	"
done

test_expect_success 'log core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 log --pretty=format:%h -1 >log &&
	test_byte_count = 8 log &&

	git -c core.abbrev=-1 log --pretty=format:%h -1 >log &&
	test_byte_count = 6 log &&

	git log --abbrev=+1 --pretty=format:%h -1 | tr_d_n >log &&
	test_byte_count = 8 log &&

	git log --abbrev=-1 --pretty=format:%h -1 | tr_d_n >log &&
	test_byte_count = 6 log
'

for i in $(test_seq 4 40)
do
	test_expect_success "diff --no-index --raw core.abbrev=$i and --abbrev=$i" "
		test_must_fail git -c core.abbrev=$i diff --no-index --raw X Y >diff &&
		cut_tr_d_n_field_n 3 <diff >diff.3 &&
		test_byte_count = $i diff.3 &&
		cut_tr_d_n_field_n 4 <diff >diff.4 &&
		test_byte_count = $i diff.4 &&

		test_must_fail git diff --no-index --raw --abbrev=$i X Y >diff &&
		cut_tr_d_n_field_n 3 <diff >diff.3 &&
		test_byte_count = $i diff.3 &&
		cut_tr_d_n_field_n 4 <diff >diff.4 &&
		test_byte_count = $i diff.4
	"

	test_expect_success "diff --raw core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i diff --raw HEAD~ >diff &&
		cut_tr_d_n_field_n 3 <diff >diff.3 &&
		test_byte_count = $i diff.3 &&
		cut_tr_d_n_field_n 4 <diff >diff.4 &&
		test_byte_count = $i diff.4 &&

		git diff --raw --abbrev=$i HEAD~ >diff &&
		cut_tr_d_n_field_n 3 <diff >diff.3 &&
		test_byte_count = $i diff.3 &&
		cut_tr_d_n_field_n 4 <diff >diff.4 &&
		test_byte_count = $i diff.4
	"
done

test_expect_success 'diff --no-index --raw core.abbrev=[-+]1 and --abbrev=[-+]1' '
	test_must_fail git -c core.abbrev=+1 diff --no-index --raw X Y >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 8 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 8 diff.4 &&

	test_must_fail git -c core.abbrev=-1 diff --no-index --raw X Y >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 6 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 6 diff.4 &&

	test_must_fail git diff --no-index --raw --abbrev=+1 X Y >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 8 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 8 diff.4 &&

	test_must_fail git diff --no-index --raw --abbrev=-1 X Y >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 6 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 6 diff.4
'

test_expect_success 'diff --raw core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 diff --raw HEAD~ >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 8 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 8 diff.4 &&

	git -c core.abbrev=-1 diff --raw HEAD~ >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 6 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 6 diff.4 &&

	git diff --raw --abbrev=+1 --raw HEAD~ >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 8 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 8 diff.4 &&

	git diff --raw --abbrev=-1 --raw HEAD~ >diff &&
	cut_tr_d_n_field_n 3 <diff >diff.3 &&
	test_byte_count = 6 diff.3 &&
	cut_tr_d_n_field_n 4 <diff >diff.4 &&
	test_byte_count = 6 diff.4
'

for i in $(test_seq 4 40)
do
	test_expect_success "ls-files core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i ls-files --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
		test_byte_count = 40 ls-files &&
		git ls-files --abbrev=$i --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
		test_byte_count = $i ls-files
	"
done

test_expect_success 'ls-files core.abbrev=[-+]1 and --abbrev=[-+]1' '
	test_must_fail git -c core.abbrev=+1 ls-files --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
	test_byte_count = 40 ls-files &&

	test_must_fail git -c core.abbrev=-1 ls-files --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
	test_byte_count = 40 ls-files &&

	git ls-files --abbrev=-1 --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
	test_byte_count = 6 ls-files &&

	git ls-files --abbrev=+1 --stage A.t | cut_tr_d_n_field_n 2 >ls-files &&
	test_byte_count = 8 ls-files
'

for i in $(test_seq 4 40)
do
	test_expect_success "ls-tree core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i ls-tree HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
		test_byte_count = 40 ls-tree &&
		git ls-tree --abbrev=$i HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
		test_byte_count = $i ls-tree
	"
done

test_expect_success 'ls-tree core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 ls-tree HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
	test_byte_count = 40 ls-tree &&

	git -c core.abbrev=-1 ls-tree HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
	test_byte_count = 40 ls-tree &&

	git ls-tree --abbrev=-1 HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
	test_byte_count = 6 ls-tree &&

	git ls-tree --abbrev=+1 HEAD A.t | cut -f 1 | cut_tr_d_n_field_n 3 >ls-tree &&
	test_byte_count = 8 ls-tree
'

for i in $(test_seq 4 40)
do
	test_expect_success "show-ref core.abbrev=$i and --abbrev=$i" "
		git -c core.abbrev=$i show-ref --hash refs/heads/master | tr_d_n >show-ref &&
		test_byte_count = 40 show-ref &&
		git show-ref --hash --abbrev=$i refs/heads/master | tr_d_n >show-ref &&
		test_byte_count = $i show-ref &&
		git show-ref --hash=$i refs/heads/master | tr_d_n >show-ref &&
		test_byte_count = $i show-ref
	"
done

test_expect_success 'show-ref core.abbrev=[-+]1 and --abbrev=[-+]1' '
	git -c core.abbrev=+1 show-ref --hash refs/heads/master | tr_d_n >show-ref &&
	test_byte_count = 40 show-ref &&

	git -c core.abbrev=-1 show-ref --hash refs/heads/master | tr_d_n >show-ref &&
	test_byte_count = 40 show-ref &&

	git show-ref --abbrev=-1 --hash refs/heads/master | tr_d_n >show-ref &&
	test_byte_count = 6 show-ref &&

	git show-ref --abbrev=+1 --hash refs/heads/master | tr_d_n >show-ref &&
	test_byte_count = 8 show-ref
'

test_done
