# Testing with tpkg, tdir, and do-tests

`tdir` (`mini_tdir.sh`) can be used to execute singular tdir tests
`tpkg` (`mini_tpkg.sh`) can be used to execute singular tpkg tests

`do-tests` runs a long list of tests.

## Requirements for `do-tests`

- `tdir`
    - e.g. `ln -s $PWD/mini_tdir.sh ~/.local/bin/tdir`
- `streamtcp`
    - Clone unbound repo and build `streamtcp`, e.g.
        - `./configure && make streamtcp`
        - `ln -s $PWD/streamtcp ~/.local/bin/streamtcp`
- configure NSD with `--enable-checking`, else clang-analysis will fail
