/*
 * Regression for printSource use-before-declare bug. Prior to commit de1d45c,
 * printSource used extract_multiple which emitted GVar globals (Phase A) before
 * forward-declaring target functions (Phase B), producing output where tbl's
 * initializer referenced foo/bar before their declarations. Re-parsing such
 * output failed with "Cannot resolve variable foo". Fix switched printSource to
 * Printer.pp_file, which respects AST order. This fixture + regression harness
 * locks the round-trip contract.
 */

int foo(int x)
{
    return x + 1;
}
int bar(int x)
{
    return x * 2;
}

int (*const tbl[])(int) = {&foo, &bar};

int dispatch(int idx, int v)
{
    return tbl[idx](v);
}
