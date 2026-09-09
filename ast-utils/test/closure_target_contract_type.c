/*
 * Fixture for closure ACSL dep scanning tests (target contract path).
 *
 * Covers test_target_contract_type_deps_collected.
 *
 * Target = `target_with_struct_contract`. Its own contract references struct
 * Bar via cast (struct Bar not in signature). After
 * clone_closure(["target_with_struct_contract"]):
 *   - struct Bar in composites
 *   - struct UnusedT must NOT appear
 */

struct Bar {
    int by;
};
struct UnusedT {
    int u;
};

/*@ requires \valid((struct Bar *)p);
    ensures *p == 0;
    assigns *p;
 */
void target_with_struct_contract(int *p)
{
    *p = 0;
}
