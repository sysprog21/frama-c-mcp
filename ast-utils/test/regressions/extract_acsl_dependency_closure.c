/*
 * Regression for extractFunctionWithDeps's ACSL-aware dependency closure. The
 * wrapper body only calls helper. The helper contract and ambient ACSL theory
 * mention C types, C globals, logic functions, predicates, axiomatic
 * declarations, logic types, and inductive predicates that are otherwise absent
 * from wrapper's C body.
 */

typedef struct public_state {
    int visible;
} public_state;

struct private_state;
typedef struct private_state private_state;

struct private_state {
    public_state pub;
    int hidden;
};

int lower_bound;
int contract_state;
int callback(int x);

/*@ type model_tag; */

/*@ logic integer bias(integer x) = x + lower_bound; */

/*@ predicate model_ok(public_state *p) =
      \valid_read((private_state *)p) &&
      ((private_state *)p)->hidden >= lower_bound;
 */

/*@ predicate spare_model(integer x) = bias(x) <= 100; */

/*@ predicate callback_available(integer x) = \valid_function(callback); */

/*@ axiomatic ModelAx {
      logic integer twice(integer x);
      axiom twice_nonneg: \forall integer x; x >= 0 ==> twice(x) >= 0;
    }
 */

/*@ inductive nat(integer x) {
      case nat_zero: nat(0);
      case nat_step: \forall integer x; nat(x) ==> nat(x + 1);
    }
 */

/*@ requires model_ok(p);
    requires nat(p->visible);
    requires callback_available(p->visible);
    assigns contract_state;
    ensures contract_state == \old(contract_state) + 1;
 */
int helper(public_state *p)
{
    return p->visible;
}

int wrapper(public_state *p)
{
    return helper(p);
}
