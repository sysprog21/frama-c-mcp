/*
 * Regression for extractFunctionWithDeps missing ACSL-only type dependencies.
 * helper's C signature and body mention only public_state, while its ACSL
 * contract mentions private_state. Extracting wrapper must include
 * private_state because the helper contract is emitted into the sandbox.
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

/*@ requires \valid_read((private_state const *)p);
    requires ((private_state const *)p)->hidden >= 0;
    assigns \nothing;
 */
int helper(public_state const *p)
{
    return p->visible;
}

int wrapper(public_state const *p)
{
    return helper(p);
}
