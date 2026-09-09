// ═══════════════════════════════════════════════════════════════════
// Safe Buffer Module — Comprehensive MCP verification workflow test
// ═══════════════════════════════════════════════════════════════════
//
// Verification targets by tool:
//   get_wp_goals alarms: unsafe_read (array bounds), unsafe_avg (div-by-zero)
//   get_wp_goals      : buf_push (provable), buf_get (provable),
//                        echo (named: ok=provable, ko=unprovable)
//   context eva_value : marker from buf_push body
//   get_wp_goals investigation : alarms from unsafe_read and unsafe_avg
//   context callers  : buf_get called by buf_sum and run
//   context call_chain: main → run → buf_sum → buf_get (4 levels)
//   context symbol    : data[], count, error_code (globals)
//   context current_annotations : buf_push has behaviors
//   suggest_plan      : EVA alarms → suggest WP; WP unknown → suggest review
//
// Call graph:
//   main ──→ run ──→ buf_push
//       │        ├──→ buf_sum ──→ buf_get
//       │        └──→ buf_avg ──→ buf_sum ──→ buf_get
//       ├──→ unsafe_read
//       ├──→ unsafe_avg
//       └──→ echo

// ── Globals ──

#define CAPACITY 16

int data[CAPACITY];
int count = 0;
int error_code = 0;  // 0=ok, -1=full, -2=oob

// ── buf_push: behaviors + assigns — WP provable ──

/*@ requires 0 <= count <= CAPACITY;
    assigns data[0 .. CAPACITY-1], count, error_code;
    behavior ok:
      assumes count < CAPACITY;
      ensures count == \old(count) + 1;
      ensures data[\old(count)] == val;
      ensures error_code == 0;
      ensures \result == 0;
    behavior full:
      assumes count >= CAPACITY;
      ensures count == \old(count);
      ensures error_code == -1;
      ensures \result == -1;
    complete behaviors;
    disjoint behaviors;
*/
int buf_push(int val)
{
    if (count >= CAPACITY) {
        error_code = -1;
        return -1;
    }
    data[count] = val;
    count++;
    error_code = 0;
    return 0;
}

// ── buf_get: simple contract — WP provable ──

/*@ requires 0 <= count <= CAPACITY;
    requires 0 <= idx < count;
    assigns \nothing;
    ensures \result == data[idx];
*/
int buf_get(int idx)
{
    return data[idx];
}

// ── buf_sum: loop + calls buf_get ──

/*@ requires 0 <= count <= CAPACITY;
    assigns \nothing;
*/
int buf_sum(void)
{
    int s = 0;
    /*@ loop invariant 0 <= i <= count;
        loop assigns i, s;
        loop variant count - i;
    */
    for (int i = 0; i < count; i++) {
        s += buf_get(i);
    }
    return s;
}

// ── buf_avg: division — safe with precondition ──

/*@ requires 0 < count <= CAPACITY;
    assigns \nothing;
*/
int buf_avg(void)
{
    return buf_sum() / count;
}

// ── echo: named ensures — ok is provable, ko is NOT ──
//    This follows the Frama-C WP test pattern (unit_bit_test.c)

/*@ assigns \nothing;
    ensures correct: \result == x;
    ensures wrong: \result > 0;
*/
int echo(int x)
{
    return x;
}

// ── unsafe_read: NO precondition — EVA array bounds alarm ──

int unsafe_read(int idx)
{
    return data[idx];  // EVA alarm: idx may be out of bounds
}

// ── unsafe_avg: NO precondition — EVA division-by-zero alarm ──

int unsafe_avg(void)
{
    return buf_sum() / count;  // EVA alarm: count could be 0 at this point
}

// ── run: Level 1 — orchestrates buffer operations ──

int run(int a, int b, int c)
{
    buf_push(a);
    buf_push(b);
    buf_push(c);
    int total = buf_sum();
    int avg = buf_avg();
    return total + avg;
}

// ── main: entry point with non-deterministic input ──

volatile int nondet;

int main(void)
{
    // Phase 1: known values
    int result = run(10, 20, 30);

    // Phase 2: potential alarms
    int idx = nondet;            // EVA: unknown value
    int val = unsafe_read(idx);  // EVA alarm: array bounds

    int saved_count = count;
    count = 0;               // force count=0
    int avg = unsafe_avg();  // EVA alarm: division by zero
    count = saved_count;

    // Phase 3: WP test
    int e = echo(0);  // WP: ensures wrong: \result > 0 fails

    return result + val + avg + e;
}
