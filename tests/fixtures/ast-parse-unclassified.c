/* A warning category neither soundness code names, so it lands in the
   unclassified aggregate: calling a function with no declaration in scope. */
int implicit_warning(void) { return undeclared_function(); }
