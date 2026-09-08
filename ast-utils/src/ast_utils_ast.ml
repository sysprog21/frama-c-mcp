(** ast_utils_ast.ml — CIL AST → JSON serialization.

    Converts Frama-C CIL internal representation to JSON objects
    suitable for consumption by LLM-based verification agents. *)

open Frama_c_kernel
open Cil_types

(* ====== Utilities ====== *)

let pp_to_string pp x =
  Format.asprintf "%a" pp x

(* ====== Variable info ====== *)

let varinfo_to_json (vi : varinfo) : Yojson.Basic.t =
  `Assoc [
    ("name", `String vi.vname);
    ("type", `String (pp_to_string Printer.pp_typ vi.vtype));
    ("vid", `Int vi.vid);
    ("ghost", `Bool vi.vghost);
  ]

(* ====== Labels ====== *)

let label_to_json (l : label) : Yojson.Basic.t =
  match l with
  | Label (name, _, _) -> `Assoc [("label", `String name)]
  | Case (exp, _) -> `Assoc [("case", `String (pp_to_string Printer.pp_exp exp))]
  | Default _ -> `Assoc [("default", `Bool true)]

let labels_to_json (labels : label list) : (string * Yojson.Basic.t) list =
  match labels with
  | [] -> []
  | _ -> [("labels", `List (List.map label_to_json labels))]

(* ====== Annotations ====== *)

let annotations_to_json (s : stmt) : (string * Yojson.Basic.t) list =
  let annots = Annotations.code_annot s in
  match annots with
  | [] -> []
  | _ ->
    let texts = List.map (fun ca ->
      `String (pp_to_string Printer.pp_code_annotation ca)
    ) annots in
    [("annotations", `List texts)]

(* ====== Instructions ====== *)

(** Extract callee function name from a call host.
    For direct calls like [f(args)], returns the function name.
    For indirect calls through function pointers, falls back to pretty-printing. *)
let extract_callee_name (fn : lhost) : string =
  match fn with
  | Var vi -> vi.vname
  | _ -> pp_to_string Printer.pp_lhost fn

let instr_to_json (i : instr) : Yojson.Basic.t option =
  match i with
  | Set _ ->
    Some (`Assoc [
      ("kind", `String "set");
      ("code", `String (pp_to_string Printer.pp_instr i));
    ])
  | Call (_, fn, args, _) ->
    let actuals = List.map (fun a ->
      `String (pp_to_string Printer.pp_exp a)
    ) args in
    Some (`Assoc [
      ("kind", `String "call");
      ("code", `String (pp_to_string Printer.pp_instr i));
      ("callee", `String (extract_callee_name fn));
      ("actuals", `List actuals);
    ])
  | Local_init (vi, AssignInit (SingleInit e), _) ->
    let code = Format.asprintf "%a %s = %a;"
      Printer.pp_typ vi.vtype vi.vname Printer.pp_exp e in
    Some (`Assoc [
      ("kind", `String "set");
      ("code", `String code);
    ])
  | Local_init (_, ConsInit (f, args, _), _) ->
    let actuals = List.map (fun a ->
      `String (pp_to_string Printer.pp_exp a)
    ) args in
    Some (`Assoc [
      ("kind", `String "call");
      ("code", `String (pp_to_string Printer.pp_instr i));
      ("callee", `String f.vname);
      ("actuals", `List actuals);
    ])
  | Local_init (_vi, AssignInit (CompoundInit _), _) ->
    Some (`Assoc [
      ("kind", `String "set");
      ("code", `String (pp_to_string Printer.pp_instr i));
    ])
  | Asm _ ->
    Some (`Assoc [
      ("kind", `String "asm");
      ("code", `String (pp_to_string Printer.pp_instr i));
    ])
  | Skip _ -> None
  | Code_annot (ca, _) ->
    Some (`Assoc [
      ("kind", `String "annotation");
      ("text", `String (pp_to_string Printer.pp_code_annotation ca));
    ])

(* ====== Statements ====== *)

let rec stmt_to_json (s : stmt) : Yojson.Basic.t =
  let base =
    [("sid", `Int s.sid);
     ("pred_sids", `List (List.map (fun p -> `Int p.sid) s.preds));
     ("succ_sids", `List (List.map (fun p -> `Int p.sid) s.succs))]
    @ labels_to_json s.labels
    @ annotations_to_json s
  in
  let kind_fields =
    match s.skind with
    | Instr i ->
      (match instr_to_json i with
       | Some j -> [("kind", `String "instr"); ("instr", j)]
       | None -> [("kind", `String "skip")])
    | Return (e_opt, _) ->
      let expr = match e_opt with
        | Some e -> `String (pp_to_string Printer.pp_exp e)
        | None -> `Null
      in
      [("kind", `String "return"); ("expr", expr)]
    | If (e, tb, fb, _) ->
      [("kind", `String "if");
       ("cond", `String (pp_to_string Printer.pp_exp e));
       ("then_body", `List (block_to_json tb));
       ("else_body", `List (block_to_json fb))]
    | Loop (_, b, _, _, _) ->
      [("kind", `String "loop");
       ("body", `List (block_to_json b))]
    | Block b ->
      [("kind", `String "block");
       ("stmts", `List (block_to_json b))]
    | Switch (e, _, cases, _) ->
      let case_labels = List.filter_map (fun cs ->
        let case_vals = List.filter_map (fun l ->
          match l with
          | Case (exp, _) -> Some (pp_to_string Printer.pp_exp exp)
          | _ -> None
        ) cs.labels in
        let is_default = List.exists (fun l ->
          match l with Default _ -> true | _ -> false
        ) cs.labels in
        if case_vals <> [] || is_default then
          let fields = [("sid", `Int cs.sid)] in
          let fields = if case_vals <> [] then
            fields @ [("values", `List (List.map (fun v -> `String v) case_vals))]
          else fields in
          let fields = if is_default then
            fields @ [("default", `Bool true)]
          else fields in
          Some (`Assoc fields)
        else None
      ) cases in
      [("kind", `String "switch");
       ("expr", `String (pp_to_string Printer.pp_exp e));
       ("cases", `List case_labels)]
    | Goto (s_ref, _) ->
      [("kind", `String "goto");
       ("target_sid", `Int (!s_ref).sid)]
    | Break _ ->
      [("kind", `String "break")]
    | Continue _ ->
      [("kind", `String "continue")]
    | UnspecifiedSequence seq ->
      let stmts = List.map (fun (s, _, _, _, _) -> stmt_to_json s) seq in
      [("kind", `String "block");
       ("stmts", `List stmts)]
    | Throw _ | TryCatch _ | TryFinally _ | TryExcept _ ->
      [("kind", `String "unsupported");
       ("text", `String (pp_to_string Printer.pp_stmt s))]
  in
  `Assoc (base @ kind_fields)

and block_to_json (b : block) : Yojson.Basic.t list =
  List.map stmt_to_json b.bstmts

(* ====== Entry point ====== *)

let get_function_ast (kf : kernel_function) : Yojson.Basic.t =
  let fundec = Kernel_function.get_definition kf in
  let name = Kernel_function.get_name kf in
  let signature = pp_to_string Printer.pp_vdecl (Kernel_function.get_vi kf) in
  let formals = List.map varinfo_to_json (Kernel_function.get_formals kf) in
  let locals = List.map varinfo_to_json fundec.slocals in
  let ret_type = pp_to_string Printer.pp_typ (Kernel_function.get_return_type kf) in
  let body = block_to_json fundec.sbody in
  `Assoc [
    ("name", `String name);
    ("signature", `String signature);
    ("formals", `List formals);
    ("locals", `List locals);
    ("return_type", `String ret_type);
    ("body", `List body);
  ]

let loc_to_json loc =
  if Ast_utils_compat.loc_is_unknown loc then `Null
  else
    `Assoc [
      ("file", `String (Ast_utils_compat.loc_file loc));
      ("line", `Int (Ast_utils_compat.loc_line loc));
      ("col", `Int (Ast_utils_compat.loc_col loc));
    ]

let stmt_kind_name s =
  match s.skind with
  | Instr _ -> "instr"
  | Return _ -> "return"
  | If _ -> "if"
  | Loop _ -> "loop"
  | Block _ -> "block"
  | Switch _ -> "switch"
  | Goto _ -> "goto"
  | Break _ -> "break"
  | Continue _ -> "continue"
  | UnspecifiedSequence _ -> "block"
  | Throw _ | TryCatch _ | TryFinally _ | TryExcept _ -> "unsupported"

let acsl_targets_for_stmt s =
  let base = ["assert"] in
  let targets = match s.skind with
    | Loop _ -> "loop invariant" :: "loop assigns" :: "loop variant" :: base
    | _ -> base
  in
  `List (List.map (fun target -> `String target) targets)

let c_label_name = function
  | Label (name, _, _) -> Some name
  | _ -> None

let stmt_context_to_json s =
  `Assoc [
    ("sid", `Int s.sid);
    ("kinstr", `Assoc [("kind", `String "Kstmt"); ("sid", `Int s.sid)]);
    ("kind", `String (stmt_kind_name s));
    ("loc", loc_to_json (Cil_datatype.Stmt.loc s));
    ("c_labels", `List (List.map label_to_json s.labels));
    ("annotations", `List (List.map (fun ca ->
      `String (pp_to_string Printer.pp_code_annotation ca)
    ) (Annotations.code_annot s)));
    ("acsl_attachment_points", acsl_targets_for_stmt s);
  ]

let rec collect_stmt_contexts acc s =
  let acc = stmt_context_to_json s :: acc in
  match s.skind with
  | If (_, tb, fb, _) ->
    collect_block_contexts (collect_block_contexts acc tb) fb
  | Loop (_, b, _, _, _) | Block b ->
    collect_block_contexts acc b
  | Switch (_, b, _, _) ->
    collect_block_contexts acc b
  | UnspecifiedSequence seq ->
    List.fold_left (fun acc (s, _, _, _, _) -> collect_stmt_contexts acc s) acc seq
  | TryCatch (b, catches, _) ->
    List.fold_left
      (fun acc (_, b) -> collect_block_contexts acc b)
      (collect_block_contexts acc b)
      catches
  | TryFinally (b, final, _) | TryExcept (b, _, final, _) ->
    collect_block_contexts (collect_block_contexts acc b) final
  | _ -> acc

and collect_block_contexts acc b =
  List.fold_left collect_stmt_contexts acc b.bstmts

let global_var_to_json vi init =
  let fields = [
    ("name", `String vi.vname);
    ("type", `String (pp_to_string Printer.pp_typ vi.vtype));
    ("vid", `Int vi.vid);
    ("loc", loc_to_json vi.vdecl);
  ] in
  match init.init with
  | Some value ->
    `Assoc (("init", `String (pp_to_string Printer.pp_init_or_str value)) :: fields)
  | None -> `Assoc fields

(* Whether a write to this lvalue is visible outside the function.

   A Var host answers directly. A Mem host is a write through a pointer, and
   the pointer may be built from several variables, so the question is whether
   any of them is global. Both serializers below need the same answer. *)
let lval_touches_global lv =
  match lv with
  | Var vi, _ -> vi.vglob
  | Mem _, _ ->
    Cil_datatype.Varinfo.Set.fold
      (fun vi acc -> acc || vi.vglob)
      (Cil.extract_varinfos_from_lval lv)
      false

let lval_base = function
  | Var vi, _ -> vi.vname
  | Mem _, _ -> ""

let modified_lval_name lv =
  match lval_base lv with
  | "" -> pp_to_string Printer.pp_lval lv
  | base -> base

let lval_access_to_json sid loc kind lv =
  let global = lval_touches_global lv in
  `Assoc [
    ("sid", `Int sid);
    ("loc", loc_to_json loc);
    ("kind", `String kind);
    ("target", `String (pp_to_string Printer.pp_lval lv));
    ("base", `String (lval_base lv));
    ("global", `Bool global);
  ]

let from_to_json = function
  | FromAny -> `Null
  | From terms ->
    `List (List.map (fun t ->
      `String (pp_to_string Printer.pp_identified_term t)
    ) terms)

(* The component an assigns target writes.

   Not the object it is reached through: "a->base" and "a->cap" are both rooted
   at "a", and a contract constraining "a->off" says nothing about either while
   mentioning "a" in the process, so comparing roots silences every field of a
   written object at once.

   Computed from the term rather than from its printed form. A reader that
   recovers it by scanning "*(buf + (0 .. len - 1))" is parsing ACSL to answer
   a question the AST already holds, and doing so reported the bound "len" as
   the location written. *)
(* The last field or model field the offset selects, if any. A range or an
   index selects no component of its own, so it falls through to whatever
   encloses it. *)
let rec offset_leaf_name = function
  | TNoOffset -> None
  | TField (fi, next) ->
    (match offset_leaf_name next with Some _ as deeper -> deeper | None -> Some fi.fname)
  | TModel (mi, next) ->
    (match offset_leaf_name next with Some _ as deeper -> deeper | None -> Some mi.mi_name)
  | TIndex (_, next) -> offset_leaf_name next

let rec term_leaf_name t =
  match t.term_node with
  | TLval (host, offset) | TAddrOf (host, offset) | TStartOf (host, offset) ->
    (match offset_leaf_name offset with
     | Some _ as field -> field

     (* Still in leaf mode across the dereference. Delegating to the root
        walker here answered "a" for "*(a->base + ...)", which is the object
        the pointer was reached through rather than the field written, and a
        contract constraining any other field of that object then silenced the
        finding. *)
     | None ->
       (match host with
        | TMem inner -> term_leaf_name inner
        | TVar lv -> Some lv.lv_name
        | TResult _ -> Some "result"))
  | TUnOp (_, t) | Tat (t, _) -> term_leaf_name t
  | TCast (_, _, t) -> term_leaf_name t
  (* Only the left operand. Frama-C normalizes pointer arithmetic so the
     pointer sits there, and falling back to the right hands back the index
     when the left is a shape this does not walk, which is a wrong name where
     no name would have routed the caller to its own fallback. *)
  | TBinOp (_, left, _) -> term_leaf_name left
  | _ -> None

let name_json = function
  | Some name -> `String name
  | None -> `Null

let assigns_to_json assigns =
  match assigns with
  | WritesAny ->
    `Assoc [
      ("kind", `String "any");
      ("assigns", `List []);
    ]
  | Writes entries ->
    let items = List.map (fun (target, froms) ->
      `Assoc [
        ("target", `String (pp_to_string Printer.pp_identified_term target));

        (* The component written, which is what a postcondition has to mention
           to constrain this location. Null where the term is a shape this does
           not walk, so a reader falls back rather than trusting a wrong name. *)
        ("leaf", name_json (term_leaf_name target.it_content));
        ("froms", from_to_json froms);
      ]
    ) entries in
    `Assoc [
      ("kind", `String (if entries = [] then "nothing" else "list"));
      ("assigns", `List items);
    ]

let behavior_assigns_to_json bhv =
  match assigns_to_json bhv.b_assigns with
  | `Assoc fields ->
    `Assoc (("behavior", `String bhv.b_name) :: fields)
  | json -> json

let callee_assigns_to_json kf =
  let spec = Annotations.funspec kf in
  `Assoc [
    ("function", `String (Kernel_function.get_name kf));
    ("assigns", assigns_to_json (Ast_info.merge_assigns_from_spec ~warn:false spec));
    ("behaviors", `List (List.map behavior_assigns_to_json spec.spec_behavior));
  ]

let kernel_function_of_varinfo vi =
  try Some (Globals.Functions.get vi)
  with Not_found ->
    try Some (Globals.Functions.find_by_name vi.vname)
    with Not_found -> None

let identified_predicate_to_json ip =
  let pred_kind = match ip.ip_content.tp_kind with
    | Assert -> "assert"
    | Check -> "check"
    | Admit -> "admit"
  in
  `Assoc [
    ("id", `Int ip.ip_id);
    ("kind", `String pred_kind);
    ("predicate", `String (pp_to_string Printer.pp_predicate ip.ip_content.tp_statement));
    ("text", `String (pp_to_string Printer.pp_identified_predicate ip));
  ]

let assumes_texts bhv =
  List.map identified_predicate_to_json bhv.b_assumes

let behavior_predicate_to_json bhv ip =
  `Assoc [
    ("behavior", `String bhv.b_name);
    ("assumes", `List (assumes_texts bhv));
    ("predicate", identified_predicate_to_json ip);
  ]

let post_condition_to_json bhv (kind, ip) =
  `Assoc [
    ("behavior", `String bhv.b_name);
    ("assumes", `List (assumes_texts bhv));
    ("kind", `String (Cil_printer.get_termination_kind_name kind));
    ("predicate", identified_predicate_to_json ip);
  ]

let behavior_contract_to_json bhv =
  `Assoc [
    ("name", `String bhv.b_name);
    ("assumes", `List (assumes_texts bhv));
    ("requires", `List (List.map identified_predicate_to_json bhv.b_requires));
    ("ensures", `List (List.map (post_condition_to_json bhv) bhv.b_post_cond));
    ("assigns", assigns_to_json bhv.b_assigns);
  ]

let funspec_to_json spec =
  let behavior_groups groups =
    `List (List.map (fun names ->
      `List (List.map (fun name -> `String name) names)
    ) groups)
  in
  `Assoc [
    ("empty", `Bool (Cil.is_empty_funspec spec));
    ("requires", `List (List.concat (List.map (fun bhv ->
      List.map (behavior_predicate_to_json bhv) bhv.b_requires
    ) spec.spec_behavior)));
    ("ensures", `List (List.concat (List.map (fun bhv ->
      List.map (post_condition_to_json bhv) bhv.b_post_cond
    ) spec.spec_behavior)));
    ("assigns", assigns_to_json (Ast_info.merge_assigns_from_spec ~warn:false spec));
    ("behaviors", `List (List.map behavior_contract_to_json spec.spec_behavior));
    ("complete", behavior_groups spec.spec_complete_behaviors);
    ("disjoint", behavior_groups spec.spec_disjoint_behaviors);
  ]

let function_contract_to_json kf =
  let vi = Kernel_function.get_vi kf in
  `Assoc [
    ("function", `String (Kernel_function.get_name kf));
    ("signature", `String (pp_to_string Printer.pp_vdecl vi));
    ("loc", loc_to_json (Kernel_function.get_location kf));
    ("contract", funspec_to_json (Annotations.funspec kf));
  ]

let logic_label_to_string = function
  | BuiltinLabel l -> pp_to_string Printer.pp_logic_builtin_label l
  | FormalLabel s -> s
  | StmtLabel sref ->
    match List.filter_map c_label_name (!sref).labels with
    | name :: _ -> name
    | [] -> Printf.sprintf "stmt:%d" (!sref).sid

let logic_info_ref_to_json li =
  let kind = match li.l_type with
    | None -> "predicate"
    | Some _ -> "function"
  in
  `Assoc [
    ("name", `String li.l_var_info.lv_name);
    ("id", `Int li.l_var_info.lv_id);
    ("kind", `String kind);
    ("labels", `List (List.map (fun label ->
      `String (logic_label_to_string label)
    ) li.l_labels));
    ("type_parameters", `List (List.map (fun name -> `String name) li.l_tparams));
    ("parameters", `List (List.map (fun lv ->
      `Assoc [
        ("name", `String lv.lv_name);
        ("id", `Int lv.lv_id);
        ("type", `String (pp_to_string Printer.pp_logic_type lv.lv_type));
      ]
    ) li.l_profile));
    ("return_type", match li.l_type with
      | None -> `Null
      | Some lt -> `String (pp_to_string Printer.pp_logic_type lt));
  ]

let logic_type_ref_to_json lti =
  `Assoc [
    ("name", `String lti.lt_name);
    ("parameters", `List (List.map (fun name -> `String name) lti.lt_params));
  ]

class logic_deps_visitor = object
  inherit Cil.nopCilVisitor

  val logic_infos : (int, logic_info) Hashtbl.t = Hashtbl.create 16
  val logic_types : (string, logic_type_info) Hashtbl.t = Hashtbl.create 16

  method! vlogic_info_use li =
    Hashtbl.replace logic_infos li.l_var_info.lv_id li;
    DoChildren

  method! vlogic_type_info_use lti =
    Hashtbl.replace logic_types lti.lt_name lti;
    DoChildren

  method result : Yojson.Basic.t =
    let infos = Hashtbl.fold (fun _ li acc -> li :: acc) logic_infos [] in
    let types = Hashtbl.fold (fun _ lti acc -> lti :: acc) logic_types [] in
    let by_logic_name a b =
      compare a.l_var_info.lv_name b.l_var_info.lv_name
    in
    let by_type_name a b = compare a.lt_name b.lt_name in
    let infos = List.sort by_logic_name infos in
    let functions, predicates =
      List.partition (fun li -> li.l_type <> None) infos
    in
    `Assoc [
      ("logic_functions", `List (List.map logic_info_ref_to_json functions));
      ("logic_predicates", `List (List.map logic_info_ref_to_json predicates));
      ("logic_types", `List (List.map logic_type_ref_to_json
                              (List.sort by_type_name types)));
    ]
end

let logic_deps_of_funspec spec =
  let visitor = new logic_deps_visitor in
  ignore (Cil.visitCilFunspec (visitor :> Cil.cilVisitor) spec);
  visitor#result

let logic_deps_of_identified_predicate ip =
  let visitor = new logic_deps_visitor in
  ignore (Cil.visitCilIdPredicate (visitor :> Cil.cilVisitor) ip);
  visitor#result

let logic_deps_of_assigns assigns =
  let visitor = new logic_deps_visitor in
  ignore (Cil.visitCilAssigns (visitor :> Cil.cilVisitor) assigns);
  visitor#result

let logic_deps_of_code_annotation ca =
  let visitor = new logic_deps_visitor in
  ignore (Cil.visitCilCodeAnnotation (visitor :> Cil.cilVisitor) ca);
  visitor#result

let predicate_clause_deps bhv kind ip =
  `Assoc [
    ("kind", `String kind);
    ("behavior", `String bhv.b_name);
    ("text", `String (pp_to_string Printer.pp_identified_predicate ip));
    ("deps", logic_deps_of_identified_predicate ip);
  ]

let post_clause_deps bhv (term_kind, ip) =
  match predicate_clause_deps bhv "ensures" ip with
  | `Assoc fields ->
    `Assoc (("termination", `String (Cil_printer.get_termination_kind_name term_kind)) :: fields)
  | json -> json

(* The text is real ACSL, so a reader can paste it back. That is a change from
   the constructor dump this used to emit, which was only available on 33
   anyway: Cil_types gained its deriving-show printers there, and 32.1 has no
   Cil_types.pp_assigns at all.

   WritesAny is spelled out rather than printed. Printer.pp_assigns emits
   nothing for it, and an empty text reads as "assigns nothing" to anyone who
   does not already know the constructor. WritesAny means the opposite: no
   clause was written, so the function may write anything, which is the
   unsound-by-default case a frame condition has to account for. *)
let assigns_clause_deps bhv =
  let text = match bhv.b_assigns with
    | WritesAny -> "assigns \\everything;"
    | Writes _ -> pp_to_string Printer.pp_assigns bhv.b_assigns
  in
  `Assoc [
    ("kind", `String "assigns");
    ("behavior", `String bhv.b_name);
    ("text", `String text);
    ("deps", logic_deps_of_assigns bhv.b_assigns);
  ]

let behavior_clause_deps bhv =
  List.map (predicate_clause_deps bhv "assumes") bhv.b_assumes
  @ List.map (predicate_clause_deps bhv "requires") bhv.b_requires
  @ List.map (post_clause_deps bhv) bhv.b_post_cond
  @ [assigns_clause_deps bhv]

let contract_logic_deps spec =
  `Assoc [
    ("deps", logic_deps_of_funspec spec);
    ("clauses", `List (List.concat (List.map behavior_clause_deps spec.spec_behavior)));
  ]

let get_logic_deps (kf : kernel_function) : Yojson.Basic.t =
  let annotation_deps =
    try
      let fundec = Kernel_function.get_definition kf in
      List.concat (List.map (fun stmt ->
        List.map (fun ca ->
          `Assoc [
            ("sid", `Int stmt.sid);
            ("loc", loc_to_json (Cil_datatype.Stmt.loc stmt));
            ("text", `String (pp_to_string Printer.pp_code_annotation ca));
            ("deps", logic_deps_of_code_annotation ca);
          ]
        ) (Annotations.code_annot stmt)
      ) fundec.sallstmts)
    with Kernel_function.No_Definition -> []
  in
  `Assoc [
    ("function", `String (Kernel_function.get_name kf));
    ("contract", contract_logic_deps (Annotations.funspec kf));
    ("annotations", `List annotation_deps);
  ]

let rte_obligation_to_json kf stmt ~rank alarm ca =
  let prop =
    try Some (Property.ip_of_code_annot_single kf stmt ca)
    with _ -> None
  in
  let loc =
    match prop with
    | Some prop -> Property.location prop
    | None -> Cil_datatype.Stmt.loc stmt
  in
  let predicate =
    match ca.annot_content with
    | AAssert (_, {tp_statement; _}) ->
      Some (pp_to_string Printer.pp_predicate tp_statement)
    | _ -> None
  in
  let fields = [
    ("sid", `Int stmt.sid);
    ("loc", loc_to_json loc);
    ("stmt_loc", loc_to_json (Cil_datatype.Stmt.loc stmt));
    ("rank", `Int rank);
    ("annot_id", `Int ca.annot_id);
    ("kind", `String (Alarms.get_name alarm));
    ("short_kind", `String (Alarms.get_short_name alarm));
    ("description", `String (Alarms.get_description alarm));
    ("text", `String (pp_to_string Printer.pp_code_annotation ca));
  ] in
  let fields = match prop with
    | Some prop ->
      ("property_marker", `String (pp_to_string Property.pretty prop))
      :: fields
    | None -> fields
  in
  match predicate with
  | Some text -> `Assoc (("predicate", `String text) :: fields)
  | None -> `Assoc fields

let get_rte_obligations (kf : kernel_function) obligations : Yojson.Basic.t =
  `Assoc [
    ("function", `String (Kernel_function.get_name kf));
    ("count", `Int (List.length obligations));
    ("obligations", `List obligations);
  ]

let assigns_targets assigns =
  match assigns with
  | WritesAny -> ["\\everything"]
  | Writes entries ->
    List.map (fun (target, _) ->
      pp_to_string Printer.pp_identified_term target
    ) entries

let call_context_to_json sid loc ret fn args =
  let fields = [
    ("sid", `Int sid);
    ("loc", loc_to_json loc);
    ("callee", `String (extract_callee_name fn));
    ("actuals", `List (List.map (fun a ->
      `String (pp_to_string Printer.pp_exp a)
    ) args));
  ] in
  match ret with
  | Some lv -> `Assoc (("result", `String (pp_to_string Printer.pp_lval lv)) :: fields)
  | None -> `Assoc fields

class cil_context_visitor = object(self)
  inherit Cil.nopCilVisitor

  val mutable current_sid = -1
  val mutable calls : Yojson.Basic.t list = []
  val mutable memory_accesses : Yojson.Basic.t list = []
  val mutable logic_labels = []

  method private add_write loc lv =
    memory_accesses <- lval_access_to_json current_sid loc "write" lv :: memory_accesses

  method private add_read loc lv =
    memory_accesses <- lval_access_to_json current_sid loc "read" lv :: memory_accesses

  method private add_address loc lv =
    memory_accesses <- lval_access_to_json current_sid loc "address" lv :: memory_accesses

  method private add_logic_label label =
    if not (List.mem label logic_labels) then
      logic_labels <- label :: logic_labels

  method! vstmt s =
    current_sid <- s.sid;
    DoChildren

  method! vinst i =
    (match i with
     | Set (lv, _, loc) ->
       self#add_write loc lv
     | Call (ret, fn, args, loc) ->
       calls <- call_context_to_json current_sid loc ret fn args :: calls;
       (match ret with Some lv -> self#add_write loc lv | None -> ())
     | Local_init (vi, ConsInit (callee, args, _), loc) ->
       self#add_write loc (Var vi, NoOffset);
       calls <- call_context_to_json current_sid loc (Some (Var vi, NoOffset)) (Var callee) args :: calls
     | Local_init (vi, AssignInit _, loc) ->
       self#add_write loc (Var vi, NoOffset)
     | _ -> ());
    DoChildren

  method! vexpr e =
    (match e.enode with
     | Lval lv -> self#add_read e.eloc lv
     | AddrOf lv | StartOf lv -> self#add_address e.eloc lv
     | _ -> ());
    DoChildren

  method! vlogic_label label =
    self#add_logic_label (logic_label_to_string label);
    DoChildren

  method result : Yojson.Basic.t =
    `Assoc [
      ("calls", `List (List.rev calls));
      ("memory_accesses", `List (List.rev memory_accesses));
      ("logic_labels", `List (List.rev_map (fun label -> `String label) logic_labels));
    ]
end

let builtin_logic_labels =
  ["Here"; "Old"; "Pre"; "Post"; "LoopEntry"; "LoopCurrent"; "Init"]

let get_cil_context (kf : kernel_function) : Yojson.Basic.t =
  let fundec = Kernel_function.get_definition kf in
  let visitor = new cil_context_visitor in
  ignore (Cil.visitCilFunction (visitor :> Cil.cilVisitor) fundec);
  let globals = Globals.Vars.fold_in_file_order
    (fun vi init acc -> global_var_to_json vi init :: acc)
    []
    |> List.rev
  in
  let statements = List.rev (collect_block_contexts [] fundec.sbody) in
  let loops = List.filter_map (function
    | `Assoc fields as stmt ->
      (match List.assoc_opt "kind" fields with
       | Some (`String "loop") -> Some stmt
       | _ -> None)
    | _ -> None
  ) statements in
  let c_labels = List.fold_left (fun acc stmt ->
    match stmt with
    | `Assoc fields ->
      (match List.assoc_opt "c_labels" fields with
       | Some (`List labels) ->
         List.fold_left (fun acc label ->
           match label with
           | `Assoc fields ->
             (match List.assoc_opt "label" fields with
              | Some (`String name) when not (List.mem name acc) -> name :: acc
              | _ -> acc)
           | _ -> acc
         ) acc labels
       | _ -> acc)
    | _ -> acc
  ) [] statements in
  match visitor#result with
  | `Assoc effect_fields ->
    let seen_logic_labels = match List.assoc_opt "logic_labels" effect_fields with
      | Some (`List labels) -> List.filter_map (function `String s -> Some s | _ -> None) labels
      | _ -> []
    in
    let logic_labels = List.fold_left (fun acc label ->
      if List.mem label acc then acc else label :: acc
    ) [] (builtin_logic_labels @ List.rev c_labels @ seen_logic_labels) in
    `Assoc ([
      ("name", `String (Kernel_function.get_name kf));
      ("formals", `List (List.map varinfo_to_json (Kernel_function.get_formals kf)));
      ("locals", `List (List.map varinfo_to_json fundec.slocals));
      ("globals", `List globals);
      ("statements", `List statements);
      ("loops", `List loops);
      ("logic_labels", `List (List.map (fun label -> `String label) logic_labels));
      ("function_acsl_attachment_points",
       `List [`String "requires"; `String "ensures"; `String "assigns"; `String "behavior"]);
      ("body", `List (block_to_json fundec.sbody));
    ] @ List.remove_assoc "logic_labels" effect_fields)
  | json -> json

class loop_write_visitor = object(self)
  inherit Cil.nopCilVisitor

  val mutable current_sid = -1
  val mutable writes : Yojson.Basic.t list = []
  val mutable modified_vars = []
  val mutable loop_local_vids = []
  val mutable callees = []

  method private add_modified lv =
    let is_loop_local = match lv with
      | Var vi, _ -> List.mem vi.vid loop_local_vids
      | Mem _, _ -> false
    in
    let name = modified_lval_name lv in
    if not is_loop_local && name <> "" && not (List.mem name modified_vars) then
      modified_vars <- name :: modified_vars

  method private add_write loc lv =
    writes <- lval_access_to_json current_sid loc "write" lv :: writes;
    self#add_modified lv

  method private add_callee vi =
    match kernel_function_of_varinfo vi with
    | Some kf ->
      if not (List.exists (Kernel_function.equal kf) callees) then
        callees <- kf :: callees
    | None -> ()

  method private add_callee_assigns vi =
    self#add_callee vi;
    match kernel_function_of_varinfo vi with
    | Some kf ->
      let spec = Annotations.funspec kf in
      let targets = assigns_targets (Ast_info.merge_assigns_from_spec ~warn:false spec) in
      List.iter (fun target ->
        if target <> "" && not (List.mem target modified_vars) then
          modified_vars <- target :: modified_vars
      ) targets
    | None -> ()

  method! vstmt s =
    current_sid <- s.sid;
    DoChildren

  method! vinst i =
    (match i with
     | Set (lv, _, loc) ->
       self#add_write loc lv
     | Call (ret, fn, _, loc) ->
       (match ret with Some lv -> self#add_write loc lv | None -> ());
       (match fn with
        | Var vi -> self#add_callee_assigns vi
        | _ -> ())
     | Local_init (vi, ConsInit (callee, _, _), loc) ->
       loop_local_vids <- vi.vid :: loop_local_vids;
       writes <- lval_access_to_json current_sid loc "write" (Var vi, NoOffset) :: writes;
       self#add_callee_assigns callee
     | Local_init (vi, AssignInit _, loc) ->
       loop_local_vids <- vi.vid :: loop_local_vids;
       writes <- lval_access_to_json current_sid loc "write" (Var vi, NoOffset) :: writes
     | _ -> ());
    DoChildren

  method result : Yojson.Basic.t =
    `Assoc [
      ("writes", `List (List.rev writes));
      ("modified_vars", `List (List.rev_map (fun name -> `String name) modified_vars));
      ("callee_assigns", `List (List.rev_map callee_assigns_to_json callees));
    ]
end

let loop_effect_to_json loop_stmt body =
  let visitor = new loop_write_visitor in
  ignore (Cil.visitCilBlock (visitor :> Cil.cilVisitor) body);
  match visitor#result with
  | `Assoc fields ->
    `Assoc ([
      ("stmt_id", `Int loop_stmt.sid);
      ("loc", loc_to_json (Cil_datatype.Stmt.loc loop_stmt));
    ] @ fields)
  | json -> json

let rec collect_loop_effects acc s =
  match s.skind with
  | Loop (_, b, _, _, _) ->
    let acc = loop_effect_to_json s b :: acc in
    collect_block_loop_effects acc b
  | If (_, tb, fb, _) ->
    collect_block_loop_effects (collect_block_loop_effects acc tb) fb
  | Block b | Switch (_, b, _, _) ->
    collect_block_loop_effects acc b
  | UnspecifiedSequence seq ->
    List.fold_left (fun acc (s, _, _, _, _) -> collect_loop_effects acc s) acc seq
  | TryCatch (b, catches, _) ->
    List.fold_left
      (fun acc (_, b) -> collect_block_loop_effects acc b)
      (collect_block_loop_effects acc b)
      catches
  | TryFinally (b, final, _) | TryExcept (b, _, final, _) ->
    collect_block_loop_effects (collect_block_loop_effects acc b) final
  | _ -> acc

and collect_block_loop_effects acc b =
  List.fold_left collect_loop_effects acc b.bstmts

let get_loop_effects (kf : kernel_function) : Yojson.Basic.t =
  let fundec = Kernel_function.get_definition kf in
  `List (List.rev (collect_block_loop_effects [] fundec.sbody))

let direct_write_to_json line lv =
  let global = lval_touches_global lv in
  `Assoc [
    ("line", `Int line);
    ("target", `String (pp_to_string Printer.pp_lval lv));
    ("base", `String (lval_base lv));
    ("global", `Bool global);
  ]

class write_effects_visitor = object(self)
  inherit Cil.nopCilVisitor

  val mutable writes : Yojson.Basic.t list = []
  val mutable callees = []
  val mutable unresolved : Yojson.Basic.t list = []

  method private add_write line lv =
    writes <- direct_write_to_json line lv :: writes

  method private add_callee vi =
    match kernel_function_of_varinfo vi with
    | Some kf ->
      if not (List.exists (Kernel_function.equal kf) callees) then
        callees <- kf :: callees
    | None -> ()

  (* An instruction whose writes cannot be enumerated. A call through a
     function pointer names no callee to read an assigns clause from, and
     inline assembly is opaque to CIL, so both write an unknown set. Recorded
     rather than skipped: a reader that sees no entry concludes nothing was
     written, and a frame condition built on that is wrong in the direction
     that lets a proof through. *)
  method private add_unresolved kind line =
    unresolved <- `Assoc [("kind", `String kind); ("line", `Int line)] :: unresolved

  method! vinst i =
    (match i with
     | Set (lv, _, loc) ->
       self#add_write (Ast_utils_compat.loc_line loc) lv
     | Call (Some lv, fn, _, loc) ->
       self#add_write (Ast_utils_compat.loc_line loc) lv;
       (match fn with
        | Var vi -> self#add_callee vi
        | _ -> self#add_unresolved "indirect_call" (Ast_utils_compat.loc_line loc))
     | Call (None, fn, _, loc) ->
       (match fn with
        | Var vi -> self#add_callee vi
        | _ -> self#add_unresolved "indirect_call" (Ast_utils_compat.loc_line loc))
     | Asm (_, _, _, loc) ->
       self#add_unresolved "inline_asm" (Ast_utils_compat.loc_line loc)
     | Local_init (vi, ConsInit (callee, _, _), loc) ->
       self#add_write (Ast_utils_compat.loc_line loc) (Var vi, NoOffset);
       self#add_callee callee
     | Local_init (vi, AssignInit _, loc) ->
       self#add_write (Ast_utils_compat.loc_line loc) (Var vi, NoOffset)
     | _ -> ());
    DoChildren

  method result : Yojson.Basic.t =
    `Assoc [
      ("writes", `List (List.rev writes));
      ("callee_assigns", `List (List.rev_map callee_assigns_to_json callees));
      ("unresolved", `List (List.rev unresolved));
    ]
end

let get_write_effects (kf : kernel_function) : Yojson.Basic.t =
  let fundec = Kernel_function.get_definition kf in
  let visitor = new write_effects_visitor in
  ignore (Cil.visitCilFunction (visitor :> Cil.cilVisitor) fundec);
  visitor#result

class direct_callee_visitor = object(self)
  inherit Cil.nopCilVisitor

  val mutable current_sid = -1
  val mutable callees = []
  val mutable unresolved : Yojson.Basic.t list = []

  method private add_callee vi =
    match kernel_function_of_varinfo vi with
    | Some kf ->
      if not (List.exists (Kernel_function.equal kf) callees) then
        callees <- kf :: callees
    | None -> ()

  method private add_unresolved sid loc fn =
    unresolved <- `Assoc [
      ("sid", `Int sid);
      ("loc", loc_to_json loc);
      ("callee", `String (pp_to_string Printer.pp_lhost fn));
    ] :: unresolved

  method! vstmt s =
    current_sid <- s.sid;
    DoChildren

  method! vinst i =
    (match i with
     | Call (_, Var vi, _, _) ->
       self#add_callee vi
     | Call (_, fn, _, loc) ->
       self#add_unresolved current_sid loc fn
     | Local_init (_, ConsInit (callee, _, _), _) ->
       self#add_callee callee
     | _ -> ());
    DoChildren

  method callees = List.rev callees
  method unresolved = List.rev unresolved
end

let direct_call_info_of_kf kf =
  try
    let fundec = Kernel_function.get_definition kf in
    let visitor = new direct_callee_visitor in
    ignore (Cil.visitCilFunction (visitor :> Cil.cilVisitor) fundec);
    (visitor#callees, visitor#unresolved)
  with Kernel_function.No_Definition -> ([], [])

let direct_callees_of_kf kf =
  fst (direct_call_info_of_kf kf)

let direct_callers_of_kf target =
  Globals.Functions.fold (fun kf acc ->
    if Kernel_function.equal kf target then acc
    else
      let callees = direct_callees_of_kf kf in
      if List.exists (Kernel_function.equal target) callees then kf :: acc else acc
  ) []
  |> List.rev

(* The functions a proof of this program still needs a contract for.

   Seeded from every defined function that already carries a contract, walked
   down the syntactic call graph, and reporting the defined functions reached
   that way which carry none. That is the specification frontier of the
   reviewed artifact: the work list a person has to write, as opposed to
   ASSUMED_CALLEE_CONTRACT, which is one hop from whatever a check happened to
   target and answers about one proof rather than about the program.

   Emptiness of the funspec is the test rather than its presence. Frama-C
   generates a default spec for every function, so "Annotations.has_funspec"
   answers true for a function nobody ever specified, and seeding from that
   would put the whole program in the reachable set and report nothing.

   The unresolved call sites travel with it. A frontier computed over a call
   graph that silently dropped the calls through function pointers is a work
   list that under-reports, and the caller cannot tell that from a short one. *)

let kf_is_defined kf =
  try ignore (Kernel_function.get_definition kf); true
  with Kernel_function.No_Definition -> false

let kf_has_contract kf =
  let spec = Annotations.funspec kf in
  not (Cil.is_empty_funspec spec)

let frontier_function_to_json kf callers =
  `Assoc [
    ("function", `String (Kernel_function.get_name kf));
    ("loc", loc_to_json (Kernel_function.get_location kf));
    ("called_by",
     `List (List.map (fun caller -> `String (Kernel_function.get_name caller)) callers));
  ]

let unresolved_site_to_json kf site =
  match site with
  | `Assoc fields -> `Assoc (("function", `String (Kernel_function.get_name kf)) :: fields)
  | other -> other

let get_contract_frontier () : Yojson.Basic.t =
  let defined = Globals.Functions.fold
      (fun kf acc -> if kf_is_defined kf then kf :: acc else acc) []
  in

  (* The kernel's own collections over Kernel_function, rather than two local
     Make applications of the comparator it already carries. *)
  let module KfSet = Kernel_function.Set in
  let module KfMap = Kernel_function.Map in

  (* One AST walk per defined function, and only one. Three consumers below
     read the call graph: the downward walk, the callers reported beside each
     frontier entry, and the unresolved sites. Asking the visitor again for
     each of them made the callers alone cost one walk per (missing, defined)
     pair, so a thousand-function program with five hundred uncontracted
     callees ran half a million whole-body visits inside the single request
     this tool exists to answer in one round trip. *)
  let call_info =
    List.fold_left
      (fun acc kf -> KfMap.add kf (direct_call_info_of_kf kf) acc)
      KfMap.empty defined
  in
  let call_info_of kf =
    match KfMap.find_opt kf call_info with Some pair -> pair | None -> ([], [])
  in
  let callees_of kf = fst (call_info_of kf) in
  let unresolved_of kf = snd (call_info_of kf) in

  (* Inverted once, in the traversal order the fold visits, so each entry's
     "called_by" reads the way a per-function query used to answer. A function
     never lists itself.

     "defined" is already reverse-Globals order and "add" prepends, so folding
     it directly puts each list in Globals order, which is what a per-function
     query yields. Folding the reversal and reversing again on every lookup
     reached the same order by doing the work twice. *)
  let callers_of =
    let add acc caller callee =
      if Kernel_function.equal caller callee then acc
      else
        let previous = match KfMap.find_opt callee acc with Some l -> l | None -> [] in
        if List.exists (Kernel_function.equal caller) previous then acc
        else KfMap.add callee (caller :: previous) acc
    in
    let table =
      List.fold_left
        (fun acc caller -> List.fold_left (fun acc callee -> add acc caller callee)
            acc (callees_of caller))
        KfMap.empty defined
    in
    fun kf -> match KfMap.find_opt kf table with Some l -> l | None -> []
  in

  (* Worklist from the contracted functions downwards. A function is in the
     reachable set when a contracted function calls it, directly or through
     other functions; a contracted function is not itself in it, since the
     question is what the contracts already written do not cover. *)
  (* One funspec lookup per defined function. Annotations.funspec materialises
     the default spec rather than answering from a cache, and this predicate was
     asked three times for every function: once to seed the queue, once to
     filter the missing list, once more to count. That is 2n avoidable calls in
     the request whose whole claim is that it answers in one round trip, and the
     call graph directly above already went to some trouble to be walked once. *)
  let contracted =
    List.fold_left
      (fun acc kf -> if kf_has_contract kf then KfSet.add kf acc else acc)
      KfSet.empty defined
  in
  let queue = Queue.create () in
  List.iter (fun kf -> if KfSet.mem kf contracted then Queue.add kf queue) defined;
  let reachable = ref KfSet.empty in

  (* Every body the walk actually read: the contracted seeds plus everything
     reached from them. Kept because the unresolved sites below are a statement
     about this walk, and a function outside it was never looked down. *)
  let walked = ref KfSet.empty in
  while not (Queue.is_empty queue) do
    let caller = Queue.take queue in
    walked := KfSet.add caller !walked;
    List.iter
      (fun callee ->
         if kf_is_defined callee && not (KfSet.mem callee !reachable) then begin
           reachable := KfSet.add callee !reachable;
           Queue.add callee queue
         end)
      (callees_of caller)
  done;

  let missing =
    List.filter (fun kf -> KfSet.mem kf !reachable && not (KfSet.mem kf contracted)) defined
  in
  let missing =
    List.sort
      (fun a b ->
         let file kf = Ast_utils_compat.loc_file (Kernel_function.get_location kf) in
         let line kf = Ast_utils_compat.loc_line (Kernel_function.get_location kf) in
         let c = String.compare (file a) (file b) in
         if c <> 0 then c
         else
           let c = Int.compare (line a) (line b) in
           if c <> 0 then c
           else String.compare (Kernel_function.get_name a) (Kernel_function.get_name b))
      missing
  in
  let unresolved =
    List.concat_map
      (fun kf -> List.map (unresolved_site_to_json kf) (unresolved_of kf))
      (List.sort
         (fun a b -> String.compare (Kernel_function.get_name a) (Kernel_function.get_name b))
         (List.filter (fun kf -> KfSet.mem kf !walked) defined))
  in
  `Assoc [
    ("contracted_count", `Int (KfSet.cardinal contracted));
    ("defined_count", `Int (List.length defined));
    ("missing_count", `Int (List.length missing));
    ("missing",
     `List (List.map (fun kf -> frontier_function_to_json kf (callers_of kf)) missing));

    (* Not a detail of the list above. A call this walk could not follow is a
       branch of the call graph nobody looked down, so a caller reading a short
       missing list needs to know one was there.

       Scoped to the bodies the walk read, for the same reason. An indirect
       call in a function no contract reaches hid nothing from the frontier,
       and reporting it would answer "call_graph_complete: false" on a program
       whose frontier is complete, which is the field saying nothing at all on
       any codebase with a callback anywhere in it. *)
    ("unresolved_call_sites", `List unresolved);
    ("call_graph_complete", `Bool (unresolved = []));
  ]

let get_contract_context (kf : kernel_function) : Yojson.Basic.t =
  let callees, unresolved_callees = direct_call_info_of_kf kf in
  `Assoc [
    ("function", function_contract_to_json kf);
    ("callers", `List (List.map function_contract_to_json (direct_callers_of_kf kf)));
    ("callees", `List (List.map function_contract_to_json callees));
    ("unresolved_callees", `List unresolved_callees);
    ("callee_resolution_complete", `Bool (unresolved_callees = []));
  ]
