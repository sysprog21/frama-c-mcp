(** ast_utils_register.ml — Frama-C plugin registration + server request handlers.

    Registers the ast-utils plugin and exposes:
    - getFunctionAst: function name → JSON AST
    - getAcslValidation: parse + type-check ACSL without inserting
    - execAddAnnotation: parse + type-check + insert ACSL
    - execRemoveAnnotations: remove all ast-utils emitter annotations
    - execInsertGhostFormal: insert a ghost function formal
    - execInsertGhostLoop: insert a tutorial-shaped ghost for loop
    - execInsertGhostLemmaFunction: insert a tutorial-shaped ghost lemma function
    - execInsertGhostStmt: insert ghost declaration or assignment
    - getVcDetails: get WP verification condition details (sequent)
    - execCreateSandbox: deep copy function for CEGIS experimentation
    - execDeleteSandbox: remove sandbox function from AST
    - execExtractAnnotations: extract our emitter's annotations from sandbox
    - getMarkerFunction: marker → enclosing function name, if any
    - getCilContext: flat Frama-C/CIL context for placement and lookup
    - getContractContext: function contract plus direct caller/callee contracts
    - getLoopEffects: direct writes grouped by loop
    - getLogicDeps: ACSL logic dependencies by function contract and annotation
    - getRteObligations: generated RTE assertions with alarm metadata
    - getWriteEffects: direct writes and direct callee assigns *)

open Frama_c_kernel
open Cil_types

(* ====== Plugin registration ====== *)

module Self = Plugin.Register (struct
  let name = "AST Utils"
  let shortname = "ast-utils"
  let help = "CIL AST JSON serialization and ACSL annotation manipulation"
end)

(* ====== Helpers ====== *)

let find_kf name =
  try Ok (Globals.Functions.find_by_name name)
  with Not_found ->
    Error (Printf.sprintf "function '%s' not found" name)

let find_stmt kf sid =
  try
    let fundec = Kernel_function.get_definition kf in
    Ok (List.find (fun s -> s.sid = sid) fundec.sallstmts)
  with
  | Kernel_function.No_Definition ->
    Error (Printf.sprintf "function '%s' has no definition"
             (Kernel_function.get_name kf))
  | Not_found ->
    Error (Printf.sprintf "statement %d not found" sid)

let error_json msg : Json.t =
  `Assoc [("error", `String msg)]

let ok_json (payload : (string * Json.t) list) : Json.t =
  `Assoc payload

let sid_map_to_json sid_map : Json.t =
  `List (List.map (fun (orig, sandbox) ->
    `List [`Int orig; `Int sandbox]
  ) sid_map)

(* ====== Server package ====== *)

let package =
  Server.Package.package
    ~plugin:"ast-utils"
    ~title:"AST Utils"
    ~descr:(Markdown.plain
              "CIL AST JSON serialization and ACSL annotation manipulation")
    ()

(* ====== getFunctionAst ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getFunctionAst"
    ~descr:(Markdown.plain "Get JSON representation of a function's CIL AST")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           let ast = Ast_utils_ast.get_function_ast kf in
           (ast :> Json.t)
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getMarkerFunction *)

(* The kernel has no request mapping a marker back to its function:
   getMarkerAt returns a marker alone despite its description, and
   getInformation on that marker answers only its source location. Taking
   Kernel_ast.Marker as the input type makes the server decode the marker
   string, so no marker parsing happens here.

   The function is an option because it has to be: a global, a type, and a
   file-scope declaration are all valid markers with no enclosing function, and
   answering with a name there would be an invention. *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getMarkerFunction"
    ~descr:(Markdown.plain
              "Return the function enclosing a marker, if any")
    ~input:(module Server.Kernel_ast.Marker)
    ~output:(module Server.Data.Jany)
    (fun localizable ->
       ok_json
         [("function",
           match Printer_tag.kf_of_localizable localizable with
           | None -> `Null
           | Some kf -> `String (Kernel_function.get_name kf))])

(* getCilContext *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getCilContext"
    ~descr:(Markdown.plain
              "Return flat Frama-C/CIL context for one function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           Ast_utils_ast.get_cil_context kf
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getContractFrontier *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getContractFrontier"
    ~descr:(Markdown.plain
              "Defined functions reachable from a contracted one that carry no contract")
    ~input:(module Server.Data.Junit)
    ~output:(module Server.Data.Jany)
    (fun () -> Ast_utils_ast.get_contract_frontier ())

(* getContractContext *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getContractContext"
    ~descr:(Markdown.plain
              "Return contract context for one function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           Ast_utils_ast.get_contract_context kf
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getClauseOrigin *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getClauseOrigin"
    ~descr:(Markdown.plain
              "ACSL names of the clauses this plug-in's emitter wrote on one function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         ok_json [
           ("function", `String (Kernel_function.get_name kf));
           ("names",
            `List (List.map (fun n -> `String n)
                     (Ast_utils_sandbox.our_clause_names kf)));
         ])

(* getWriteEffects *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getWriteEffects"
    ~descr:(Markdown.plain
              "Return direct written lvalues and direct callee assigns clauses")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           Ast_utils_ast.get_write_effects kf
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getLoopEffects *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getLoopEffects"
    ~descr:(Markdown.plain
              "Return direct writes grouped by loop statement")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           Ast_utils_ast.get_loop_effects kf
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getLogicDeps *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getLogicDeps"
    ~descr:(Markdown.plain
              "Return ACSL logic dependencies used by a function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         try
           Ast_utils_ast.get_logic_deps kf
         with Kernel_function.No_Definition ->
           error_json (Printf.sprintf "function '%s' has no definition" name))

(* getRteObligations *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"getRteObligations"
    ~descr:(Markdown.plain
              "Return generated RTE assertions for one function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         (try RteGen.Visit.annotate kf
          with Kernel_function.No_Definition -> ());
         let obligations =
           Alarms.to_seq ()
           |> Seq.filter_map
             (fun (emitter, alarm_kf, stmt, rank, alarm, ca) ->
                if Emitter.equal emitter RteGen.Generator.emitter
                   && Kernel_function.equal alarm_kf kf
                then
                  Some (Ast_utils_ast.rte_obligation_to_json
                          kf stmt ~rank alarm ca)
                else None)
           |> List.of_seq
         in
         Ast_utils_ast.get_rte_obligations kf obligations)

(* ====== getAcslValidation ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_kind = Server.Request.param s
    ~name:"kind" ~descr:(Markdown.plain "\"spec\", \"annot\", or \"global\"")
    (module Server.Data.Jstring) in
  let get_acsl = Server.Request.param s
    ~name:"acsl" ~descr:(Markdown.plain "ACSL string to validate")
    (module Server.Data.Jstring) in
  let get_stmt = Server.Request.param_opt s
    ~name:"stmt" ~descr:(Markdown.plain "Statement ID (required for kind=annot)")
    (module Server.Data.Jint) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Validation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`GET
    ~name:"getAcslValidation"
    ~descr:(Markdown.plain
              "Parse and type-check ACSL string without inserting into AST")
    (fun rq () ->
       let fname = get_function rq in
       let kind = get_kind rq in
       let acsl = get_acsl rq in
       let stmt_opt = get_stmt rq in
       let result =
         match kind with
         | "global" ->
           (match Ast_utils_core.type_global acsl with
            | Ok _ ->
              ok_json [("valid", `Bool true); ("error", `Null)]
            | Error msg ->
              ok_json [("valid", `Bool false); ("error", `String msg)])
         | _ ->
           match find_kf fname with
           | Error msg -> error_json msg
           | Ok kf ->
             match kind with
           | "spec" ->
             (match Ast_utils_core.type_spec kf acsl with
              | Ok _ ->
                ok_json [("valid", `Bool true); ("error", `Null)]
              | Error msg ->
                ok_json [("valid", `Bool false); ("error", `String msg)])
           | "annot" ->
             (match stmt_opt with
              | None ->
                error_json "stmt parameter required for kind=annot"
              | Some sid ->
                match find_stmt kf sid with
                | Error msg -> error_json msg
                | Ok stmt ->
                  match Ast_utils_core.type_annot kf stmt acsl with
                  | Ok _ ->
                    ok_json [("valid", `Bool true); ("error", `Null)]
                  | Error msg ->
                    ok_json [("valid", `Bool false); ("error", `String msg)])
           | _ ->
             error_json (Printf.sprintf "unknown kind '%s', expected 'spec', 'annot', or 'global'" kind)
       in
       set_result rq result)

(* ====== execAddGlobalAcsl ====== *)

let () =
  let s = Server.Request.signature () in
  let get_acsl = Server.Request.param s
    ~name:"acsl" ~descr:(Markdown.plain "Global ACSL declaration to add")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execAddGlobalAcsl"
    ~descr:(Markdown.plain
              "Parse, type-check and insert a global ACSL declaration into CIL AST")
    (fun rq () ->
       let acsl = get_acsl rq in
       let result =
         match Ast_utils_core.type_global acsl with
         | Ok globals ->
           Ast_utils_core.insert_globals globals;
           ok_json [("success", `Bool true); ("error", `Null);
                    ("count", `Int (List.length globals))]
         | Error msg ->
           ok_json [("success", `Bool false); ("error", `String msg)]
       in
       set_result rq result)

(* ====== execRemoveGlobalAcsl ====== *)

let () =
  let s = Server.Request.signature () in
  let get_acsl = Server.Request.param s
    ~name:"acsl" ~descr:(Markdown.plain "Global ACSL declaration to remove")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execRemoveGlobalAcsl"
    ~descr:(Markdown.plain
              "Remove a global ACSL declaration added by ast-utils emitter")
    (fun rq () ->
       let acsl = get_acsl rq in
       let result =
         match Ast_utils_core.type_global acsl with
         | Ok globals ->
           let n = Ast_utils_core.remove_globals_matching globals in
           ok_json [("success", `Bool true); ("removed_count", `Int n)]
         | Error msg ->
           ok_json [("success", `Bool false); ("error", `String msg)]
       in
       set_result rq result)

(* ====== execInsertGhostGlobal ====== *)

let () =
  let s = Server.Request.signature () in
  let get_name = Server.Request.param s
    ~name:"name" ~descr:(Markdown.plain "Ghost global variable name")
    (module Server.Data.Jstring) in
  let get_type = Server.Request.param_opt s
    ~name:"type" ~descr:(Markdown.plain "Type name (default: \"int\")")
    (module Server.Data.Jstring) in
  let get_expr = Server.Request.param_opt s
    ~name:"expr" ~descr:(Markdown.plain "Integer initializer")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execInsertGhostGlobal"
    ~descr:(Markdown.plain "Insert a C ghost global variable into the AST")
    (fun rq () ->
       let name = get_name rq in
       let type_name = match get_type rq with Some t -> t | None -> "int" in
       let expr = match get_expr rq with Some e -> e | None -> "" in
       let result =
         match Ast_utils_ghost.resolve_ghost_type type_name with
         | Error msg -> ok_json [("success", `Bool false); ("error", `String msg)]
         | Ok typ ->
           let loc = Ast_utils_compat.loc_unknown in
           match Ast_utils_ghost.parse_global_init loc typ expr with
           | Error msg ->
             ok_json [("success", `Bool false); ("error", `String msg)]
           | Ok init ->
             match Ast_utils_ghost.insert_ghost_global name typ init with
             | Error msg ->
               ok_json [("success", `Bool false); ("name", `String name);
                        ("vid", `Null); ("error", `String msg)]
             | Ok vi ->
               ok_json [("success", `Bool true); ("name", `String name);
                        ("vid", `Int vi.vid); ("error", `Null)]
       in
       set_result rq result)

(* ====== execInsertGhostFormal ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_name = Server.Request.param s
    ~name:"name" ~descr:(Markdown.plain "Ghost formal parameter name")
    (module Server.Data.Jstring) in
  let get_type = Server.Request.param_opt s
    ~name:"type" ~descr:(Markdown.plain "Type name (default: \"int\")")
    (module Server.Data.Jstring) in
  let get_where = Server.Request.param_opt s
    ~name:"where" ~descr:(Markdown.plain "Insertion point: \"^\", \"$\", or existing ghost formal name")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execInsertGhostFormal"
    ~descr:(Markdown.plain "Insert a C ghost formal parameter into a function")
    (fun rq () ->
       let fname = get_function rq in
       let name = get_name rq in
       let type_name = match get_type rq with Some t -> t | None -> "int" in
       let where = match get_where rq with Some w -> w | None -> "$" in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           match Ast_utils_ghost.resolve_ghost_type type_name with
           | Error msg -> ok_json [("success", `Bool false); ("name", `String name);
                                   ("vid", `Null); ("error", `String msg)]
           | Ok typ ->
             match Ast_utils_ghost.insert_ghost_formal kf name typ where with
             | Error msg ->
               ok_json [("success", `Bool false); ("name", `String name);
                        ("vid", `Null); ("error", `String msg)]
             | Ok vi ->
               ok_json [("success", `Bool true); ("name", `String name);
                        ("vid", `Int vi.vid); ("error", `Null)]
       in
       set_result rq result)

(* ====== execInsertGhostLemmaFunction ====== *)

let () =
  let s = Server.Request.signature () in
  let get_name = Server.Request.param s
    ~name:"name" ~descr:(Markdown.plain "Ghost lemma function name")
    (module Server.Data.Jstring) in
  let get_param = Server.Request.param s
    ~name:"param" ~descr:(Markdown.plain "Single parameter name")
    (module Server.Data.Jstring) in
  let get_param_type = Server.Request.param_opt s
    ~name:"param_type" ~descr:(Markdown.plain "Parameter type (default: \"int\")")
    (module Server.Data.Jstring) in
  let get_requires = Server.Request.param s
    ~name:"requires" ~descr:(Markdown.plain "Requires predicate")
    (module Server.Data.Jstring) in
  let get_decreases = Server.Request.param s
    ~name:"decreases" ~descr:(Markdown.plain "Decreases term")
    (module Server.Data.Jstring) in
  let get_assigns = Server.Request.param s
    ~name:"assigns" ~descr:(Markdown.plain "Assigns clause target")
    (module Server.Data.Jstring) in
  let get_ensures = Server.Request.param s
    ~name:"ensures" ~descr:(Markdown.plain "Ensures predicate")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execInsertGhostLemmaFunction"
    ~descr:(Markdown.plain "Insert a ghost lemma function with one recursive call")
    (fun rq () ->
       let name = get_name rq in
       let param = get_param rq in
       let param_type =
         match get_param_type rq with Some t -> t | None -> "int" in
       let requires = get_requires rq in
       let decreases = get_decreases rq in
       let assigns = get_assigns rq in
       let ensures = get_ensures rq in
       let result =
         match Ast_utils_ghost.resolve_ghost_type param_type with
         | Error msg ->
           ok_json [("success", `Bool false);
                    ("name", `String name);
                    ("vid", `Null);
                    ("sids", `List []);
                    ("error", `String msg)]
         | Ok typ ->
           match Ast_utils_ghost.insert_ghost_lemma_function
                   name param typ requires decreases assigns ensures with
           | Error msg ->
             ok_json [("success", `Bool false);
                      ("name", `String name);
                      ("vid", `Null);
                      ("sids", `List []);
                      ("error", `String msg)]
           | Ok vi ->
             let sids =
               try
                 let kf = Globals.Functions.get vi in
                 let fundec = Kernel_function.get_definition kf in
                 List.map (fun stmt -> `Int stmt.sid) fundec.sallstmts
               with _ -> []
             in
             ok_json [("success", `Bool true);
                      ("name", `String name);
                      ("vid", `Int vi.vid);
                      ("sids", `List sids);
                      ("error", `Null)]
       in
       set_result rq result)

(* ====== execAddAnnotation ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_kind = Server.Request.param s
    ~name:"kind" ~descr:(Markdown.plain "\"spec\" or \"annot\"")
    (module Server.Data.Jstring) in
  let get_acsl = Server.Request.param s
    ~name:"acsl" ~descr:(Markdown.plain "ACSL string to add")
    (module Server.Data.Jstring) in
  let get_stmt = Server.Request.param_opt s
    ~name:"stmt" ~descr:(Markdown.plain "Statement ID (required for kind=annot)")
    (module Server.Data.Jint) in
  let get_label = Server.Request.param_opt s
    ~name:"label" ~descr:(Markdown.plain "Label to inject into pred_name (optional)")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execAddAnnotation"
    ~descr:(Markdown.plain
              "Parse, type-check and insert ACSL annotation into CIL AST")
    (fun rq () ->
       let fname = get_function rq in
       let kind = get_kind rq in
       let acsl = get_acsl rq in
       let stmt_opt = get_stmt rq in
       let label = get_label rq in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           match kind with
           | "spec" ->
             let inserted =
               Result.bind (Ast_utils_core.type_spec ?label kf acsl)
                 (Ast_utils_core.insert_spec kf)
             in
             (match inserted with
              | Ok () ->
                ok_json [("success", `Bool true); ("error", `Null)]
              | Error msg ->
                ok_json [("success", `Bool false); ("error", `String msg)])
           | "annot" ->
             (match stmt_opt with
              | None ->
                error_json "stmt parameter required for kind=annot"
              | Some sid ->
                match find_stmt kf sid with
                | Error msg -> error_json msg
                | Ok stmt ->
                  match Ast_utils_core.type_annot ?label kf stmt acsl with
                  | Ok annots ->
                    (try
                       Ast_utils_core.insert_annots kf stmt annots;
                       ok_json [("success", `Bool true); ("error", `Null);
                                ("count", `Int (List.length annots))]
                     with Invalid_argument msg ->
                       ok_json [("success", `Bool false); ("error", `String msg)])
                  | Error msg ->
                    ok_json [("success", `Bool false); ("error", `String msg)])
           | _ ->
             error_json (Printf.sprintf "unknown kind '%s', expected 'spec' or 'annot'" kind)
       in
       set_result rq result)

(* ====== execRemoveAnnotations ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`EXEC
    ~name:"execRemoveAnnotations"
    ~descr:(Markdown.plain
              "Remove all annotations added by ast-utils emitter from a function")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         let n = Ast_utils_core.remove kf in
         ok_json [("success", `Bool true); ("removed_count", `Int n)])

(* ====== execRemoveAnnotationByLabel ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_label = Server.Request.param s
    ~name:"label" ~descr:(Markdown.plain "Hash label of annotation to remove")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execRemoveAnnotationByLabel"
    ~descr:(Markdown.plain
              "Remove a single annotation identified by its hash_label")
    (fun rq () ->
       let fname = get_function rq in
       let label = get_label rq in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           match Ast_utils_core.remove_annotation_by_label kf label with
           | true ->
             ok_json [("success", `Bool true); ("error", `Null)]
           | false ->
             ok_json [("success", `Bool false);
                      ("error", `String "annotation not found")]
       in
       set_result rq result)

(* ====== execInsertGhostLoop ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_stmt = Server.Request.param s
    ~name:"stmt" ~descr:(Markdown.plain "Statement ID to insert before")
    (module Server.Data.Jint) in
  let get_name = Server.Request.param s
    ~name:"name" ~descr:(Markdown.plain "Ghost loop counter name")
    (module Server.Data.Jstring) in
  let get_type = Server.Request.param_opt s
    ~name:"type" ~descr:(Markdown.plain "Counter type (default: \"unsigned\")")
    (module Server.Data.Jstring) in
  let get_stop = Server.Request.param s
    ~name:"stop" ~descr:(Markdown.plain "Loop upper-bound expression")
    (module Server.Data.Jstring) in
  let get_init = Server.Request.param_opt s
    ~name:"init" ~descr:(Markdown.plain "Initial counter expression (default: 0)")
    (module Server.Data.Jstring) in
  let get_step = Server.Request.param_opt s
    ~name:"step" ~descr:(Markdown.plain "Counter increment expression (default: 1)")
    (module Server.Data.Jstring) in
  let get_invariant = Server.Request.param s
    ~name:"invariant" ~descr:(Markdown.plain "Loop invariant predicate")
    (module Server.Data.Jstring) in
  let get_assigns = Server.Request.param s
    ~name:"assigns" ~descr:(Markdown.plain "Loop assigns target")
    (module Server.Data.Jstring) in
  let get_variant = Server.Request.param s
    ~name:"variant" ~descr:(Markdown.plain "Loop variant term")
    (module Server.Data.Jstring) in
  let get_assert = Server.Request.param_opt s
    ~name:"assert" ~descr:(Markdown.plain "Optional assertion predicate after the loop")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execInsertGhostLoop"
    ~descr:(Markdown.plain "Insert an empty ghost counting for loop with loop ACSL")
    (fun rq () ->
       let fname = get_function rq in
       let sid = get_stmt rq in
       let name = get_name rq in
       let type_name = match get_type rq with Some t -> t | None -> "unsigned" in
       let stop = get_stop rq in
       let init = match get_init rq with Some e -> e | None -> "0" in
       let step = match get_step rq with Some e -> e | None -> "1" in
       let invariant = get_invariant rq in
       let assigns = get_assigns rq in
       let variant = get_variant rq in
       let assert_pred = match get_assert rq with Some p -> p | None -> "" in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           match find_stmt kf sid with
           | Error msg -> error_json msg
           | Ok stmt ->
             let fundec =
               try Kernel_function.get_definition kf
               with Kernel_function.No_Definition ->
                 failwith "function has no definition"
             in
             let loc = Cil_datatype.Stmt.loc stmt in
             let parse_expr field text =
               match Ast_utils_ghost.parse_c_expr fundec loc text with
               | Ok exp -> Ok exp
               | Error msg -> Error (Printf.sprintf "%s: %s" field msg)
             in
             match Ast_utils_ghost.resolve_ghost_type type_name with
             | Error msg -> ok_json [("success", `Bool false);
                                     ("sid", `Null);
                                     ("loop_sid", `Null);
                                     ("counter_vid", `Null);
                                     ("sids", `List []);
                                     ("error", `String msg)]
             | Ok typ ->
               match parse_expr "init" init, parse_expr "stop" stop, parse_expr "step" step with
               | Error msg, _, _ | _, Error msg, _ | _, _, Error msg ->
                 ok_json [("success", `Bool false);
                          ("sid", `Null);
                          ("loop_sid", `Null);
                          ("counter_vid", `Null);
                          ("sids", `List []);
                          ("error", `String msg)]
               | Ok init_exp, Ok stop_exp, Ok step_exp ->
                 match Ast_utils_ghost.insert_ghost_loop
                         kf stmt name typ init_exp stop_exp step_exp invariant assigns variant assert_pred with
                 | Error msg ->
                   ok_json [("success", `Bool false);
                            ("sid", `Null);
                            ("loop_sid", `Null);
                            ("counter_vid", `Null);
                            ("sids", `List []);
                            ("error", `String msg)]
                 | Ok (block_stmt, loop_stmt, counter, sids) ->
                   ok_json [("success", `Bool true);
                            ("sid", `Int block_stmt.sid);
                            ("loop_sid", `Int loop_stmt.sid);
                            ("counter_vid", `Int counter.vid);
                            ("sids", `List (List.map (fun sid -> `Int sid) sids));
                            ("error", `Null)]
       in
       set_result rq result)

(* ====== execInsertGhostStmt ====== *)

let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let get_stmt = Server.Request.param s
    ~name:"stmt" ~descr:(Markdown.plain "Statement ID to insert before")
    (module Server.Data.Jint) in
  let get_op = Server.Request.param s
    ~name:"op" ~descr:(Markdown.plain "\"decl\", \"set\", \"label\", or \"else_set\"")
    (module Server.Data.Jstring) in
  let get_name = Server.Request.param s
    ~name:"name" ~descr:(Markdown.plain "Variable or label name")
    (module Server.Data.Jstring) in
  let get_type = Server.Request.param_opt s
    ~name:"type" ~descr:(Markdown.plain "Type name (default: \"int\", for op=decl)")
    (module Server.Data.Jstring) in
  let get_expr = Server.Request.param s
    ~name:"expr" ~descr:(Markdown.plain "Expression string")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Operation result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execInsertGhostStmt"
    ~descr:(Markdown.plain
              "Insert a ghost declaration, assignment, label, or empty-else assignment")
    (fun rq () ->
       let fname = get_function rq in
       let sid = get_stmt rq in
       let op = get_op rq in
       let var_name = get_name rq in
       let type_name = match get_type rq with Some t -> t | None -> "int" in
       let expr_str = get_expr rq in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           match find_stmt kf sid with
           | Error msg -> error_json msg
           | Ok stmt ->
             let fundec =
               try Kernel_function.get_definition kf
               with Kernel_function.No_Definition ->
                 failwith "function has no definition"
             in
             let loc = Cil_datatype.Stmt.loc stmt in
             match op with
             | "decl" ->
               (match Ast_utils_ghost.resolve_ghost_type type_name with
                | Error msg -> error_json msg
                | Ok typ ->
                  match Ast_utils_ghost.parse_c_expr fundec loc expr_str with
                  | Error msg -> error_json msg
                  | Ok init_exp ->
                    match Ast_utils_ghost.insert_ghost_decl
                            kf stmt var_name typ init_exp with
                    | Error msg ->
                      ok_json [("success", `Bool false);
                               ("sid", `Null);
                               ("error", `String msg)]
                    | Ok new_stmt ->
                      ok_json [("success", `Bool true);
                               ("sid", `Int new_stmt.sid);
                               ("error", `Null)])
             | "set" ->
               (match Ast_utils_ghost.parse_c_expr fundec loc expr_str with
                | Error msg -> error_json msg
                | Ok expr ->
                  match Ast_utils_ghost.insert_ghost_assign
                          kf stmt var_name expr with
                  | Error msg ->
                    ok_json [("success", `Bool false);
                             ("sid", `Null);
                             ("error", `String msg)]
                  | Ok new_stmt ->
                    ok_json [("success", `Bool true);
                             ("sid", `Int new_stmt.sid);
                             ("error", `Null)])
             | "else_set" ->
               (match Ast_utils_ghost.parse_c_expr fundec loc expr_str with
                | Error msg -> error_json msg
                | Ok expr ->
                  match Ast_utils_ghost.insert_ghost_else_assign
                          kf stmt var_name expr with
                  | Error msg ->
                    ok_json [("success", `Bool false);
                             ("sid", `Null);
                             ("error", `String msg)]
                  | Ok new_stmt ->
                    ok_json [("success", `Bool true);
                             ("sid", `Int new_stmt.sid);
                             ("error", `Null)])
             | "label" ->
               (match Ast_utils_ghost.insert_ghost_label
                        kf stmt var_name with
                | Error msg ->
                  ok_json [("success", `Bool false);
                           ("sid", `Null);
                           ("error", `String msg)]
                | Ok new_stmt ->
                  ok_json [("success", `Bool true);
                           ("sid", `Int new_stmt.sid);
                           ("error", `Null)])
             | _ ->
               error_json (Printf.sprintf
                 "unknown op '%s', expected 'decl', 'set', 'label', or 'else_set'" op)
       in
       set_result rq result)

(* ====== getVcDetails ====== *)

(** Pretty-print a WP predicate to string. *)
let () =
  let s = Server.Request.signature () in
  let get_function = Server.Request.param s
    ~name:"function" ~descr:(Markdown.plain "Function name")
    (module Server.Data.Jstring) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "VC details")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`GET
    ~name:"getVcDetails"
    ~descr:(Markdown.plain
              "Get WP verification condition details (sequent) for a function")
    (fun rq () ->
       let fname = get_function rq in
       let result =
         match find_kf fname with
         | Error msg -> error_json msg
         | Ok kf ->
           try
             let goals = Wp.VC.generate_kf kf in
             let vcs = ref [] in
             let idx = ref 0 in
             Bag.iter (fun vc ->
               let desc = Wp.VC.get_description vc in
               let prop = Wp.VC.get_property vc in
               let (hyps_raw, goal_raw) = Wp.VC.get_sequent vc in
               let steps = Wp.Conditions.list hyps_raw in
               let hyp_jsons = List.filter_map Ast_utils_property.step_to_json steps in
               let goal_str = Ast_utils_property.pp_pred_to_string goal_raw in
               let loc, loc_confidence, loc_source = Ast_utils_property.vc_loc_json prop steps in
               let vc_json = `Assoc [
                 ("index", `Int !idx);
                 ("wpo_id", `String (Wp.VC.get_id vc));
                 ("loc", loc);
                 ("loc_confidence", `String loc_confidence);
                 ("loc_source", `String loc_source);
                 ("description", `String desc);
                 ("clause", Ast_utils_property.clause_metadata_of_property prop);
                 ("involved_variables", Ast_utils_property.variables_of_property prop);
                 ("callee_contracts", Ast_utils_property.callee_context_of_property prop);
                 ("goal", `String goal_str);
                 ("hypotheses", `List hyp_jsons)
               ] in
               vcs := vc_json :: !vcs;
               incr idx
             ) goals;
             ok_json [
               ("function", `String fname);
               ("vc_count", `Int !idx);
               ("vcs", `List (List.rev !vcs))
             ]
           with exn ->
             error_json (Printf.sprintf "WP error: %s" (Printexc.to_string exn))
       in
       set_result rq result)

(* ====== execSetWpConfig ====== *)

let () =
  let s = Server.Request.signature () in
  let get_model = Server.Request.param_opt s
    ~name:"model" ~descr:(Markdown.plain
      "WP memory model selector list. Rust MCP defaults to \"Typed+nocast\" \
       and validates against selectors reported by frama-c -wp-h.")
    (module Server.Data.Jstring) in
  let get_prop = Server.Request.param_opt s
    ~name:"prop" ~descr:(Markdown.plain
      "Property filter (comma-separated). Use +name to include, \
       -name to exclude. Example: \"+my_inv,-assigns\"")
    (module Server.Data.Jstring) in
  let get_timeout = Server.Request.param_opt s
    ~name:"timeout" ~descr:(Markdown.plain
      "Per-goal prover timeout in seconds (default: 2)")
    (module Server.Data.Jint) in
  let get_par = Server.Request.param_opt s
    ~name:"par" ~descr:(Markdown.plain
      "Number of parallel WP prover processes")
    (module Server.Data.Jint) in
  let set_result = Server.Request.result s
    ~name:"result" ~descr:(Markdown.plain "Configuration result")
    (module Server.Data.Jany) in
  Server.Request.register_sig s
    ~package
    ~kind:`EXEC
    ~name:"execSetWpConfig"
    ~descr:(Markdown.plain
              "Configure WP parameters (model, property filter, timeout) \
               for subsequent WP runs")
    (fun rq () ->
       let changed = ref [] in
       (match get_model rq with
        | Some m ->
          let model_list = String.split_on_char ',' m in
          Wp.Wp_parameters.Model.set model_list;
          changed := ("model", `String m) :: !changed
        | None -> ());
       (match get_prop rq with
        | Some p ->
          let prop_list = String.split_on_char ',' p in
          Wp.Wp_parameters.Properties.set prop_list;
          changed := ("prop", `String p) :: !changed
        | None -> ());
       (match get_timeout rq with
        | Some t ->
          Wp.Wp_parameters.Timeout.set t;
          changed := ("timeout", `Int t) :: !changed
        | None -> ());
       (match get_par rq with
        | Some p ->
          if p < 1 then
            invalid_arg "par must be at least 1";
          Wp.Wp_parameters.Procs.set p;
          changed := ("par", `Int p) :: !changed
        | None -> ());
       set_result rq
         (ok_json [("success", `Bool true);
                    ("changed", `List (List.map (fun (k, v) ->
                       `Assoc [("param", `String k); ("value", v)]
                     ) !changed))]))

(* ====== execCreateSandbox ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`EXEC
    ~name:"execCreateSandbox"
    ~descr:(Markdown.plain
              "Deep copy a function for CEGIS experimentation. \
               Returns sandbox name, experiment ID, and sid mapping.")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         match Ast_utils_sandbox.create_sandbox kf with
         | Error msg -> error_json msg
         | Ok (sandbox_name, hash, sid_map) ->
           ok_json [
             ("sandbox_name", `String sandbox_name);
             ("experiment_id", `String hash);
             ("sid_map", sid_map_to_json sid_map)
           ])

(* ====== execDeleteSandbox ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`EXEC
    ~name:"execDeleteSandbox"
    ~descr:(Markdown.plain
              "Remove sandbox function from AST. Idempotent.")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun sandbox_name ->
       match Ast_utils_sandbox.delete_sandbox sandbox_name with
       | Error msg -> error_json msg
       | Ok () ->
         ok_json [("success", `Bool true)])

(* ====== execExtractAnnotations ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"execExtractAnnotations"
    ~descr:(Markdown.plain
              "Extract annotations added by ast-utils emitter from a sandbox function. \
               Returns list of (sid, annotation_text) pairs.")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun sandbox_name ->
       match find_kf sandbox_name with
       | Error msg -> error_json msg
       | Ok sandbox_kf ->
         match Ast_utils_sandbox.extract_our_annotations sandbox_kf with
         | Error msg -> error_json msg
         | Ok annots ->
           let globals = Ast_utils_core.our_globals () in
           ok_json [
             ("globals", `List (List.map (fun ga ->
               `Assoc [
                 ("name", (match Globals.get_annotation_name ga with
                           | Some name -> `String name
                           | None -> `Null));
                 ("acsl", `String (Format.asprintf "%a" Printer.pp_global_annotation ga))
               ]
             ) globals));
             ("annotations", `List (List.map (fun (sid, text) ->
               `Assoc [("sid", `Int sid); ("acsl", `String text)]
             ) annots))
           ])

(* ====== extractFunctionWithDeps ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"extractFunctionWithDeps"
    ~descr:(Markdown.plain
              "Extract a function with all type/callee/global dependencies as a self-contained C string")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun name ->
       match find_kf name with
       | Error msg -> error_json msg
       | Ok kf ->
         match Ast_utils_extract.extract kf with
         | Ok (c_source, sids, extraction_report) ->
           let logic_dependencies = Ast_utils_ast.get_logic_deps kf in
           ok_json [("success", `Bool true);
                    ("source", `String c_source);
                    ("sids", `List (List.map (fun s -> `Int s) sids));
                    ("extraction_report", extraction_report);
                    ("logic_dependencies", logic_dependencies)]
         | Error msg ->
           ok_json [("success", `Bool false);
                    ("error", `String msg)])

(* ====== printSource: output complete annotated C source ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"printSource"
    ~descr:(Markdown.plain
              "Print complete annotated C source (all globals with ACSL + RTE assertions)")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jstring)
    (fun _ignored ->
       (* pp_file emits the whole AST in declaration order, which is what a
          dispatch table needs: its initializer names functions that have to be
          declared above it. *)
       let buf = Buffer.create 65536 in
       let fmt = Format.formatter_of_buffer buf in
       Printer.pp_file fmt (Ast.get ());
       Format.pp_print_flush fmt ();
       Buffer.contents buf)

(* ====== dumpProject: export F-CIL JSON ====== *)

let () =
  Server.Request.register
    ~package
    ~kind:`GET
    ~name:"dumpProject"
    ~descr:(Markdown.plain
      "Dump complete project AST as F-CIL JSON format. \
       Output includes all type definitions, global variables, \
       functions (with ACSL contracts), and ident_names mapping.")
    ~input:(module Server.Data.Jstring)
    ~output:(module Server.Data.Jany)
    (fun _ignored -> Ast_utils_export.dump_project ())

(* ====== Command-line export mode ====== *)

module ExportFile = Self.String(struct
  let option_name = "-ast-utils-export"
  let default = ""
  let arg_name = "file"
  let help = "Export F-CIL JSON to file (- for stdout)"
end)

let () = Boot.Main.extend (fun () ->
  let path = ExportFile.get () in
  if path <> "" then begin
    let json = Ast_utils_export.dump_project () in
    let oc = if path = "-" then stdout else open_out path in
    Yojson.Basic.pretty_to_channel oc json;
    if path <> "-" then close_out oc
  end)
