//! Callee-before-caller verification order for whole-program runs.
//!
//! Tarjan SCC, then petgraph condensation, then Kahn layering, so recursive
//! groups stay together and leaves come first.

use std::collections::{HashMap, HashSet};

use petgraph::algo::{condensation, tarjan_scc};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::state::{Level, SccGroup};

/// Build the caller → callee graph. Edges naming a vertex that was never
/// declared are dropped rather than treated as an error, because the callgraph
/// and the function list come from two separate Frama-C requests.
fn build_graph(
    vertices: &[String],
    edges: &[(String, String)],
) -> (DiGraph<String, ()>, HashMap<String, NodeIndex>) {
    let mut graph = DiGraph::<String, ()>::new();
    let mut name_to_node: HashMap<String, NodeIndex> = HashMap::new();
    for v in vertices {
        name_to_node
            .entry(v.clone())
            .or_insert_with(|| graph.add_node(v.clone()));
    }
    for (caller, callee) in edges {
        if let (Some(&c), Some(&d)) = (name_to_node.get(caller), name_to_node.get(callee)) {
            graph.add_edge(c, d, ());
        }
    }
    (graph, name_to_node)
}

/// Callgraph (vertices, edges) → levels of SCC groups, level 0 being the
/// leaves. Members and groups are sorted so the output is deterministic;
/// vertices with no edges appear as single-member, non-cycle groups.
pub fn compute_topological_order(vertices: &[String], edges: &[(String, String)]) -> Vec<Level> {
    let (graph, _) = build_graph(vertices, edges);
    if graph.node_count() == 0 {
        return vec![];
    }

    // Snapshot self-loops before condensation, which drops them along with
    // intra-SCC edges. Without this a self-recursive function looks like a
    // plain single-member group.
    let self_loop_names: HashSet<String> = graph
        .node_indices()
        .filter(|&n| graph.contains_edge(n, n))
        .map(|n| graph[n].clone())
        .collect();

    // Each condensed node weight is the member-name list of one SCC.
    let condensed = condensation(graph, true);

    // Kahn layering upward from the leaves: level 0 has no outgoing edges.
    let n_groups = condensed.node_count();
    let mut out_degree: Vec<usize> = (0..n_groups)
        .map(|i| {
            condensed
                .neighbors_directed(NodeIndex::new(i), Direction::Outgoing)
                .count()
        })
        .collect();
    let mut levels_map: Vec<usize> = vec![0; n_groups];
    let mut current_level = 0usize;
    let mut ready: Vec<NodeIndex> = (0..n_groups)
        .filter(|&i| out_degree[i] == 0)
        .map(NodeIndex::new)
        .collect();

    while !ready.is_empty() {
        for &g in &ready {
            levels_map[g.index()] = current_level;
        }
        let mut next_ready: Vec<NodeIndex> = vec![];
        for &g in &ready {
            let callers = condensed.neighbors_directed(g, Direction::Incoming);
            next_ready.extend(callers.filter(|caller| {
                // Decrementing is the point, not the filter: every caller loses
                // one outstanding callee here, and the ones that reach zero are
                // exactly the next level.
                out_degree[caller.index()] -= 1;
                out_degree[caller.index()] == 0
            }));
        }
        ready = next_ready;
        current_level += 1;
    }

    let mut groups: Vec<SccGroup> = (0..n_groups)
        .map(|i| {
            let mut members: Vec<String> = condensed[NodeIndex::new(i)].clone();
            members.sort();

            // Multi-member means a strongly connected ring; a single member is
            // recursive only if it had a self-loop.
            let is_cycle = members.len() >= 2
                || (members.len() == 1 && self_loop_names.contains(&members[0]));
            SccGroup {
                id: i as u32,
                members,
                level: levels_map[i],
                is_cycle,
            }
        })
        .collect();

    // Renumber ids so they ascend with (level, id) instead of following
    // petgraph's internal condensation order.
    groups.sort_by_key(|g| (g.level, g.id));
    for (new_id, g) in groups.iter_mut().enumerate() {
        g.id = new_id as u32;
    }

    let max_level = levels_map.iter().max().copied().unwrap_or(0);
    let mut levels: Vec<Level> = (0..=max_level)
        .map(|l| Level {
            level: l,
            groups: vec![],
        })
        .collect();
    for g in groups {
        let lvl = g.level;
        levels[lvl].groups.push(g);
    }

    levels
}

/// Flatten `compute_topological_order` levels into a bottom-up verification
/// order plus its SCC groups.
///
/// Only functions in `defined` survive: the callgraph also names library
/// functions that are declared but have no body, and an order containing those
/// could never be completed, so the done gate would never fire.
pub fn flatten_levels_to_vo_scc(
    levels: &[Level],
    defined: &HashSet<String>,
) -> (Vec<String>, Vec<SccGroup>) {
    let mut vo: Vec<String> = Vec::new();
    let mut scc_groups: Vec<SccGroup> = Vec::new();
    for level in levels {
        for group in &level.groups {
            let members: Vec<String> = group
                .members
                .iter()
                .filter(|m| defined.contains(*m))
                .cloned()
                .collect();
            if members.is_empty() {
                continue;
            }
            vo.extend(members.iter().cloned());
            scc_groups.push(SccGroup {
                id: group.id,
                members,
                level: level.level,
                is_cycle: group.is_cycle,
            });
        }
    }
    (vo, scc_groups)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReadyFunc {
    pub function: String,
    /// Index of the enclosing SCC, or null when the function is not recursive.
    pub scc_id: Option<u32>,
    pub is_cycle: bool,
    /// Sorted SCC members when `is_cycle`, otherwise just this function.
    pub scc_members: Vec<String>,
}

/// Functions whose callees are all verified, so they can be verified next.
///
/// `ready(f) ⇔ f ∉ done ∧ f ∉ in_progress ∧ ∀ direct callee c: c ∈ done ∨
/// same_scc(f, c)`.
///
/// Same-SCC callees are exempt because a recursive group can only converge
/// through placeholder contracts; its members become ready independently rather
/// than as one batch. Pure by design: `done` and `in_progress` are arguments,
/// never read back from persisted state, so a caller cannot desync the two.
pub fn compute_ready_functions(
    vertices: &[String],
    edges: &[(String, String)],
    done: &[String],
    in_progress: &[String],
) -> Vec<ReadyFunc> {
    let (graph, name_to_node) = build_graph(vertices, edges);
    let sccs = tarjan_scc(&graph);
    let mut scc_of: HashMap<String, usize> = HashMap::new();
    let mut scc_members: Vec<Vec<String>> = Vec::with_capacity(sccs.len());
    let mut is_cycle_of: Vec<bool> = Vec::with_capacity(sccs.len());
    for (i, scc) in sccs.iter().enumerate() {
        let is_cycle =
            scc.len() >= 2 || (scc.len() == 1 && graph.contains_edge(scc[0], scc[0]));
        let mut names: Vec<String> = scc.iter().map(|&n| graph[n].clone()).collect();
        for nm in &names {
            scc_of.insert(nm.clone(), i);
        }
        names.sort();
        scc_members.push(names);
        is_cycle_of.push(is_cycle);
    }

    let done_set: HashSet<&str> = done.iter().map(String::as_str).collect();
    let inprog_set: HashSet<&str> = in_progress.iter().map(String::as_str).collect();
    let mut out: Vec<ReadyFunc> = Vec::new();
    for v in vertices {
        if done_set.contains(v.as_str()) || inprog_set.contains(v.as_str()) {
            continue;
        }
        let f_node = name_to_node[v];
        let f_scc = scc_of[v];

        // Read callees off the graph, not `edges`, so the dropped-edge rule in
        // build_graph applies here too.
        let ext_ok = graph
            .neighbors_directed(f_node, Direction::Outgoing)
            .all(|cn| {
                let c = &graph[cn];
                let same_scc = scc_of.get(c) == Some(&f_scc) && is_cycle_of[f_scc];
                same_scc || done_set.contains(c.as_str())
            });
        if ext_ok {
            let is_cycle = is_cycle_of[f_scc];
            out.push(ReadyFunc {
                function: v.clone(),
                scc_id: if is_cycle { Some(f_scc as u32) } else { None },
                is_cycle,
                scc_members: if is_cycle {
                    scc_members[f_scc].clone()
                } else {
                    vec![v.clone()]
                },
            });
        }
    }
    out.sort_by(|a, b| a.function.cmp(&b.function));
    out
}
