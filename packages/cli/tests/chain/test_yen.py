import rustworkx as rx

from opentools.chain.query.yen import RawPath, yens_k_shortest


def _cost(edge_data):
    # For tests, edge_data is a float cost directly
    return float(edge_data)


def _make_graph(edges: list[tuple[int, int, float]]) -> tuple[rx.PyDiGraph, dict[int, int]]:
    """Build a rustworkx graph where int nodes map to int indices.

    edges is a list of (src_label, tgt_label, cost). Returns the graph
    and a label->index map.
    """
    g = rx.PyDiGraph()
    label_to_idx: dict[int, int] = {}

    def _get(label: int) -> int:
        if label not in label_to_idx:
            label_to_idx[label] = g.add_node(label)
        return label_to_idx[label]

    for src, tgt, cost in edges:
        g.add_edge(_get(src), _get(tgt), cost)

    return g, label_to_idx


def test_single_shortest_path():
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 3, 1.0),
        (1, 3, 5.0),
    ])
    paths = yens_k_shortest(g, idx[1], idx[3], k=1, max_hops=10, cost_key=_cost)
    assert len(paths) == 1
    assert paths[0].total_cost == 2.0
    assert [g.get_node_data(i) for i in paths[0].node_indices] == [1, 2, 3]


def test_multiple_paths_ordered_by_cost():
    # Three paths from 1 to 5: 1->2->5 (2.0), 1->3->5 (3.0), 1->4->5 (5.0)
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 5, 1.0),
        (1, 3, 1.5),
        (3, 5, 1.5),
        (1, 4, 2.0),
        (4, 5, 3.0),
    ])
    paths = yens_k_shortest(g, idx[1], idx[5], k=5, max_hops=10, cost_key=_cost)
    assert len(paths) == 3  # only 3 distinct paths exist
    assert paths[0].total_cost == 2.0
    assert paths[1].total_cost == 3.0
    assert paths[2].total_cost == 5.0


def test_k_caps_results():
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 5, 1.0),
        (1, 3, 1.5),
        (3, 5, 1.5),
        (1, 4, 2.0),
        (4, 5, 3.0),
    ])
    paths = yens_k_shortest(g, idx[1], idx[5], k=2, max_hops=10, cost_key=_cost)
    assert len(paths) == 2
    assert paths[0].total_cost == 2.0
    assert paths[1].total_cost == 3.0


def test_max_hops_excludes_long_paths():
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 3, 1.0),
        (3, 4, 1.0),
        (4, 5, 1.0),  # 4 hops total (1->2->3->4->5)
    ])
    # max_hops=3 should exclude this 4-edge path
    paths = yens_k_shortest(g, idx[1], idx[5], k=5, max_hops=3, cost_key=_cost)
    assert paths == []


def test_unreachable_target():
    g = rx.PyDiGraph()
    a = g.add_node(1)
    b = g.add_node(2)
    # No edges
    paths = yens_k_shortest(g, a, b, k=5, max_hops=10, cost_key=_cost)
    assert paths == []


def test_source_equals_target():
    g = rx.PyDiGraph()
    a = g.add_node(1)
    paths = yens_k_shortest(g, a, a, k=5, max_hops=10, cost_key=_cost)
    assert paths == []


def test_graph_not_mutated():
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 3, 1.0),
        (1, 3, 5.0),
    ])
    nodes_before = g.num_nodes()
    edges_before = g.num_edges()
    yens_k_shortest(g, idx[1], idx[3], k=5, max_hops=10, cost_key=_cost)
    assert g.num_nodes() == nodes_before
    assert g.num_edges() == edges_before


def test_all_paths_are_simple_no_cycles():
    # Graph with a cycle: 1->2->3->1 and 1->3
    g, idx = _make_graph([
        (1, 2, 1.0),
        (2, 3, 1.0),
        (3, 1, 1.0),
        (1, 3, 10.0),
    ])
    paths = yens_k_shortest(g, idx[1], idx[3], k=5, max_hops=10, cost_key=_cost)
    for p in paths:
        # No node repeats in a simple path
        assert len(p.node_indices) == len(set(p.node_indices))


def test_raw_path_construction():
    p = RawPath(node_indices=[0, 1, 2], total_cost=3.5, hops=2)
    assert p.hops == 2
    assert p.total_cost == 3.5
