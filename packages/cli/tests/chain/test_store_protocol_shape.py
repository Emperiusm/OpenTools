"""Shape tests for ChainStoreProtocol — verify every expected method
is defined as a Protocol member with correct signature.
"""
import inspect

from opentools.chain.store_protocol import ChainStoreProtocol


def _protocol_methods() -> set[str]:
    return {
        name
        for name in dir(ChainStoreProtocol)
        if not name.startswith("_") and callable(getattr(ChainStoreProtocol, name))
    }


EXPECTED_METHODS = {
    # Lifecycle (4)
    "initialize", "close", "transaction", "batch_transaction",
    # Entity CRUD (6)
    "upsert_entity", "upsert_entities_bulk", "get_entity",
    "get_entities_by_ids", "list_entities", "delete_entity",
    # Mention CRUD (9)
    "add_mentions_bulk", "mentions_for_finding",
    "delete_mentions_for_finding", "recompute_mention_counts",
    "rewrite_mentions_entity_id", "rewrite_mentions_by_ids",
    "fetch_mentions_with_engagement",
    "fetch_finding_ids_for_entity",
    "fetch_entity_mentions_for_engagement",
    # Relation CRUD (5)
    "upsert_relations_bulk", "relations_for_finding",
    "fetch_relations_in_scope", "stream_relations_in_scope",
    "apply_link_classification",
    # Linker-specific queries (5)
    "fetch_candidate_partners", "fetch_findings_by_ids",
    "count_findings_in_scope", "compute_avg_idf", "entities_for_finding",
    # LinkerRun lifecycle (5)
    "start_linker_run", "set_run_status", "finish_linker_run",
    "current_linker_generation", "fetch_linker_runs",
    # Extraction state + parser output (3)
    "get_extraction_hash", "upsert_extraction_state", "get_parser_output",
    # LLM caches (4)
    "get_extraction_cache", "put_extraction_cache",
    "get_llm_link_cache", "put_llm_link_cache",
    # Export (3)
    "fetch_findings_for_engagement", "fetch_all_finding_ids",
    "export_dump_stream",
}


def test_protocol_has_all_expected_methods():
    # Spec §4.3 originally listed 41 methods; Task 24 added
    # fetch_all_finding_ids for the exporter's "all engagements" path,
    # bringing the total to 42. Task 26 added fetch_finding_ids_for_entity
    # and fetch_entity_mentions_for_engagement for the async query stack,
    # bringing the total to 44.
    assert len(EXPECTED_METHODS) == 44
    methods = _protocol_methods()
    missing = EXPECTED_METHODS - methods
    extra = methods - EXPECTED_METHODS
    assert not missing, f"protocol missing methods: {missing}"
    assert not extra, f"protocol has unexpected methods: {extra}"


def test_every_method_is_async_or_returns_context_manager():
    for name in EXPECTED_METHODS:
        method = getattr(ChainStoreProtocol, name)
        assert inspect.iscoroutinefunction(method) or callable(method), (
            f"{name} is neither a coroutine nor a callable"
        )
