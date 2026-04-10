from opentools.chain.extractors.preprocess import TextRegion, split_code_blocks


def test_plain_text_single_prose_region():
    text = "This is plain text with no code blocks."
    regions = split_code_blocks(text)
    assert len(regions) == 1
    assert regions[0].kind == "prose"
    assert regions[0].start == 0
    assert regions[0].end == len(text)


def test_empty_text():
    regions = split_code_blocks("")
    assert regions == [] or (len(regions) == 1 and regions[0].kind == "prose" and regions[0].start == 0 and regions[0].end == 0)


def test_single_fenced_block():
    text = "before\n```\ncode here\n```\nafter"
    regions = split_code_blocks(text)
    kinds = [r.kind for r in regions]
    assert "code" in kinds
    assert "prose" in kinds
    # Reassembly roundtrip — offsets must be non-overlapping and cover the full input
    assert _covers(text, regions)


def test_multiple_fenced_blocks():
    text = "prose1\n```\ncode1\n```\nprose2\n```\ncode2\n```\nprose3"
    regions = split_code_blocks(text)
    kinds = [r.kind for r in regions]
    assert kinds.count("code") == 2
    assert kinds.count("prose") >= 2
    assert _covers(text, regions)


def test_pre_tag_block():
    text = "text <pre>raw\noutput</pre> more"
    regions = split_code_blocks(text)
    assert any(r.kind == "code" for r in regions)
    assert any(r.kind == "prose" for r in regions)
    assert _covers(text, regions)


def test_unclosed_fence_treats_rest_as_code():
    text = "prose\n```\nunclosed code block without closing"
    regions = split_code_blocks(text)
    # There should be a prose region and then a trailing code region
    assert any(r.kind == "prose" for r in regions)
    assert any(r.kind == "code" for r in regions)
    assert regions[-1].kind == "code"
    assert _covers(text, regions)


def test_regions_are_non_overlapping_and_ordered():
    text = "a ```b``` c ```d``` e"
    regions = split_code_blocks(text)
    for i in range(len(regions) - 1):
        assert regions[i].end == regions[i + 1].start
    assert regions[0].start == 0
    assert regions[-1].end == len(text)


def _covers(text: str, regions: list[TextRegion]) -> bool:
    """Assert regions exactly tile the input with no gaps or overlaps."""
    if not regions:
        return text == ""
    if regions[0].start != 0:
        return False
    for i in range(len(regions) - 1):
        if regions[i].end != regions[i + 1].start:
            return False
    return regions[-1].end == len(text)
