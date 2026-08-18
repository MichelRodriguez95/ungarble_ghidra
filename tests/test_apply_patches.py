"""Tests for assembling the patched image.

The behaviour under test is the one that changed: a patch that cannot be applied
is *reported*, not raised.  Raising discarded a whole run's emulation over one
bad entry, and a duplicate region is ordinary input -- two callsites can resolve
to the same obfuscation start.
"""

from ungarble.patcher import apply_patches

ORIGINAL = bytes(range(64))


def patch(offset, blob):
    return {"offset": offset, "bytes": blob}


def test_applies_disjoint_patches_and_leaves_the_rest_alone():
    image, rejected = apply_patches(
        ORIGINAL, [patch(4, b"AAAA"), patch(32, b"BB")]
    )
    assert rejected == []
    assert len(image) == len(ORIGINAL), "the file must not change size"
    assert image[4:8] == b"AAAA"
    assert image[32:34] == b"BB"
    assert image[:4] == ORIGINAL[:4]
    assert image[8:32] == ORIGINAL[8:32]
    assert image[34:] == ORIGINAL[34:]


def test_reports_an_overlap_instead_of_discarding_the_run():
    image, rejected = apply_patches(
        ORIGINAL, [patch(0, b"AAAAAAAA"), patch(4, b"BBBB"), patch(16, b"CC")]
    )
    assert [index for index, _ in rejected] == [1]
    assert "overlaps" in rejected[0][1]
    assert image[0:8] == b"AAAAAAAA"
    assert image[16:18] == b"CC"


def test_the_earlier_patch_wins_an_overlap():
    image, rejected = apply_patches(ORIGINAL, [patch(8, b"XX"), patch(8, b"YY")])
    assert image[8:10] == b"XX"
    assert [index for index, _ in rejected] == [1]


def test_a_duplicate_region_is_rejected_not_reapplied():
    duplicate = patch(12, b"same")
    image, rejected = apply_patches(ORIGINAL, [duplicate, dict(duplicate)])
    assert image[12:16] == b"same"
    assert [index for index, _ in rejected] == [1]


def test_reports_a_patch_running_past_the_end_of_the_file():
    image, rejected = apply_patches(
        ORIGINAL, [patch(60, b"ZZZZZZZZ"), patch(0, b"ok")]
    )
    assert [index for index, _ in rejected] == [0]
    assert "past end of file" in rejected[0][1]
    assert image[0:2] == b"ok"
    assert len(image) == len(ORIGINAL)


def test_a_patch_ending_exactly_at_the_end_of_the_file_is_fine():
    image, rejected = apply_patches(ORIGINAL, [patch(60, b"WXYZ")])
    assert rejected == []
    assert image[60:] == b"WXYZ"


def test_adjacent_patches_do_not_count_as_overlapping():
    image, rejected = apply_patches(ORIGINAL, [patch(0, b"AA"), patch(2, b"BB")])
    assert rejected == []
    assert image[0:4] == b"AABB"


def test_no_patches_returns_the_original_untouched():
    image, rejected = apply_patches(ORIGINAL, [])
    assert image == ORIGINAL
    assert rejected == []


def test_rejected_indices_address_the_input_list():
    patches = [patch(0, b"A"), patch(0, b"B"), patch(8, b"C"), patch(8, b"D")]
    _, rejected = apply_patches(ORIGINAL, patches)
    assert [index for index, _ in rejected] == [1, 3]
    for index, reason in rejected:
        assert "0x%x" % patches[index]["offset"] in reason
