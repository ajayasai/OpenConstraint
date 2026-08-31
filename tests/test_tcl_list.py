from __future__ import annotations

import pytest

from openconstraint.parsers.tcl import (
    MAX_TCL_LIST_ELEMENTS,
    MAX_TCL_LIST_NESTING,
    TclSyntaxError,
    split_tcl_list,
    split_tcl_list_preserving_backslashes,
)


def test_generic_tcl_list_decodes_grouping_and_backslashes() -> None:
    assert split_tcl_list(r'core {aux clock} {{nested}} "quoted clock" escaped\ clock line\nfeed') == (
        "core",
        "aux clock",
        "{nested}",
        "quoted clock",
        "escaped clock",
        "line\nfeed",
    )


def test_generic_tcl_list_preserves_braced_backslashes_and_nested_structure() -> None:
    assert split_tcl_list(r"{a\ b {c d} \{escaped\}}") == (r"a\ b {c d} \{escaped\}",)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{open", "unmatched open brace"),
        ('"open', "unmatched quote"),
        ("{closed}suffix", "extra characters after close-brace"),
        ('"closed"suffix', "extra characters after close-quote"),
    ],
)
def test_generic_tcl_list_rejects_malformed_structure(value: str, message: str) -> None:
    with pytest.raises(TclSyntaxError, match=message):
        split_tcl_list(value)


def test_generic_tcl_list_nesting_is_bounded() -> None:
    value = "{" * (MAX_TCL_LIST_NESTING + 1) + "x" + "}" * (MAX_TCL_LIST_NESTING + 1)

    with pytest.raises(TclSyntaxError, match="nesting limit"):
        split_tcl_list(value)


def test_generic_tcl_list_element_retention_is_bounded() -> None:
    value = "x " * (MAX_TCL_LIST_ELEMENTS + 1)

    with pytest.raises(TclSyntaxError, match="exceeds .* elements"):
        split_tcl_list(value)


def test_pattern_tcl_list_nesting_is_bounded() -> None:
    value = "{" * (MAX_TCL_LIST_NESTING + 1) + "x" + "}" * (MAX_TCL_LIST_NESTING + 1)

    with pytest.raises(TclSyntaxError, match="nesting limit"):
        split_tcl_list_preserving_backslashes(value)


def test_pattern_tcl_list_element_retention_is_bounded_without_partial_result() -> None:
    value = "x " * (MAX_TCL_LIST_ELEMENTS + 1)

    with pytest.raises(TclSyntaxError, match="exceeds .* elements"):
        split_tcl_list_preserving_backslashes(value)


def test_pattern_tcl_list_accepts_the_exact_element_limit() -> None:
    value = "x " * MAX_TCL_LIST_ELEMENTS

    assert len(split_tcl_list_preserving_backslashes(value)) == MAX_TCL_LIST_ELEMENTS
