from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from openconstraint.engine import AuditOptions, ModeInput, audit
from openconstraint.parsers.liberty import CellLibrary, parse_liberty, parse_liberty_text
from openconstraint.parsers.verilog import elaborate, parse_verilog, parse_verilog_text

SYNTHETIC_LIBERTY = r"""
library (synthetic) {
  /* Combinational cells exercise propagation and ordinary pin metadata. */
  cell (BUF) {
    pin (A) { direction : input; }
    pin (Y) { direction : output; function : "A"; }
  }
  cell (INV) {
    pin (A) { direction : input; }
    pin (Y) { direction : output; function : "!A"; }
  }
  cell (DFF) {
    ff (IQ, IQN) {
      clocked_on : "CK";
      next_state : "D";
    }
    pin (CK) { direction : input; clock : true; }
    pin (D)  { direction : input; }
    pin (Q)  { direction : output; }
  }
  cell (DFFR) {
    ff (IQ, IQN) {
      clocked_on : "CK";
      next_state : "D";
      clear : "RN";
    }
    pin (CK) { direction : input; clock : true; }
    pin (D)  { direction : input; }
    pin (RN) { direction : input; }
    pin (Q)  { direction : output; }
  }
  cell (DLAT) {
    latch (IQ, IQN) {
      enable : "G";
      data_in : "D";
    }
    pin (G) { direction : input; clock : true; }
    pin (D) { direction : input; }
    pin (Q) { direction : output; }
  }
}
"""


SYNTHETIC_VERILOG = r"""
module top(
  input clk,
  input clk2,
  input data,
  input spare,
  output result
);
  wire q;
  DFF u_ff (.CK(clk), .D(data), .Q(q));
  BUF u_out (.A(q), .Y(result));
endmodule
"""


COMPLETE_SDC = r"""
create_clock -name core -period 10 -waveform {0 5} [get_ports clk]
set_input_delay 1 -clock core [all_inputs]
set_output_delay 2 -clock core [all_outputs]
"""


def write_text(path: Path, text: str) -> Path:
    path.write_text(text.strip() + "\n", encoding="utf-8", newline="\n")
    return path


@pytest.fixture
def project_files(tmp_path: Path) -> Callable[..., tuple[Path, Path, Path]]:
    def create(
        *,
        verilog: str = SYNTHETIC_VERILOG,
        liberty: str = SYNTHETIC_LIBERTY,
        sdc: str = COMPLETE_SDC,
        stem: str = "case",
    ) -> tuple[Path, Path, Path]:
        return (
            write_text(tmp_path / f"{stem}.v", verilog),
            write_text(tmp_path / f"{stem}.lib", liberty),
            write_text(tmp_path / f"{stem}.sdc", sdc),
        )

    return create


@pytest.fixture
def design_factory() -> Callable[..., object]:
    def create(*, verilog: str = SYNTHETIC_VERILOG, liberty: str = SYNTHETIC_LIBERTY, top: str = "top") -> object:
        return elaborate(parse_verilog_text(verilog), parse_liberty_text(liberty), top)

    return create


@pytest.fixture
def audit_factory(tmp_path: Path, design_factory: Callable[..., object]) -> Callable[..., object]:
    counter = 0

    def run(
        sdc: str | list[tuple[str, str]],
        *,
        verilog: str = SYNTHETIC_VERILOG,
        liberty: str = SYNTHETIC_LIBERTY,
        options: AuditOptions | None = None,
    ) -> object:
        nonlocal counter
        counter += 1
        design = design_factory(verilog=verilog, liberty=liberty)
        mode_inputs: list[ModeInput] = []
        entries = [("default", sdc)] if isinstance(sdc, str) else sdc
        for mode_name, mode_sdc in entries:
            path = write_text(tmp_path / f"audit-{counter}-{mode_name}.sdc", mode_sdc)
            mode_inputs.append(ModeInput(mode_name, [str(path)]))
        return audit(design, mode_inputs, options)

    return run


@pytest.fixture
def file_design(project_files: Callable[..., tuple[Path, Path, Path]]) -> Callable[..., object]:
    def create(**kwargs: str) -> object:
        verilog_path, liberty_path, _ = project_files(**kwargs)
        library = CellLibrary()
        library.merge(parse_liberty(liberty_path))
        return elaborate(parse_verilog([verilog_path]), library, "top")

    return create


def diagnostic_ids(result: object) -> list[str]:
    return [item.rule_id for item in result.diagnostics]
