# OpenConstraint coverage surrogate for OpenROAD's project-specific helper.
# Uses its documented 20%-of-period value. In a Tcl engine, all_inputs also
# selects clk; OpenConstraint's input-delay denominator excludes clock ports.
# This benchmark overlay is not sign-off SDC.
set_input_delay 0.748 -clock clk [all_inputs]
set_output_delay 0.748 -clock clk [all_outputs]
