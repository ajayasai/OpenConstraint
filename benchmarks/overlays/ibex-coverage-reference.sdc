# OpenConstraint coverage surrogate for OpenROAD's project-specific helper.
# Uses its documented 20%-of-period value. In a Tcl engine, all_inputs also
# selects core_clock; OpenConstraint's input-delay denominator excludes clock
# ports. This benchmark overlay is not sign-off SDC.
set_input_delay 3.031 -clock core_clock [all_inputs]
set_output_delay 3.031 -clock core_clock [all_outputs]
