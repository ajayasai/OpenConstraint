# OpenConstraint coverage surrogate for OpenROAD's project-specific helper.
# Uses its documented 20%-of-period value. The explicit patterns cover every
# non-clock input without creating an invalid same-port clock relationship.
# This benchmark overlay is not sign-off SDC.
set_input_delay 0.748 -clock clk [get_ports {rst ld key[[]*[]] text_in[[]*[]]}]
set_output_delay 0.748 -clock clk [all_outputs]
