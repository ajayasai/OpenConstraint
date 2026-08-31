# OpenConstraint coverage surrogate for OpenROAD's project-specific helper.
# Uses its documented 20%-of-period value. The explicit patterns cover every
# non-clock input without creating an invalid same-port clock relationship.
# This benchmark overlay is not sign-off SDC.
set_input_delay 1.6 -clock clk [get_ports {ena rst dstrb din[[]*[]] qnt_val[[]*[]]}]
set_output_delay 1.6 -clock clk [all_outputs]
