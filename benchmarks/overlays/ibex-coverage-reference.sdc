# OpenConstraint coverage surrogate for OpenROAD's project-specific helper.
# Uses its documented 20%-of-period value. The explicit patterns cover every
# non-clock input without creating an invalid same-port clock relationship.
# This benchmark overlay is not sign-off SDC.
set_input_delay 3.031 -clock core_clock [get_ports {rst_ni test_en_i instr_gnt_i instr_rvalid_i instr_err_i data_gnt_i data_rvalid_i data_err_i irq_software_i irq_timer_i irq_external_i irq_nm_i debug_req_i fetch_enable_i boot_addr_i[[]*[]] data_rdata_i[[]*[]] hart_id_i[[]*[]] instr_rdata_i[[]*[]] irq_fast_i[[]*[]]}]
set_output_delay 3.031 -clock core_clock [all_outputs]
