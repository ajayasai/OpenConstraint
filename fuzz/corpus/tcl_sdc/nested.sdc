set_false_path -from [get_clocks -filter {name =~ "core*"} *] \
  -through [get_pins -hierarchical {u0/A u1/Z}] \
  -to [get_clocks {scan test}]
set note {semicolons; and # characters stay grouped}
