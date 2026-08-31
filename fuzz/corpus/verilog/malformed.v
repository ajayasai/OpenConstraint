module missing_close(input a, output q;
  assign q = {a, 1'b0};
// no endmodule on purpose
