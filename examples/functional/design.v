// Real Yosys CI input. Not a timing signoff example.
module top(input a, input enable, output out);
  assign out = a & enable;
endmodule
