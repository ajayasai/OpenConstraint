module leaf(input clk, input [1:0] data, output q);
  DFF state (.CK(clk), .D(data[1]), .Q(q));
endmodule

module top(input clk, input [1:0] data, output result);
  leaf block (.clk(clk), .data(data), .q(result));
endmodule

module nonansi_bus(clk, data, result);
  input clk;
  input [3:0] data;
  output result;
  DFF state (.CK(clk), .D(data[0]), .Q(result));
endmodule
