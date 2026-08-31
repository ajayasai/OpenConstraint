module opensta_roundtrip (
  input  wire clk,
  input  wire data,
  output wire q
);
  DFF u_ff (.D(data), .CLK(clk), .Q(q));
endmodule
