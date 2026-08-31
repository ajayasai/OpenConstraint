module tiny_top (
    input  wire       clk,
    input  wire       rst_n,
    input  wire [1:0] din,
    input  wire       scan_clk,
    input  wire       scan_en,
    output wire [1:0] dout
);
  DFF u_ff0 (.D(din[0]), .CLK(clk), .Q(dout[0]), .RN(rst_n));
  DFF u_ff1 (.D(din[1]), .CLK(clk), .Q(dout[1]), .RN(rst_n));
endmodule
