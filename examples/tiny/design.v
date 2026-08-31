module tiny_top (
    input  wire       clk,
    input  wire       scan_clk,
    input  wire       rst_n,
    input  wire       scan_en,
    input  wire [1:0] din,
    output wire [1:0] dout
);
  wire selected_clk;
  MUX2 u_clk_mux (.A(clk), .B(scan_clk), .S(scan_en), .Y(selected_clk));
  DFFR u_ff0 (.D(din[0]), .CLK(selected_clk), .RN(rst_n), .Q(dout[0]));
  DFFR u_ff1 (.D(din[1]), .CLK(selected_clk), .RN(rst_n), .Q(dout[1]));
endmodule
