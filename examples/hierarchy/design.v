// Repository-owned parameterized, repeated and nested hierarchy fixture.
module lane #(parameter W = 2) (
    input clk, input reset, input [W-1:0] d, output reg [W-1:0] q
);
    always @(posedge clk)
        if (reset) q <= {W{1'b0}};
        else q <= d;
endmodule

module wrapper #(parameter W = 2) (
    input clk, input reset, input [W-1:0] d, output [W-1:0] q
);
    lane #(.W(W)) capture (.clk(clk), .reset(reset), .d(d), .q(q));
endmodule

module mix(input [2:0] i, output o);
    assign o = (i[2] ^ i[1]) & i[0];
endmodule

module top (
    input clk, input reset, input a, input b, input c,
    output [1:0] q_left, output [1:0] q_right, output [2:0] q_wide,
    output comb, output bad_pair
);
    wrapper #(.W(2)) left  (.clk(clk), .reset(reset), .d({a,b}), .q(q_left));
    wrapper #(.W(2)) right (.clk(clk), .reset(reset), .d({a,b}), .q(q_right));
    wrapper #(.W(3)) wide  (.clk(clk), .reset(reset), .d({a,b,c}), .q(q_wide));
    mix logic_mix (.i({a,b,c}), .o(comb));
    assign bad_pair = |(q_left ^ q_right);
endmodule
