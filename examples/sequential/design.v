// Repository-owned validation fixture. Synchronous reset; no initial blocks.
module top(input clk, input reset, input data,
           output reg phase, output reg held_a, output reg held_b,
           output bad_equal, output bad_spacing2, output bad_spacing3);
    reg previous;
    reg previous2;
    always @(posedge clk) begin
        if (reset) begin
            phase <= 0;
            held_a <= 0;
            held_b <= 0;
            previous <= 0;
            previous2 <= 0;
        end else begin
            phase <= ~phase;
            previous <= phase;
            previous2 <= previous;
            if (phase) begin
                held_a <= data;
                held_b <= data;
            end
        end
    end
    assign bad_equal = held_a ^ held_b;
    assign bad_spacing2 = phase & previous;
    assign bad_spacing3 = phase & (previous | previous2);
endmodule
