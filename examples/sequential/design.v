// Owned conformance fixture: synchronous reset; no assumed power-up values.
module top(
  input clk, input reset, input data,
  output reg phase, output reg left, output reg right,
  output bad_equal, output bad_spacing2, output bad_spacing3
);
  reg last_event, older_event;
  always @(posedge clk) begin
    if (reset) begin
      phase <= 1'b0;
      left <= 1'b0;
      right <= 1'b0;
      last_event <= 1'b0;
      older_event <= 1'b0;
    end else begin
      phase <= ~phase;
      if (phase) begin
        left <= data;
        right <= data;
      end
      last_event <= phase;
      older_event <= last_event;
    end
  end
  assign bad_equal = left ^ right;
  assign bad_spacing2 = phase & last_event;
  assign bad_spacing3 = phase & (last_event | older_event);
endmodule
