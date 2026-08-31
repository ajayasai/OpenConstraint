module escaped(input \clock/net , output q);
  wire \internal.signal ;
  BUF \instance/path  (.A(\clock/net ), .Y(q));
endmodule
