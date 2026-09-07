module top(input data, input spare, output result, output extra);
 wire l,r,j;
 BUF u_left (.A(data),.Y(l)); BUF u_right (.A(data),.Y(r));
 OR2 u_join (.A(l),.B(r),.Y(j)); BUF u_out (.A(j),.Y(result));
 BUF u_extra (.A(spare),.Y(extra)); endmodule
