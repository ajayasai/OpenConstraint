# Tiny synthetic example

This design and library are original, synthetic fixtures distributed with
OpenConstraint. They contain no foundry, vendor, or customer data.

Run the clean functional/scan comparison:

```console
openconstraint audit \
  --verilog examples/tiny/design.v \
  --liberty examples/tiny/cells.lib \
  --mode functional=examples/tiny/functional.sdc \
  --mode scan=examples/tiny/scan.sdc \
  --top tiny_top --format all --output reports/tiny-modes
```

Run the deliberately broken constraint set:

```console
openconstraint audit \
  --verilog examples/tiny/design.v \
  --liberty examples/tiny/cells.lib \
  --sdc examples/tiny/broken.sdc \
  --top tiny_top --format text --output - --fail-on never
```

`expected-broken-rules.txt` lists the stable rule IDs that the broken case is
intended to exercise. Exact human wording is not a compatibility surface.
