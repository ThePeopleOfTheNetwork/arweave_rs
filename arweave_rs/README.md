Binary package the contains the tests for block validation.

Eventually these tests should be moved into the individual packages.

Tests are executed in sequence using a `fn main()` function.

Why?

We don't rely on rusts #[test] or #[bench] features because...

```
  #[test] - tries to run all the tests in parallel but the functions themselves 
   are already highly parallelized and long running causing huge delays when 
   running them simultaneously.

 #[bench] - tries to run the benchmark tests multiple times to get a 
   statistically valid measurement of each test. But some of these validation 
   tests take 30s or more making benchmark tests unbearably slow.
```

In the end we just want to run our tests (which have high parallelism) sequentially
one by one, which is why calling them one by one from `fn main()` works the best.
