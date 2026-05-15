# `brute`

`brute` is the main code for [`dog brute`](../CLI/brute.md). it exposes a few things to assist with bruteforcing.


### `#!python finish(reason: str = "finished") -> None`
notify the orchestrator that your script has succeeded. required for `dog brute` to work
```python
p = process("/vuln")
will_likely_crash(p)
finish("bruteforce worked! entering shell...")
p.interactive()
```

### `#!python brute_id: int | None`
the ID of the worker process running this script. you can use this to try different things in each worker process, ex. mmap relativity:
```python
# 0, 0x1000, -0x1000, 0x2000, -0x2000...
def f(n):
    return 0x1000 * (n // 2) * (1 if n % 2 == 0 else -1)

...

libc.address = get_libc_leak()
tls_address = libc.address - 0x5000 + f(brute_id)
do_unlikely_thing()
```


### `#!python brute_workers: int | None`
the current number of workers. you can use this in combination with `brute_id` to split work between workers.  
note that `brute_id` may be higher than `brute_workers` if you delete workers in the TUI.


### `#!python brute_attempt: int | None`
the attempt number of this process, starting from 1. useful as a monotonic counter:

```python
def make_guess():
    p.readuntil(b"What number am I thinking of?")
    p.sendline(str(brute_attempt).encode())

make_guess() # connection closes if wrong
p.recv()     # so this would error
finish(f"magic number is {brute_attempt}")
```