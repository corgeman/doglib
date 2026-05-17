# `dog brute`
`dog brute` can be used to easily orchestrate the bruteforce of any solve script.  

just run `dog brute [path_to_script] [script_arguments]` and you'll be dropped into a TUI:
```bash
dog brute  brute_cat.py  -  4 workers  -  elapsed 00:05
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ #1    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
│ #2    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
│ #3    0:00  ██████████████████░░░░░░░░░░░░  3  attempt step 0                              │
│ #4    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

11.2 iter/s  ·  total: 64  ·  h=help  ·  q=quit
```
if a worker succeeds, pressing `i` will 'swap' your terminal over to that worker.


## setup
`dog brute` only needs you to add one thing to your solve script: `finish()`.  

call this function right *before* you drop into `.interactive()`, print a flag, etc etc, and you're good to go.


## cli
the format for the CLI is `dog brute [CLI_ARGUMENTS] [SCRIPT_AND_ARGUMENTS]`.  
for example: `dog brute --instant solve.py REMOTE 127.0.0.1`  
```bash
usage: dog brute [-h] [-n N] [--timeout SEC] [--delay SEC] [--instant] [--no-finish-check] solve.py ...

Spawn multiple workers running the same solve script. When one worker calls dog.finish(), dog brute hands that worker's terminal back to you for
interactive use.

positional arguments:
  solve.py           Solve script to run
  script-arg         Arguments passed to solve.py

options:
  -h, --help         show this help message and exit
  -n, --workers N    Initial worker count (default: min(8, os.cpu_count()))
  --timeout SEC      Per-attempt timeout in seconds (default: 60)
  --delay SEC        Delay before respawning a finished attempt (default: 0)
  --instant          Immediately hand off to a worker when it calls dog.finish()
  --no-finish-check  Skip the static check that warns when solve.py has no finish() call
```

## tui
upon running `dog brute ...` you'll be dropped into a TUI like this (minus the annotation):
```bash
  ID    time elapsed   progress bar  infocount  last info message
  │      │                  │           └━━┐      │
  ▼      ▼                  ▼              ▼      ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ #1    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
│ #2    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
│ #3    0:00  ██████████████████░░░░░░░░░░░░  3  attempt step 0                              │
│ #4    0:00  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0  starting                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

11.2 iter/s  ·  total: 64  ·  h=help  ·  q=quit
   ▲                ▲ 
   │                │
 attempts/s      total attempts
```
the progress bar and infocount are made by tracking how many `info()` calls your program makes

### tui commands
the tui also has some management commands. they are:

* `up/down`: move between a selected worker process
* `[enter]`: monitor a worker, getting its live output
* `r`: restart a single worker, ex. if you notice one hanged
* `+` / `-`: add or remove a worker
* `[space]`: pause/unpause all workers from running
* `f`: show the output of the most recent failure
* `i`: go 'interactive'-- swap your terminal with a worker that succeeded
* `q`: exit the TUI



## advanced usage / warnings
* scripts taking longer than 60s are killed to prevent hangs. adjust `--timeout` as necessary.  
* if you're low on time, `--instant` will IMMEDIATELY swap terminals upon a worker succeeding.
* you can use this module for specific bruteforces, ex. trying every number 1-1000. see the [brute api](../modules/brute.md)
* adding `BRUTE` to your args (`python ./solve.py REMOTE 127.0.0.1 BRUTE`) will automatically launch it in bruteforce mode