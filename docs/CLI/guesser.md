# dog guesser
this is a cli verson of the `flagguesser` module, which you can read about [here](../modules/flagguesser.md). it lets you create and use models directly from the cli.
```bash
corgo@dog-computer:/tmp$ dog guesser guess "dogctf{congratz_u_got_it_48a093"

  dogctf{congratz_u_got_it_48a093 →

    7      17.9%
    4      12.7%
    e      10.9%
    5       7.1%
    1       6.9%
```

## help

```bash
corgo@dog-computer:/tmp$ dog guesser --help
usage: dog guesser [-h] {train,guess} ...

Byte-level n-gram flag guesser. Sub-commands: train, guess.

positional arguments:
  {train,guess}
    train        Train a model from a flags file
    guess        Show top-N likely next bytes for a flag prefix

options:
  -h, --help     show this help message and exit
```

```bash
corgo@dog-computer:/tmp$ dog guesser train --help
usage: dog guesser train [-h] [-o OUTPUT] [--order ORDER] [--generic] flags_file

Train a byte-level n-gram model from a file of flags (one per line).

positional arguments:
  flags_file           Path to a file with one flag per line.

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Output model path (gzip-compressed JSON). Default: model.json.gz
  --order ORDER        N-gram order (default: 5).
  --generic            Train on raw lines without stripping the flag prefix before '{'.
```
the 'order' of a model is how many characters it will read backwards to use to determine the next character. if you want to train on non-flag data, you should probably pass `--generic` (as we normally strip the flag prefix)

```bash
corgo@dog-computer:/tmp$ dog guesser guess --help
usage: dog guesser guess [-h] [-m MODEL] [--top TOP] [--hex] prefix

Load a model and print the most likely next bytes for a given prefix.

positional arguments:
  prefix             Flag prefix (UTF-8 string, or hex bytes with --hex).

options:
  -h, --help         show this help message and exit
  -m, --model MODEL  Path to a trained model (.json.gz). Omit to use the bundled model.
  --top TOP          How many guesses to show (default: 5).
  --hex              Interpret PREFIX as hex bytes.
```