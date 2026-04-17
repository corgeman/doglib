# flagguesser

silly module to speed up character-by-character flag bruteforces

sometimes a challenge requires us to slowly leak a flag character-by-character, for instance when doing blind SQL injection.

the idea is that naively checking `A, B, C...` is inefficient, and we should instead be checking in order of the most common characters that show up in flags.  

even better, we should put what we've leaked into context-- if we've leaked `fakectf{g00d_job_e8af30`, we should probably first guess `[a-f0-9]` before anything else.

i scraped 10k+ real flags from previous competitions to create both of these. if you just want the most common characters that show up in flags, here it is:
```text
_te3ran0cs1lfi4do{}uhgbmy5p7CwT2k6F9S8-vAEN!UDR ILMHPO.jxGzY?BWK@q:V/JXZ,Q'$*+][;=)>(&|#\^<"~%`
```
or, as a string:
```python
common = '_te3ran0cs1lfi4do{}uhgbmy5p7CwT2k6F9S8-vAEN!UDR ILMHPO.jxGzY?BWK@q:V/JXZ,Q\'$*+][;=)>(&|#\\^<"~%`'
```

but if you want to go a step further, you can use the `flagguesser` module. this is an extremely small ngram model trained on all the flags i scraped. it looks at the last 5 characters you've leaked, then returns a list of every byte 0-256 sorted by likeliness:
```python
>>> from dog import *
>>> guesser("dogctf{th")[:6]
[b'e', b'3', b'_', b'a', b'i', b'1']
>>> guesser("dogctf{good_job_e8a906")[:10]
[b'9', b'd', b'8', b'1', b'6', b'0', b'4', b'3', b'5', b'}']
```

if you want to do your own analysis for fun, you can find the scraped flags (and repositories) at `src/doglib/data/flagguesser`.


# API

### `#!python guesser: Guesser`
`Guesser` instance loaded with a model trained on ctf flags. this is probably what you want.
```python
>>> from dog import *
>>> guesser("flag{wh3r")[:5]
[b'3', b'e', b'_', b'}', b's']
```

### `#!python CTFFREQ: bytes`
a string of every ascii character, sorted by how frequently it shows up in flags.

### `#!python CTFFREQ_ALL: bytes`
a string of every byte 0-256, sorted by how frequently it shows up in flags.

### `#!python flagguesser.NGramModel`
this class is not very relevant, it's a generic ngram model. you should only look at this if you'd like to train your own model for something else (in that case, see the CLI section)

### `#!python flagguesser.Guesser`
class for getting output from an `NGramModel`.
#### `#!python def __init__(model: NGramModel)`
load an NGramModel for inference.
#### `#!python def guess(prefix: bytes | str, stats: bool = False)`
given some known data `prefix`, return a list of every byte 0-256, sorted by likelihood:
```python
>>> guesser.guess("flag{the_fl")[:3]
[b'a', b'4', b'o']
>>> guesser.guess("flag{th3_fl")[:3]
[b'4', b'a', b'1']
```
if `stats` is true, you'll be given the exact percentage of likelihood:
```python
>>> guesser.guess("flag{th3_fl",stats=True)[:3]
[(52, 0.4225396483136242), (97, 0.28357899445506607), (49, 0.06058591039291106)]
>>>
```
#### `#!python def __call__(prefix: bytes | str, stats: bool = False)`
same as `.guess`




