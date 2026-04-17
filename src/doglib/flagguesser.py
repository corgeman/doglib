"""Byte-level n-gram flag guesser.

Combines the NGramModel (linear-interpolation n-gram LM) and the
Guesser high-level API. Trained on >10k scraped CTF flags.

The module-level ``guesser`` is a ready-to-use instance backed by the
bundled model so you can start guessing immediately:

    from dog import guesser, CTFFREQ
    for b in guesser.guess(b"flag{"):
        ...
"""

# if you're bored feel free to check out ./src/doglib/data/flagguesser/all_scraped_flags.txt.gz

import gzip
import json
from collections import defaultdict
from collections.abc import Iterable

# ---------------------------------------------------------------------------
# NGramModel
# ---------------------------------------------------------------------------

BOS = 256
EOS = 257

_FORMAT_TAG = "flagguesser-ngram-v1"


class NGramModel:
    """Byte-level n-gram language model with linear-interpolation smoothing.

    Internally the alphabet is 0..255 (real bytes) plus two out-of-band
    sentinels: BOS=256 and EOS=257. Sentinels are only used to wrap training
    sequences so position-1 predictions know they are at the start of a flag.
    """

    def __init__(self, order: int = 5):
        if order < 1:
            raise ValueError("order must be >= 1")
        self.order = order
        self.counts: list[dict[tuple[int, ...], dict[int, int]]] = [
            defaultdict(lambda: defaultdict(int)) for _ in range(order)
        ]
        self.totals: list[dict[tuple[int, ...], int]] = [
            defaultdict(int) for _ in range(order)
        ]
        self.num_flags = 0

    # ---------- training ----------

    def fit(self, flags: Iterable[bytes]) -> None:
        order = self.order
        for flag in flags:
            self.num_flags += 1
            seq = [BOS] * (order - 1) + list(flag) + [EOS]
            for i in range(order - 1, len(seq)):
                nxt = seq[i]
                for k in range(order):
                    ctx = tuple(seq[i - k : i]) if k > 0 else ()
                    self.counts[k][ctx][nxt] += 1
                    self.totals[k][ctx] += 1

    # ---------- scoring ----------

    def score_distribution(self, context: tuple[int, ...]) -> list[float]:
        """Return P(next byte | context) over the 256 real bytes."""
        order = self.order
        if len(context) > order - 1:
            context = tuple(context[-(order - 1) :])

        weights = [1 << k for k in range(order)]

        scores = [0.0] * 256
        for k in range(order):
            if k > len(context):
                break
            ctx = context[len(context) - k :] if k > 0 else ()
            total = self.totals[k].get(ctx, 0)
            if total == 0:
                continue
            inv = weights[k] / total
            for sym, cnt in self.counts[k][ctx].items():
                if sym < 256:
                    scores[sym] += cnt * inv

        eps = 1e-12
        for i in range(256):
            scores[i] += eps
        s = sum(scores)
        inv_s = 1.0 / s
        for i in range(256):
            scores[i] *= inv_s
        return scores

    # ---------- persistence ----------

    @staticmethod
    def _encode_ctx(ctx: tuple[int, ...]) -> str:
        return ",".join(str(x) for x in ctx)

    @staticmethod
    def _decode_ctx(s: str) -> tuple[int, ...]:
        if not s:
            return ()
        return tuple(int(x) for x in s.split(","))

    def _to_plain(self) -> dict:
        return {
            "format": _FORMAT_TAG,
            "order": self.order,
            "num_flags": self.num_flags,
            "counts": [
                {
                    self._encode_ctx(ctx): {str(sym): cnt for sym, cnt in tbl.items()}
                    for ctx, tbl in self.counts[k].items()
                }
                for k in range(self.order)
            ],
        }

    @classmethod
    def _from_plain(cls, data: dict) -> "NGramModel":
        if not isinstance(data, dict) or data.get("format") != _FORMAT_TAG:
            raise ValueError(f"unrecognized model file: expected format {_FORMAT_TAG!r}")
        order = int(data["order"])
        m = cls(order=order)
        m.num_flags = int(data.get("num_flags", 0))
        raw_counts = data["counts"]
        if len(raw_counts) != order:
            raise ValueError("model file: counts length does not match order")
        for k in range(order):
            for ctx_str, tbl in raw_counts[k].items():
                ctx = cls._decode_ctx(ctx_str)
                if len(ctx) != k:
                    raise ValueError(
                        f"model file: context {ctx_str!r} has wrong length for k={k}"
                    )
                decoded = {int(sym): int(cnt) for sym, cnt in tbl.items()}
                m.counts[k][ctx] = defaultdict(int, decoded)
                m.totals[k][ctx] = sum(decoded.values())
        return m

    def save(self, path: str) -> None:
        with gzip.open(path, "wt", encoding="utf-8") as f:
            json.dump(self._to_plain(), f, separators=(",", ":"))

    @classmethod
    def load(cls, path: str) -> "NGramModel":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return cls._from_plain(json.load(f))

    @classmethod
    def load_fileobj(cls, fileobj) -> "NGramModel":
        with gzip.open(fileobj, "rt", encoding="utf-8") as f:
            return cls._from_plain(json.load(f))

    # ---------- introspection ----------

    def num_contexts(self) -> int:
        return sum(len(self.counts[k]) for k in range(self.order))


# ---------------------------------------------------------------------------
# Guesser
# ---------------------------------------------------------------------------

# Basic single-char frequency analysis of >10k scraped flags.
# Use to speed up char-by-char bruteforce.
CTFFREQ = b'_te3ran0cs1lfi4do{}uhgbmy5p7CwT2k6F9S8-vAEN!UDR ILMHPO.jxGzY?BWK@q:V/JXZ,Q\'$*+][;=)>(&|#\\^<"~%`'

# Above, but without stripping non-printables — all bytes 0-255.
CTFFREQ_ALL = (
    b'_te3ran0cs1lfi4do{}uhgbmy5p7CwT2k6F9S8-vAEN!UDR ILMHPO.jxGzY?BWK@q:V/'
    b'JXZ,Q\'$*+][;=)>(&|#\xe2\\^<"\xc3\xaf\x98\xa0\xce\xe0~\xa9\xc2\xd0%\x8c'
    b'\x9f\x89\xb1\xe5\xc9\xe1\x9b\xa5\x87\xb8\x80\x81\x9d\xc6\xe3\xf0\r\x9a'
    b'\xb4\xbc\xca\x84\x94\x95\x96\xb9\xbd\xe4\x82\x88\x91\xb0\xc7\xcf\x83\xb5'
    b'\xbb\x8a\x97\xa4\xad\xe6\x8d\x90\xef\x86\x92\xa1\xa2\xa8\xe7\x85\xac\xb6`'
    b'\x8b\x8f\x9c\xa3\xa7\xb2\xe9\x8e\x99\x9e\xb3\xba\xbf\xd1\xd9\xe8\xa6\xab\xae'
    b'\xbe\xee\x05\x93\xaa\xb7\xc4\xc8\xd3\xd4\xd6\xd8\xdb\xeb\xed\x00\x01\x02\x03'
    b'\x04\x06\x07\x08\t\n\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19'
    b'\x1a\x1b\x1c\x1d\x1e\x1f\x7f\xc0\xc1\xc5\xcb\xcc\xcd\xd2\xd5\xd7\xda\xdc\xdd'
    b'\xde\xdf\xea\xec\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
)



class Guesser:
    """High-level next-byte ranker on top of NGramModel."""

    def __init__(self, model: NGramModel):
        self.model = model

    def _context(self, prefix: bytes) -> tuple[int, ...]:
        n = self.model.order - 1
        if n <= 0:
            return ()
        padded = [BOS] * n + list(prefix)
        return tuple(padded[-n:])

    def guess(self, prefix: bytes | str, *, stats: bool = False):
        """Return all 256 byte values ranked by P(next byte | prefix).

        By default returns ``list[bytes]`` (one per byte value). Pass
        ``stats=True`` for ``list[tuple[int, float]]`` of
        ``(byte_value, probability)`` pairs, sorted descending.
        """
        if isinstance(prefix, str):
            prefix = prefix.encode()
        ctx = self._context(prefix)
        scores = self.model.score_distribution(ctx)
        indexed = sorted(enumerate(scores), key=lambda t: (-t[1], t[0]))
        if stats:
            return [(i, p) for i, p in indexed]
        return [bytes((i,)) for i, _ in indexed]


# ---------------------------------------------------------------------------
# Bundled instance (lazy-loaded)
# ---------------------------------------------------------------------------

class _LazyGuesser:
    """Proxy for the bundled Guesser that defers model loading until first use."""

    _real: Guesser | None = None

    def _load(self) -> Guesser:
        if self._real is None:
            from importlib.resources import files
            resource = files("doglib.data.flagguesser").joinpath("model.json.gz")
            with resource.open("rb") as f:
                model = NGramModel.load_fileobj(f)
            self._real = Guesser(model)
        return self._real

    def guess(self, prefix: bytes, *, stats: bool = False):
        return self._load().guess(prefix, stats=stats)
    
    def __call__(self, prefix: bytes | str, *, stats: bool = False):
        return self.guess(prefix, stats=stats)

    @property
    def model(self) -> NGramModel:
        return self._load().model


guesser: Guesser = _LazyGuesser()  # type: ignore[assignment]


__all__ = ["CTFFREQ", "CTFFREQ_ALL", "guesser"]
