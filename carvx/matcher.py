"""Multi-pattern matcher for signature magics.

Two backends with the same interface:
    finditer(buf) -> iterator of (start_offset, magic_bytes)

Default is a compiled regex alternation. In CPython this lowers to a C DFA
that scans at ~100+ MiB/s and beats a pure-Python Aho-Corasick automaton by
~4x, so it is the right choice for the stdlib-only path.

If the optional `pyahocorasick` C extension is installed, an Aho-Corasick
automaton is used instead - it scales better when the signature set is very
large (e.g. big --sig-file imports). Selection is automatic; force the regex
backend with backend="regex".
"""

import re

try:
    import ahocorasick                      # optional C extension
    _HAVE_AC = True
except ImportError:
    _HAVE_AC = False


class RegexMatcher:
    backend = "regex"

    def __init__(self, magics):
        # longest first so the alternation prefers the most specific magic
        ordered = sorted(set(magics), key=len, reverse=True)
        self._pattern = re.compile(b"|".join(re.escape(m) for m in ordered))

    def finditer(self, buf):
        for m in self._pattern.finditer(buf):
            yield m.start(), m.group(0)


class AhoCorasickMatcher:
    backend = "aho-corasick"

    def __init__(self, magics):
        self._a = ahocorasick.Automaton(ahocorasick.STORE_LENGTH)
        for magic in set(magics):
            self._a.add_word(bytes(magic))
        self._a.make_automaton()

    def finditer(self, buf):
        # pyahocorasick yields (end_index, length); recover (start, bytes)
        for end, length in self._a.iter(bytes(buf)):
            start = end - length + 1
            yield start, bytes(buf[start:end + 1])


def build(magics, backend="auto", many_threshold=200):
    """Pick a matcher. 'auto' uses Aho-Corasick only when the C extension is
    present AND the pattern set is large enough to benefit; else regex."""
    magics = list(magics)
    if backend == "regex":
        return RegexMatcher(magics)
    if backend == "aho-corasick":
        if not _HAVE_AC:
            raise RuntimeError("pyahocorasick not installed")
        return AhoCorasickMatcher(magics)
    # auto
    if _HAVE_AC and len(set(magics)) >= many_threshold:
        return AhoCorasickMatcher(magics)
    return RegexMatcher(magics)
