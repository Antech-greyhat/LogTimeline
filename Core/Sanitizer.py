r"""Make attacker-controlled log text safe to print to a terminal.

Usernames, commands and other fields in a log file are written by whoever
triggered the event - including an attacker, who chooses the username they try
to log in with. If such text contained raw ANSI escape sequences or control
characters, printing it to a terminal could move the cursor, hide or overwrite
text, or (in some terminals) trigger other actions. This is called
"terminal injection".

Our defense is simple and strict: every control character is replaced with a
visible ``\xNN`` form. This keeps output readable, shows the analyst that
something odd was in the log, and removes the dangerous bytes - an ESC
character (``0x1b``) becomes the literal four-character text ``\x1b`` and can
no longer start an escape sequence.

JSON output does not use this function: the standard ``json`` module already
escapes control characters to ``\uXXXX`` when it serializes strings.
"""


def sanitize(text: str) -> str:
    r"""Return ``text`` with every control character made visible.

    Control characters are those below space (``0x00``-``0x1f``), ``DEL``
    (``0x7f``) and the rarely used C1 range (``0x80``-``0x9f``). Everything
    else - ordinary letters, digits, punctuation and normal Unicode - is left
    unchanged, so a legitimate non-English username such as ``josé`` still
    displays correctly.

    Example: ``sanitize("admin\x1b[2J")`` returns ``"admin\\x1b[2J"`` (the ESC
    is neutralized; the harmless ``[2J`` text remains).
    """
    safe_chars = []
    for char in text:
        code = ord(char)
        is_c0 = code < 0x20            # NUL, BEL, TAB, newline, ESC, ...
        is_del = code == 0x7F          # the DEL character
        is_c1 = 0x80 <= code <= 0x9F   # rarely used C1 control range
        if is_c0 or is_del or is_c1:
            # "\\x" is a literal backslash + x; the result is text like \x1b.
            safe_chars.append("\\x{:02x}".format(code))
        else:
            safe_chars.append(char)
    return "".join(safe_chars)
