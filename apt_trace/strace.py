import re
from functools import wraps
from logging import getLogger
from typing import Callable, Iterator

logger = getLogger(__name__)


class ParseWarning(RuntimeWarning):
    pass


class ParseError(RuntimeError):
    pass


class UnexpectedTokenError(ParseError):
    pass


class EndOfStringError(ParseError):
    pass


class Arg:
    def __init__(self, value: str, quoted: bool = False):
        self.value: str = value
        self.quoted: bool = quoted

    def __bool__(self):
        return self.quoted or bool(self.value)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return (
            (
                isinstance(other, Arg)
                and self.value == other.value
                and self.quoted == other.quoted
            )
            or isinstance(other, str)
            and self.value == other
        )

    def __str__(self):
        return self.value

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(value={self.value!r}, quoted={self.quoted!r})"
        )


class ListArg(Arg):
    def __init__(self, *items: Arg):
        super().__init__(f"[{', '.join(map(str, items))}]", quoted=False)
        self.items: tuple[Arg, ...] = items

    def __hash__(self):
        return hash(self.items)

    def __eq__(self, other):
        return isinstance(other, ListArg) and self.items == other.items


class ParsingContext:
    def __init__(self, text: str, offset: int = 0):
        self.text: str = text
        self.offset: int = offset
        self._sub_contexts: list[ParsingContext] = []

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int):
        self.offset = offset

    def expect(self, *any_of: str) -> str:
        any_of = frozenset(any_of)  # type: ignore
        c = self.peek()
        if c == "":
            if not any_of:
                return ""
            what_found = "the end of the string"
        else:
            what_found = repr(c)
        if c not in any_of:
            any_of = sorted(any_of)  # type: ignore
            if not any_of:
                what_expected = "the end of the string"
            elif len(any_of) == 1:
                what_expected = repr(any_of)
            else:
                what_expected = ", ".join(map(repr, any_of[:-1]))
                what_expected = (
                    f"{what_expected}{['', ','][len(any_of) > 2]} or {any_of[-1]}"
                )
            raise ParseError(
                f"Expected {what_expected} but instead found {what_found} at offset {self.offset} of "
                f"{self.text!r}"
            )
        self.offset += 1
        return c

    def __enter__(self) -> "ParsingContext":
        ret = ParsingContext(self.text, self.offset)
        self._sub_contexts.append(ret)
        return ret

    def __exit__(self, exc_type, exc_val, exc_tb):
        ctx = self._sub_contexts.pop()
        if exc_type is None:
            if not self._sub_contexts:
                self.offset = ctx.offset
            else:
                self._sub_contexts[-1].offset = ctx.offset

    def try_production(self, prod: Callable[["ParsingContext"], Arg]) -> Arg | None:
        try:
            with self as ctx:
                return prod(ctx)
        except ParseError:
            return None

    def lstrip(self):
        while self.peek() in (" ", "\t"):
            self.offset += 1

    def peek(self, n: int = 1) -> str:
        return self.text[self.offset : self.offset + n]

    def next(self) -> str:
        ret = self.peek()
        if len(ret) > 0:
            self.offset += 1
        return ret

    def __bool__(self):
        return self.offset < len(self.text)

    def __str__(self):
        return self.text


def production(
    func: Callable[[ParsingContext], Arg],
) -> Callable[[str | ParsingContext], Arg]:
    @wraps(func)
    def wrapper(text: str | ParsingContext) -> Arg:
        if isinstance(text, str):
            text = ParsingContext(text)

        return func(text)

    return wrapper


escapes = {"n": "\n", "t": "\t", "b": "\b", "r": "\r", "\\": "\\", '"': '"', "'": "'"}


@production
def parse_escape(text: ParsingContext) -> Arg:
    text.expect("\\")
    c = text.next()
    if c not in escapes:
        logger.warning(
            f'Invalid escape "\\{c!s}" in {str(text)!r} at offset {text.offset-1}'
        )
        return Arg(c)
    else:
        return Arg(escapes[c])


@production
def parse_comment(text: ParsingContext) -> Arg:
    text.expect("/")
    text.expect("*")
    while text and text.peek(2) != "*/":
        text.offset += 1
    text.expect("*")
    text.expect("/")
    return Arg("")


@production
def parse_quoted_string(text: ParsingContext) -> Arg:
    quote_char = text.expect('"', "'")

    parsed = ""

    while True:
        c: str | Arg = text.next()
        if c == quote_char:
            break
        elif c == "":
            raise EndOfStringError(
                f"Reached the end of the string {str(text)!r} while searching for {quote_char!r}"
            )
        elif c == "\\":
            text.seek(text.tell() - 1)
            c = parse_escape(text)
        parsed = f"{parsed}{c}"

    return Arg(parsed, quoted=True)


@production
def parse_list(text: ParsingContext) -> ListArg:
    text.expect("[")
    first = True
    items = []
    while text.peek() != "]":
        text.lstrip()
        if first:
            first = False
        elif text:
            if text.peek(n=3) == "...":
                text.offset += 3
                text.lstrip()
                items.append(Arg("..."))
                break
            else:
                text.expect(",")
                text.lstrip()
        items.append(parse_syscall_arg(text))
    text.expect("]")
    return ListArg(*items)


@production
def parse_syscall_arg(text: ParsingContext) -> Arg:
    text.lstrip()

    ret = text.try_production(parse_quoted_string)
    if ret is not None:
        return ret
    ret = text.try_production(parse_list)
    if ret is not None:
        return ret

    arg = ""

    while True:
        _ = text.try_production(parse_comment)

        c = text.next()

        if c in "":
            break
        elif c == ",":
            text.offset -= 1
            break
        elif c in ("'", '"'):
            raise ParseError(
                f"Unexpected quotation mark in {text.text!r} at offset {text.offset - 1}"
            )
        else:
            arg = f"{arg}{c}"

    return Arg(arg.rstrip())


def parse_syscall_args(args: str | ParsingContext) -> Iterator[Arg]:
    if isinstance(args, str):
        args = ParsingContext(args)

    first = True

    while args:
        args.lstrip()
        if first:
            first = False
        elif args:
            args.expect(",")
            args.lstrip()
        ret = args.try_production(parse_syscall_arg)
        if ret is None:
            break
        yield ret
    args.expect()


strace_pattern = re.compile(
    r"\s*(\d*\s+)?(?P<syscall>.+)\((?P<args>[^)]+)\)\s*=\s*(?P<retval>-?\d+).*",
    flags=re.MULTILINE,
)
strace_ignore_pattern = re.compile(
    r".*?(\+\+\+\s*exited with \d+\s*\+\+\+|---\s*SIGCHLD).*", flags=re.MULTILINE
)
strace_resumed_pattern = re.compile(
    r".*?<\s*...\s*(?P<syscall>\S+)\s+resumed>(?P<remainder>.*)$", flags=re.MULTILINE
)


def parse_strace_log_line(line: str) -> tuple[str | None, Iterator[Arg], int]:
    line = line.replace("<unfinished ...>", ")")

    m = strace_resumed_pattern.match(line)
    if m:
        line = f"{m.group('syscall')}({m.group('remainder')}"

    m = strace_pattern.match(line)
    if m:
        return (
            m.group("syscall"),
            parse_syscall_args(m.group("args")),
            int(m.group("retval")),
        )
    elif not strace_ignore_pattern.match(line):
        raise ParseError(f"Could not parse strace output: {line!r}")
    else:
        return None, iter(()), 1


def lazy_parse_paths(line: str) -> Iterator[str]:
    text = ParsingContext(line)
    while text:
        result = text.try_production(parse_quoted_string)
        if result:
            yield result.value
        else:
            text.offset += 1
