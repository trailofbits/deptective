from unittest import TestCase

from deptective.strace import Arg, ListArg, parse_strace_log_line, parse_syscall_args


class TestStrace(TestCase):
    def test_strace_arg_parser(self):
        for args, expected in (
            (
                'AT_FDCWD, "/etc/ld.so.preload", R_OK',
                ("AT_FDCWD", Arg("/etc/ld.so.preload", quoted=True), "R_OK"),
            ),
            (
                '"/usr/bin/git", ["git", "config", "user.email"], 0xffffcd377c68 / * 8 vars * / ',
                (
                    Arg("/usr/bin/git", quoted=True),
                    ListArg(
                        Arg("git", quoted=True),
                        Arg("config", quoted=True),
                        Arg("user.email", quoted=True),
                    ),
                    Arg("0xffffcd377c68 / * 8 vars * /"),
                ),
            ),
            (
                '"/usr/bin/expr", ["expr", "a", ":", "\\\\(a\\\\)"], 0xaaab113a4980 / * 14 vars * /',
                (
                    Arg("/usr/bin/expr", quoted=True),
                    ListArg(
                        Arg("expr", quoted=True),
                        Arg("a", quoted=True),
                        Arg(":", quoted=True),
                        Arg("\\(a\\)", quoted=True),
                    ),
                    Arg("0xaaab113a4980 / * 14 vars * /"),
                ),
            ),
        ):
            self.assertEqual(expected, tuple(parse_syscall_args(args)))

    def test_exited_line(self):
        syscall, args, retval = parse_strace_log_line("11    +++ exited with 0 +++")
        self.assertIsNone(syscall)
        self.assertEqual((), tuple(args))
        self.assertEqual(1, retval)
