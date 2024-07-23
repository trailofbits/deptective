from unittest import TestCase

from apt_trace.syscalls import Arg, ListArg, parse_syscall_args


class TestSyscallParser(TestCase):
    def test_syscall_arg_parser(self):
        for args, expected in (
                (
                        'AT_FDCWD, "/etc/ld.so.preload", R_OK',
                        ("AT_FDCWD", Arg("/etc/ld.so.preload", quoted=True), "R_OK")
                ),
                (
                        '"/usr/bin/git", ["git", "config", "user.email"], 0xffffcd377c68 / * 8 vars * / ',
                        (Arg("/usr/bin/git", quoted=True), ListArg(
                            Arg("git", quoted=True),
                            Arg("config", quoted=True),
                            Arg("user.email", quoted=True)
                        ), Arg("0xffffcd377c68 / * 8 vars * /"))
                ),
        ):
            self.assertEqual(expected, tuple(parse_syscall_args(args)))
