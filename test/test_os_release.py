from deptective.package_manager import parse_os_release_line


def test_quoted_values_keep_full_value():
    assert parse_os_release_line('ID="ubuntu"') == ("id", "ubuntu")
    assert parse_os_release_line('VERSION_ID="22.04"') == ("version_id", "22.04")
    assert parse_os_release_line('PRETTY_NAME="Ubuntu 22.04.3 LTS"') == (
        "pretty_name",
        "Ubuntu 22.04.3 LTS",
    )


def test_single_and_unquoted_values():
    assert parse_os_release_line("VERSION_ID='22.04'") == ("version_id", "22.04")
    assert parse_os_release_line("VERSION_CODENAME=jammy") == ("version_codename", "jammy")


def test_non_assignment_returns_none():
    assert parse_os_release_line("# a comment") is None
    assert parse_os_release_line("") is None
