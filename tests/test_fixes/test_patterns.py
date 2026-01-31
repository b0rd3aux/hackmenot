"""Tests for pattern parser."""

import pytest

from hackmenot.fixes.patterns import PatternParser, PLACEHOLDERS


class TestPatternParser:
    """Tests for PatternParser."""

    @pytest.fixture
    def parser(self):
        return PatternParser()

    def test_simple_var_placeholder(self, parser):
        """Test {var} placeholder matches variable names."""
        parsed = parser.parse("{var} = 123")
        assert parsed.regex.search("foo = 123")
        assert parsed.regex.search("myVar = 123")
        # Note: \w+ matches digits too, so "123 = 123" would match
        assert not parsed.regex.search("!@# = 123")  # Non-word chars should not match

    def test_func_placeholder(self, parser):
        """Test {func} matches function/method names."""
        parsed = parser.parse("{func}()")
        assert parsed.regex.search("doSomething()")
        assert parsed.regex.search("obj.method()")
        assert parsed.regex.search("a.b.c()")

    def test_arg_placeholder(self, parser):
        """Test {arg} matches function arguments."""
        parsed = parser.parse("print({arg})")
        match = parsed.regex.search('print("hello")')
        assert match
        assert match.group(1) == '"hello"'

    def test_string_placeholder(self, parser):
        """Test {string} matches string literals."""
        parsed = parser.parse("x = {string}")
        assert parsed.regex.search('x = "hello"')
        assert parsed.regex.search("x = 'world'")

    def test_multiple_placeholders(self, parser):
        """Test multiple placeholders in one pattern."""
        parsed = parser.parse("{func}({arg}, {arg})")
        assert len(parsed.placeholders) == 3
        assert parsed.regex.search("call(1, 2)")

    def test_literal_text_escaped(self, parser):
        """Test that special regex chars are escaped."""
        parsed = parser.parse("a.b({arg})")
        assert parsed.regex.search("a.b(x)")
        assert not parsed.regex.search("aXb(x)")  # . should be literal

    def test_apply_replacement_simple(self, parser):
        """Test basic replacement."""
        parsed = parser.parse("md5({arg})")
        result = parser.apply_replacement(
            "hash = md5(data)",
            parsed,
            "sha256({arg})"
        )
        assert result == "hash = sha256(data)"

    def test_apply_replacement_multiple_groups(self, parser):
        """Test replacement with multiple captured groups."""
        parsed = parser.parse("{func}({arg})")
        result = parser.apply_replacement(
            "x = foo(bar)",
            parsed,
            "{func}_safe({arg})"
        )
        assert result == "x = foo_safe(bar)"

    def test_apply_replacement_no_match(self, parser):
        """Test that None is returned when pattern doesn't match."""
        parsed = parser.parse("md5({arg})")
        result = parser.apply_replacement("sha256(data)", parsed, "sha512({arg})")
        assert result is None

    def test_complex_sql_pattern(self, parser):
        """Test complex SQL injection fix pattern."""
        parsed = parser.parse('db.Query({string} + {var})')
        result = parser.apply_replacement(
            'db.Query("SELECT * FROM users WHERE id = " + userId)',
            parsed,
            'db.Query({string}, {var})'
        )
        assert "userId" in result
        assert "+ userId" not in result

    def test_terraform_pattern(self, parser):
        """Test Terraform ACL fix pattern."""
        parsed = parser.parse('acl = "public-read"')
        result = parser.apply_replacement(
            '  acl = "public-read"',
            parsed,
            'acl = "private"'
        )
        assert result == '  acl = "private"'
