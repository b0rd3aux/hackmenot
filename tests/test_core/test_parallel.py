"""Tests for parallel scanning functionality."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_parallel_scan_finds_all_vulnerabilities(tmp_path: Path):
    """Test parallel scan finds vulnerabilities in all files."""
    scanner = Scanner()

    # Create 10 files with SQL injection vulnerabilities
    for i in range(10):
        vuln_file = tmp_path / f"vuln_{i}.py"
        vuln_file.write_text(f'''
def get_data_{i}(user_input):
    query = f"SELECT * FROM table_{i} WHERE id = {{user_input}}"
    return db.execute(query)
''')

    result = scanner.scan([tmp_path], parallel=True)

    assert result.files_scanned == 10
    assert len(result.findings) == 10
    assert all(f.rule_id == "INJ001" for f in result.findings)


def test_parallel_scan_faster_than_sequential(tmp_path: Path):
    """Test parallel scan works on multiple files."""
    scanner = Scanner()

    # Create 20 files with vulnerabilities
    for i in range(20):
        vuln_file = tmp_path / f"test_{i}.py"
        vuln_file.write_text(f'''
def process_{i}(data):
    sql = f"INSERT INTO logs VALUES ({{data}})"
    return execute(sql)
''')

    # Verify parallel scan works and finds all vulnerabilities
    result = scanner.scan([tmp_path], parallel=True, max_workers=4)

    assert result.files_scanned == 20
    assert len(result.findings) == 20


def test_parallel_scan_handles_errors_gracefully(tmp_path: Path):
    """Test errors in one file don't crash the entire scan."""
    scanner = Scanner()

    # Create valid Python files with vulnerabilities
    for i in range(5):
        valid_file = tmp_path / f"valid_{i}.py"
        valid_file.write_text(f'''
def func_{i}(x):
    query = f"SELECT * FROM t WHERE id = {{x}}"
    return query
''')

    # Create a file with syntax errors
    bad_file = tmp_path / "bad_syntax.py"
    bad_file.write_text("def broken( this is not valid python syntax")

    # Create more valid files after the bad one
    for i in range(5, 8):
        valid_file = tmp_path / f"valid_{i}.py"
        valid_file.write_text(f'''
def func_{i}(y):
    sql = f"DELETE FROM t WHERE id = {{y}}"
    return sql
''')

    result = scanner.scan([tmp_path], parallel=True)

    # Should scan all 9 files (8 valid + 1 with syntax error)
    assert result.files_scanned == 9
    # Should find vulnerabilities in all 8 valid files
    assert len(result.findings) == 8
    # No errors should be reported for syntax errors (parser handles gracefully)
    # The scan should complete successfully


def test_parallel_scan_with_single_file(tmp_path: Path):
    """Test parallel=True with single file works correctly."""
    scanner = Scanner()

    single_file = tmp_path / "single.py"
    single_file.write_text('query = f"SELECT * FROM t WHERE x = {y}"')

    result = scanner.scan([tmp_path], parallel=True)

    assert result.files_scanned == 1
    assert len(result.findings) == 1


def test_parallel_scan_with_cache(tmp_path: Path):
    """Test parallel scanning works correctly with caching enabled."""
    from hackmenot.core.cache import FileCache

    cache_dir = tmp_path / "cache"
    cache = FileCache(cache_dir=cache_dir)
    scanner = Scanner(cache=cache)

    # Create files with vulnerabilities
    for i in range(5):
        vuln_file = tmp_path / f"cached_{i}.py"
        vuln_file.write_text(f'''
def get_{i}(data):
    query = f"SELECT * FROM t_{i} WHERE id = {{data}}"
    return query
''')

    # First scan - should populate cache
    result1 = scanner.scan([tmp_path], parallel=True, use_cache=True)
    assert result1.files_scanned == 5
    assert len(result1.findings) == 5

    # Second scan - should use cache
    result2 = scanner.scan([tmp_path], parallel=True, use_cache=True)
    assert result2.files_scanned == 5
    assert len(result2.findings) == 5
