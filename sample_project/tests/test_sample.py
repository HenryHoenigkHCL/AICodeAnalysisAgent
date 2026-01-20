"""Tests for sample module."""
import pytest
from src.sample_module import parse_config, calculate_total, hardcoded_credentials


def test_parse_config_valid():
    """Test parsing valid config."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("name=test\nvalue=123")
        f.flush()
        
        result = parse_config(f.name)
        assert result['name'] == 'test'
        assert result['value'] == '123'


def test_calculate_total():
    """Test total calculation."""
    items = [
        {'quantity': 2, 'price': 10.0},
        {'quantity': 3, 'price': 5.0},
    ]
    result = calculate_total(items)
    assert result == 35.0


def test_calculate_total_empty():
    """Test with empty items."""
    result = calculate_total([])
    assert result == 0


def test_hardcoded_credentials():
    """Test credentials function."""
    api_key, password = hardcoded_credentials()
    assert api_key == "sk_live_abcdef123456789"
    assert password == "admin123"


# Missing test: parse_config_invalid (null dereference case)
# Missing test: calculate_total with missing fields
# Missing test: unsafe_eval_config
