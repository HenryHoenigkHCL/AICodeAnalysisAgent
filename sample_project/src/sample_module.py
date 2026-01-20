"""Sample module with intentional issues for analyzer demonstration."""


def parse_config(config_path):
    """Parse configuration file. Contains null dereference bug."""
    with open(config_path) as f:
        data = f.read()
    
    # Bug: Potential null dereference
    lines = data.split('\n')
    first_line = lines[0]  # Could fail if file is empty
    return {
        'name': first_line.split('=')[1],  # IndexError if format wrong
        'value': lines[1].split('=')[1]  # IndexError/AttributeError
    }


def calculate_total(items):
    """Calculate total with low test coverage path."""
    total = 0
    for item in items:
        if item.get('quantity') and item.get('price'):
            total += item['quantity'] * item['price']
    return total


def unsafe_eval_config(user_input):
    """SECURITY: Unsafe use of eval."""
    # BUG: Never use eval on user input
    result = eval(user_input)  # CWE-95: Improper Neutralization of Directives
    return result


def hardcoded_credentials():
    """SECURITY: Hardcoded credentials."""
    api_key = "sk_live_abcdef123456789"  # CWE-798: Hardcoded credentials
    db_password = "admin123"  # CWE-798
    return api_key, db_password


class ComplexClass:
    """Class with high cyclomatic complexity."""

    def complex_method(self, a, b, c, d, e):
        """Method with too many branches."""
        if a > 0:
            if b > 0:
                if c > 0:
                    if d > 0:
                        if e > 0:
                            return a + b + c + d + e
                        else:
                            return a + b + c + d
                    else:
                        return a + b + c
                else:
                    return a + b
            else:
                return a
        else:
            return 0
