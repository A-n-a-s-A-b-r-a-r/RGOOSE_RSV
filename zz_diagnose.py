import sys

def diagnose(is_good, action):
    if is_good:
        print(f"{action} OK")
    else:
        print(f"{action} error", file=sys.stderr)
        sys.exit(1)
