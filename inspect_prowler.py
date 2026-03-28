"""
inspect_prowler.py — find exact class names and module paths for
AWS_Audit_Info, AWS_Credentials, and AWS_Assumed_Role_Info in the
installed Prowler version.
"""
import importlib
import inspect
import pkgutil

KEYWORDS = ("audit", "credentials", "assumed", "credential", "role")

def scan_module(module_path):
    try:
        mod = importlib.import_module(module_path)
    except ImportError as e:
        print(f"  [SKIP] {module_path} — {e}")
        return

    members = inspect.getmembers(mod, inspect.isclass)
    hits = [
        (name, cls)
        for name, cls in members
        if any(kw in name.lower() for kw in KEYWORDS)
    ]
    if hits:
        print(f"\n  [{module_path}]")
        for name, cls in hits:
            print(f"    {name}  (defined in: {cls.__module__})")
    else:
        print(f"\n  [{module_path}] — no matching classes")


PATHS_TO_CHECK = [
    "prowler.providers.aws.lib.audit_info.models",
    "prowler.providers.aws.lib.audit_info.audit_info",
    "prowler.providers.aws.models",
    "prowler.providers.common.models",
    "prowler.providers.aws.lib.audit_info",
]

print("=" * 60)
print("Prowler model class scanner")
print("=" * 60)

import prowler
try:
    from importlib.metadata import version
    print(f"Prowler version : {version('prowler')}")
except Exception:
    print(f"Prowler location: {prowler.__file__}")

import sys
print(f"Python          : {sys.version}")
print()
print("Searching known module paths...")

for path in PATHS_TO_CHECK:
    scan_module(path)

# Deep scan: walk every sub-module of prowler.providers.aws.lib.audit_info
print()
print("=" * 60)
print("Deep walk of prowler.providers.aws.lib.audit_info.*")
print("=" * 60)
try:
    import prowler.providers.aws.lib.audit_info as _pkg
    pkg_path = _pkg.__path__
    for finder, name, ispkg in pkgutil.walk_packages(pkg_path, prefix="prowler.providers.aws.lib.audit_info."):
        scan_module(name)
except Exception as e:
    print(f"  Walk failed: {e}")

input("\nDone. Press Enter to close...")
