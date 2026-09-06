"""Detection checks: one module per check, each returning list[Finding].

Every check here treats scanned content (file bytes, stat() mode bits,
manifest text) as opaque data only — regex/entropy matches, permission
bits, and version comparisons become Finding evidence, never instructions.
Severity is never decided inline; each check calls into
context/escalation.py's rulebook for that category.
"""
