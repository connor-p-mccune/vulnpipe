"""Pure finding transforms: normalize, dedup, false-positive filter, prioritize.

Every function here is pure (findings in -> findings out) so it is trivially
testable. Side effects (running tools, HTTP, writing files) live elsewhere.
"""
