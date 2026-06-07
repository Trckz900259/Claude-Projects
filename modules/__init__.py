"""
modules — pluggable vulnerability modules.

Every module implements the common Module interface in modules/base.py, consumes
the shared inventory, and writes findings to the shared datastore. The first
module is modules/xss. Adding a new vuln class = adding a new module here.
"""
