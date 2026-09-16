"""Haven's hosted web accounts service (Phase 7a).

This is a genuinely different trust model from the desktop app: an
account here is stored server-side (encrypted, but centrally held) so
you can sign in from any browser, and usernames are globally unique
across everyone who signs up — both of which require this server to
exist and be trusted to run its own code honestly. See webapp/README.md
for the full design and the tradeoffs this accepts.
"""
