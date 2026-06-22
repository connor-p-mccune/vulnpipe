"""NVD (National Vulnerability Database) client.

Looks up CVE metadata over the NVD API with ``httpx`` + ``tenacity`` retries,
caching responses with ``diskcache``. The API key resolves from ``NVD_API_KEY``
at runtime. Enrichment failures mark fields unknown rather than guessing.

Implemented in a later phase.
"""
