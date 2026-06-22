"""EPSS (Exploit Prediction Scoring System) client.

Fetches EPSS probabilities/percentiles for CVE IDs over the FIRST.org API with
``httpx`` + ``tenacity`` retries and ``diskcache`` caching. Missing data leaves
the EPSS fields unknown -- scores are never invented.

Implemented in a later phase.
"""
