"""Base class for Validators. These are wrappers around DNS APIs."""

class DnsValidator:
    """Base class for Validators. These are wrappers around DNS APIs.

    Implementations add a CNAME to a domain's DNS to validate it."""

    def is_owned(self, domain: str):
        """Return True if given DNS thinks it is managing this zone."""
        raise NotImplementedError

    def add_cname(self, host: str, point: str):
        """Add a cname on the given `host` that points to `point`."""
        raise NotImplementedError

    def delete_cname(self, host: str, point: str):
        """Removes the given cname at `host`."""
        raise NotImplementedError
