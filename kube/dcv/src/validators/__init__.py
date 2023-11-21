"""Validators that add a CNAME to the domain's DNS to validate it.

To add support for DCV with domains on a different DNS server, simply create a
new file, implement DnsValidator, and it add it to the `enabled_validators` list."""

from .uw_dns import UwDnsValidator
from .validator import DnsValidator

def enabled_validators(cert):
    """Return the list of enabled validators."""
    return [UwDnsValidator(cert)]
