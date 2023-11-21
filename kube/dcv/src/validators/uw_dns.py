"""DNS Validator for the UW DNS."""

import logging
import requests

from .validator import DnsValidator

_DNS_NAME = "UW DNS"
_TIMEOUT_SECS = 60
logger = logging.getLogger("validators.uw_dns")


class UwDnsValidator(DnsValidator):
    """Adds the validation CNAME to a UW DNS managed domain."""

    def __init__(self, cert):
        self.cert = cert

    def is_owned(self, domain: str):
        """Return True if UW DNS thinks it is managing this zone."""
        # TODO: In theory, we could use dig which might be more accurate, but that
        # would require knowing and maintaining a full list of UW DNS servers.

        logger.debug("Checking if %s is owned by %s", domain, _DNS_NAME)

        # Get the UW DNS info for the domain
        url = f"https://api.networks.uw.edu/v1/dns/fqdns/{domain}"
        logger.debug("Calling %s", url)
        response = requests.get(url, cert=self.cert, timeout=_TIMEOUT_SECS).json()
        logger.debug("Response: %s", response)

        # Check if we're an owner
        zone_info = response["zone_info"]
        if zone_info is None:
            return False

        if zone_info["ns_exists"] or zone_info["parent_exists"]:
            return True
        return False

    def add_cname(self, host: str, point: str):
        """Add a cname on the given `host` that points to `point`."""
        logger.debug("Adding a CNAME on %s to %s on %s", host, point, _DNS_NAME)

        # Add the CNAME
        url = f"https://api.networks.uw.edu/v1/dns/fqdns/{host}/records"
        json = {
            "type": "CNAME",
            "value": point,
            "ttl": 3600,
            "views": ["internal", "external"],
        }

        logger.debug("Calling %s with %s", url, json)
        response = requests.post(url, json=json, cert=self.cert, timeout=_TIMEOUT_SECS).json()
        logger.debug("Response: %s", response)

    def delete_cname(self, host: str, point: str):
        """Removes the given cname at `host` from UW DNS."""
        logger.debug("Deleting the CNAME from %s to %s on %s", host, point, _DNS_NAME)

        # Get the list of records
        url = f"https://api.networks.uw.edu/v1/dns/fqdns/{host}/records"

        logger.debug("Calling %s", url)
        response = requests.get(url, cert=self.cert, timeout=_TIMEOUT_SECS).json()
        logger.debug("Response: %s", response)

        for record in response["resource_records"]:
            if record["type"] == "CNAME" and record["value"] == point:
                logger.debug("Deleting record %s -> %s on %s", host, point, _DNS_NAME)

                # Delete the record
                url = f"https://api.networks.uw.edu/v1/dns/fqdns/{host}/records/{record['id']}"
                logger.debug("Calling DELETE %s", url)
                response = requests.delete(url, cert=self.cert, timeout=_TIMEOUT_SECS)
                logger.debug("Response: %s", response)

                break
