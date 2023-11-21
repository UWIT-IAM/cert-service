"""Autorenew the domain control validation for our domains.

This script will automatically renew the domain control validation with Sectigo
for any domains expiring in the next 30 days.

Secrets: This relies on the following secrets, which should be in a .env file in the working dir:

- SECTIGO_USERNAME: The username to use when logging into cert-manager
- SECTIGO_PASSWORD: The password to use when logging into cert-manager
- UW_DNS_CERT: The path to the certificate for the DNS API.
- UW_DNS_KEY: The path to the private key for the DNS API.
"""

from datetime import datetime, timedelta
from time import sleep
import logging
import os
from dotenv import load_dotenv
from requests.exceptions import HTTPError
from cert_manager import Client
from cert_manager import Organization

from .dcv import DomainControlValidation
from .validators import enabled_validators, DnsValidator

logger = logging.getLogger("main")

# The list of CNAME records that should be cleaned up after the verification succeeded.
RECORD_CLEANUP_FILE = "data/records_to_delete.txt"


def main():
    """Automatically renews domain control validation for any domains we own."""
    client = Client(
        base_url="https://cert-manager.com/api",
        login_uri="InCommon",
        username=os.getenv("SECTIGO_USERNAME"),
        password=os.getenv("SECTIGO_PASSWORD"),
    )

    logger.debug("Getting the list of expired domains")
    expiring_dcvs = get_expiring_domains(client)
    logger.debug("Got expiring domains: %s", expiring_dcvs)

    validators = enabled_validators(
        cert=[os.getenv("UW_DNS_CERT"), os.getenv("UW_DNS_KEY")]
    )
    clean_up_cnames(validators, expiring_dcvs)

    # Start the validation process for each domain
    renew_validations(client, validators, expiring_dcvs)


def clean_up_cnames(validators, expiring_dcvs: dict):
    """Delete all the CNAMEs that are no longer needed for domain verification."""
    domain_to_dcv = {x["domain"]: x for x in expiring_dcvs}

    to_write = []
    with open(RECORD_CLEANUP_FILE, "r", encoding="UTF-8") as f:
        for line in f:
            domain, host, point = line.strip().split(" ")
            if domain not in domain_to_dcv:
                # If it's not expiring, delete it
                logger.info("Validation succeeded for %s, removing CNAME", domain)
                for validator in validators:
                    if validator.is_owned(domain):
                        validator.delete_cname(host, point)
            else:
                # It's still expiring, don't delete it yet
                to_write.append(line)

    with open(RECORD_CLEANUP_FILE, "w", encoding="UTF-8") as f:
        for line in to_write:
            f.write(line)


def is_expiring_in(dcv_status: dict, days=30):
    """Returns true if the given domain validation is expiring in <30 days"""
    expiry_date_str = dcv_status["expirationDate"]
    expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d")
    return expiry_date < datetime.now() + timedelta(days=days)


def get_expiring_domains(client: Client, days_to_expiry=30, batch_size=100):
    """Get the list of domains that are expiring in `days_to_expire` days.

    Args:
        client (Client): The cert-manager client to use
        days_to_expiry (int): The number of days before a domain expires to renew it
        batch_size (int): The number of domains to fetch at once from cert-manager
    """
    org_client = Organization(client=client)
    dcv_client = DomainControlValidation(client=client)

    # Get our organization ID
    our_org = org_client.find(dept_name="UW-IT")
    assert len(our_org) == 1
    our_org = our_org[0]

    # Get the domains that are expiring in the next 30 days
    expiring_dcvs = []
    position = 0
    while True:
        results = dcv_client.search(
            position=position,
            size=batch_size,
            expiresIn=days_to_expiry,
            department=our_org["id"],
        )
        expiring_dcvs.extend(results)
        if len(results) < batch_size:
            break
        position += len(results)

    # Filter out wildcard domains, because we don't need to verify those
    expiring_dcvs = [d for d in expiring_dcvs if not d["domain"].startswith("*")]

    return expiring_dcvs


def renew_validations(
    client: Client, dns_validators: list[DnsValidator], domains: list[dict]
):
    """Attempt to renew the validation for a single domain.

    Args:
        client (Client): The cert-manager client to use
        dns_validators (list[DnsValidator]): The list of DNS validators to use
        domains (list[dict]): The list of domains to renew
    """
    dcv_client = DomainControlValidation(client=client)

    # Get the validators for each domain
    validators = {}
    cnames_to_add = {}
    for domain in domains:
        domain = domain["domain"]
        validators[domain] = get_validator_for_domain(domain, dns_validators)
        if validators[domain]:
            # Start validation with Sectigo
            logger.debug("Starting validation at Sectigo for %s", domain)
            cnames_to_add[domain] = dcv_client.start_validation_cname(domain=domain)
            logger.debug("Result %s", cnames_to_add[domain])

    # Set the CNAMES for each domain
    added_cnames = {}
    for domain, validator in validators.items():
        if domain in cnames_to_add:
            added_cnames[domain] = add_cname(validator, cnames_to_add[domain])

    logger.debug("Waiting for DNS to propagate")
    sleep(10)

    # Submit the validation requests to Sectigo
    for domain, cname in added_cnames.items():
        logger.info("Submitting validation at Sectigo for %s", domain)
        result = dcv_client.submit_validation_cname(domain=domain)
        logger.debug("Result %s", result)

        # Add the CNAME to the list of records to delete when the process is complete
        with open(RECORD_CLEANUP_FILE, "a", encoding="UTF-8") as f:
            f.write(f"{domain} {cname['host']} {cname['point']}\n")


def get_validator_for_domain(domain: str, validators: list[DnsValidator]):
    """Return the validator that can handle the given domain.

    Args:
        domain (str): The domain to validate
        validators (list[DnsValidator]): The list of validators to check
    """
    for validator in validators:
        if validator.is_owned(domain):
            return validator
    return None


def add_cname(validator: DnsValidator, cname_to_add: dict):
    """Add the given cname to the DNS, ignoring errors."""
    try:
        # Add the validation CNAME to the DNS and wait for it to propagate
        validator.add_cname(cname_to_add["host"], cname_to_add["point"])
        return cname_to_add
    except (HTTPError, ConnectionError) as e:
        # We can ignore and log any errors because this script is idempotent.
        logging.warning(e)
        return None


if __name__ == "__main__":
    # Configure logging here
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("main").setLevel(logging.INFO)
    logging.getLogger("validators").setLevel(logging.INFO)

    load_dotenv()
    main()
