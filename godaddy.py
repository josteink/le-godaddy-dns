#!/usr/bin/env python3

import os
import sys
import logging
from tld import get_tld
import time
import godaddypy

# Override this to False, if you are not using wildcards and
# do not want to have new records added in DNS
LE_WILDCARDS_SUPPORT = True

if "GD_KEY" not in os.environ:
    raise Exception("Missing Godaddy API-key in GD_KEY environment variable! Please register one at https://developer.godaddy.com/keys/")

if "GD_SECRET" not in os.environ:
    raise Exception("Missing Godaddy API-secret in GD_SECRET environment variable! Please register one at https://developer.godaddy.com/keys/")

my_acct = godaddypy.Account(
    api_key=os.environ["GD_KEY"], 
    api_secret=os.environ["GD_SECRET"]
)

client = godaddypy.Client(my_acct)

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def _get_zone(domain):
    d = get_tld(domain,as_object=True,fix_protocol=True)
    return d.tld

def _get_subdomain_for(domain, zone):
    subdomain = domain[0:(-len(zone)-1)]
    return subdomain

def _add_dns_rec(domain, token, tries=0):
    challengedomain = "_acme-challenge." + domain
    logger.info(" + Adding TXT record for {0} to '{1}'.".format(challengedomain, token))
    zone = _get_zone(challengedomain)
    # logger.info("Zone to update: {0}".format(zone))
    subdomain = _get_subdomain_for(challengedomain, zone)
    # logger.info("Subdomain name: {0}".format(subdomain))

    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }
    result=None
    try:
        result = client.add_record(zone, record)
    except godaddypy.client.BadResponse as err:
        msg=str(err)
        if msg.find('DUPLICATE_RECORD') > -1:
            logger.info(" + . Duplicate record found. Skipping.")
            return
        logger.warn("Error returned {0}.".format(err))
    except Exception as err:
        logger.warn("Error returned {0}.".format(err))

    if result is not True:
        logger.warn("Error updating recLE_WILDCARDS_SUPPORTord for domain {0}.".format(domain))
        if tries < 3:
            logger.warn("Will retry in 5 seconds...")
            time.sleep(5)
            _get_subdomain_for(domain, token, tries+1)
        else:
            logger.warn("Giving up after 3 tries...")
    else:
        logger.info(" + . Record added")

def _update_dns(domain, token):
    challengedomain = "_acme-challenge." + domain
    logger.info(" + Updating TXT record for {0} to '{1}'.".format(challengedomain, token))
    zone = _get_zone(challengedomain)
    # logger.info("Zone to update: {0}".format(zone))
    subdomain = _get_subdomain_for(challengedomain, zone)
    # logger.info("Subdomain name: {0}".format(subdomain))

    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }

    existing_records = client.get_records(zone, record_type="TXT", name=subdomain)
    if (len(existing_records) == 0):
        result = client.add_record(zone, record)
    else:
        result = client.update_record(zone, record)

    if result is not True:
        logger.warn("Error updating record for domain {0}.".format(domain))


def create_txt_record(args):
    global LE_WILDCARDS_SUPPORT
    for i in range(0, len(args), 3):
        domain, token = args[i], args[i+2]
        if LE_WILDCARDS_SUPPORT:
            _add_dns_rec(domain, token)
        else:
            _update_dns(domain, token)
        # Sleep between calls to avoid godaddy rate limits
        # Acccording to their docs its 60 calls per minute
        time.sleep(1)
    # a sleep is needed to allow DNS propagation
    logger.info(" + Sleeping to wait for DNS propagation")
    time.sleep(30)


def delete_txt_record(args):
    for i in range(0, len(args), 3):
        domain = args[i]
        # using client.delete_record() is dangerous. null it instead!
        # https://github.com/eXamadeus/godaddypy/issues/13

        if domain == "":
            logger.warn("Error deleting record, the domain argument is empty")
        else:
            _update_dns(domain, "(le_godaddy_dns) please delete me")


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def invalid_challenge(args):
    [domain, response] = args
    logger.warn(" + invalid challenge for domain {0}: {1}".format(domain, response))
    return


def request_failure(args):
    [status_code, err_txt, req_type] = args
    logger.warn(" + Request failed with status code: {0}, {1}, type: {2}".format(status_code, err_txt, req_type))
    return


def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
        'invalid_challenge': invalid_challenge,
        'request_failure' : request_failure
    }

    opname = argv[0]
    if opname not in ops:
        return
    else:
        logger.info(" + Godaddy hook executing: {0}".format(opname))
        ops[opname](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
