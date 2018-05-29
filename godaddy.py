#!/usr/bin/env python3

import os
import sys
import logging
from tld import get_tld
import time
import godaddypy

# See readme.md for explanation of this flag
LE_WILDCARD_SUPPORT = True

if "GD_KEY" not in os.environ:
    raise Exception("Missing Godaddy API-key in GD_KEY environment variable! Please register one at https://developer.godaddy.com/keys/")

if "GD_SECRET" not in os.environ:
    raise Exception("Missing Godaddy API-secret in GD_SECRET environment variable! Please register one at https://developer.godaddy.com/keys/")

env=os.environ
my_acct = godaddypy.Account(api_key=env["GD_KEY"], api_secret=env["GD_SECRET"])

client = godaddypy.Client(my_acct)

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


def _get_zone(domain):
    d = get_tld(domain,as_object=True,fix_protocol=True)
    return d.tld


def _get_subdomain(domain, zone):
    subdomain = domain[0:(-len(zone)-1)]
    return subdomain


def _get_txt_records(domain):
    txt_records = client.get_records(zone, record_type="TXT", name=domain)
    return txt_records


def _set_token_in_dns(domain, token, do_update=False, tries=0):
    logger.info("_set_token_in_dns() called. domain={}, token={}, tries={}".format(domain, token, tries))
    global LE_WILDCARD_SUPPORT
    challengedomain = "_acme-challenge." + domain
    zone = _get_zone(challengedomain)
    subdomain = _get_subdomain(challengedomain, zone)

    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }

    verb='add'
    gd_api = client.add_record
    
    if do_update or not LE_WILDCARD_SUPPORT:
        if do_update or len(_get_txt_records(subdomain)) > 0:
            if not do_update and domain.find('*') > -1:
                logger.warn("+ Warning - Wildcard URL dectected, but LE_WILDCARD_SUPPORT is set to False. If valiation fails, please set LE_WILDCARD_SUPPORT to True and run again.")
            verb='update'
            gd_api = client.update_record

    logger.info(" + {} TXT record for {}. token = '{}'.".format(
        verb.capitalize(), challengedomain, token))

    result=None
    try:
        result = gd_api(zone, record)
    except godaddypy.client.BadResponse as err:
        msg=str(err)
        if msg.find('DUPLICATE_RECORD') > -1:
            logger.info(" + . Duplicate record found. Skipping.")
            return
        logger.warn("Error returned during {}: {}.".format(verb, err))
    except Exception as err:
        logger.warn("Error returned during {}: {}.".format(verb, err))

    if result is not True:
        logger.warn("Error {}ing record for domain {}.".format(verb, domain))
        if tries < 3:
            logger.warn("Will retry in 5 seconds...")
            time.sleep(5)
            _set_token_in_dns(domain, token, do_update, tries+1)
        else:
            logger.warn("Giving up after 3 tries {}ing dns...".format(verb))
    else: # Success
        logger.info(" + . Record {}ed".format(verb))        
        # Sleep between calls to avoid godaddy rate limits
        # Acccording to their docs its 60 calls per minute
        time.sleep(1)


# Begin hooks
def create_txt_record(args):
    for i in range(0, len(args), 3):
        domain, token = args[i], args[i+2]
        _set_token_in_dns(domain, token)
    # a sleep is needed to allow DNS propagation
    logger.info(" + Sleeping to wait for DNS propagation")
    time.sleep(30)


def delete_txt_record(args):
    for i in range(0, len(args), 3):
        domain = args[i]
        # using client.delete_record() is dangerous. null it instead!
        # https://github.com/eXamadeus/godaddypy/issues/13

        if domain == "":
            logger.warn("delete_txt_record() error. The domain argument is empty")
        else:
            _set_token_in_dns(domain, "(le_godaddy_dns) please delete me", do_update=True)


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {}'.format(privkey_pem))
    return


def invalid_challenge(args):
    [domain, response] = args
    logger.warn(" + invalid challenge for domain {}: {}".format(domain, response))
    return


def request_failure(args):
    [status_code, err_txt, req_type] = args
    logger.warn(" + Request failed with status code: {}, {}, type: {}".format(status_code, err_txt, req_type))
    return
# End Hooks

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
        logger.info(" + Godaddy hook executing: {}".format(opname))
        ops[opname](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])