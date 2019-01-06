#!/usr/bin/env python3

import os
import sys
import logging
from tld import get_tld
import time
import godaddypy

if "GD_KEY" not in os.environ:
    raise Exception("Missing Godaddy API-key in GD_KEY environment variable! Please register one at https://developer.godaddy.com/keys/")

if "GD_SECRET" not in os.environ:
    raise Exception("Missing Godaddy API-secret in GD_SECRET environment variable! Please register one at https://developer.godaddy.com/keys/")

api_key = os.environ["GD_KEY"]
api_secret = os.environ["GD_SECRET"]
my_acct = godaddypy.Account(api_key=api_key, api_secret=api_secret)
client = godaddypy.Client(my_acct)

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

domain_hist = []
HOOK_CHAIN = None


def _get_zone(domain):
    d = get_tld(domain,as_object=True,fix_protocol=True)
    return d.fld


def _get_subdomain(domain, zone):
    subdomain = domain[0:(-len(zone)-1)]
    return subdomain


def _set_token_in_dns(domain, token, do_update=False, tries=0):
    global HOOK_CHAIN, domain_hist

    challengedomain = "_acme-challenge." + domain
    logger.info(" + add -or- update TXT '{}' to '{}'.".format(challengedomain, token))
    zone = _get_zone(challengedomain)
    # logger.info("Zone to update: {}".format(zone))
    subdomain = _get_subdomain(challengedomain, zone)
    # logger.info("Subdomain name: {}".format(subdomain))
    
    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }

    def __should_add():
        if do_update: return False
        if HOOK_CHAIN:
            if domain in domain_hist:
                domain_hist.append(domain)
                return True
            domain_hist.append(domain)
            return False
        return True if len(client.get_records(zone, record_type="TXT", name=subdomain)) == 0 else False

    (verb, gd_api) = ['add', client.add_record] if __should_add() else ['update', client.update_record]

    logger.info(" + {} TXT record for {} | token = '{}' | zone = '{}' | godaddypy rec = '{}'".format(
        verb.capitalize(), challengedomain, token, zone, record))

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
        logger.info(" + . Record {}".format('added' if verb == 'add' else "updated"))        
        # Sleep between calls to avoid godaddy rate limits
        # Acccording to their docs its 60 calls per minute
        time.sleep(1)


def create_txt_record(args):
    global HOOK_CHAIN, domain_hist
    # Note: This is a soft check that will only work for SAN certs. However, a incorrect result for non SAN certs will not cause problems in the logic.
    HOOK_CHAIN = True if len(args) > 3 else False
    logger.info("HOOK_CHAIN = {}".format(HOOK_CHAIN))
    if HOOK_CHAIN == False:
        logger.warn(" + Dehydrated may be running with HOOK_CHAIN disabled. Consider enabling HOOK_CHAIN for wildcard-support and improved performance.")

    for i in range(0, len(args), 3):
        domain, token = args[i], args[i+2]
        _set_token_in_dns(domain, token)
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
