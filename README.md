
# le-godaddy-dns

[![Build Status](https://travis-ci.org/josteink/le-godaddy-dns.svg?branch=master)](https://travis-ci.org/josteink/le-godaddy-dns)

le-godaddy-dns is a [Let's encrypt](https://letsencrypt.org/) module,
designed to be used as a hook with
[dehydrated](https://github.com/lukas2511/dehydrated) for
[DNS-based validation](https://github.com/lukas2511/dehydrated/blob/master/docs/dns-verification.md)
against Godaddy DNS.

## Prerequisites

To use this module you will need the following:

* curl
* python3
* godaddypy & tld python3 module
* [Production Godaddy API keys](https://developer.godaddy.com/keys/)
* OpenSSL (or basically whatever `dehydrated` depends on)

## Usage

**Before anything else: Back up your zone-file.**

You are letting a program meddle with your DNS. Bugs happen. Shit
happens. Be prepared.

First you need to download all dependencies and configure `letsencrypt.sh`.

````bash
# get dependencies
sudo apt-get install python3 python3-pip curl

# setup a workplace
ROOTDIR=$HOME/letsencrypt
mkdir -p $ROOTDIR
cd $ROOTDIR

# get letsencrypt.sh
git clone https://github.com/lukas2511/dehydrated
# get le-godaddy-dns
git clone https://github.com/josteink/le-godaddy-dns
cd $ROOTDIR/le-godaddy-dns
python3 -m pip install -r requirements.txt --user

# configure dehydrated
cd $ROOTDIR/dehydrated
nano domains.txt

# the format for domains.txt is documented in letsencrypt.sh's repo.
# https://github.com/lukas2511/dehydrated/blob/master/docs/domains_txt.md
cat domains.txt
mydomain.com sub.mydomain.com
example.com
...
````

### HOOK_CHAIN

This step is required for wildcard certificates and is otherwise recommended 
to reduced runtime if you have many domains (SAN Cert.). Dehydrated gives you
the option to process multiple domains in wall call to the hook script, saving 
resource overhead and pauses for dns propagation with each call.

````bash
# open your config file for dehydrated
# Note: you can also edit the configuration elsewere if you want
# https://github.com/lukas2511/dehydrated/#config
nano $ROOTDIR/dehydrated/config

# Locate the line #HOOK_CHAIN="no"
# Uncomment the line and change the value to yes
HOOK_CHAIN="yes"
````

Now you need to configure `le-godaddy-dns` and retrieve your certs.

````bash
# configure your API keys
export GD_KEY=your_key_here
export GD_SECRET=your_secret_here

# run letsencrypt.sh in "cron" mode (-c)
# this creates CSRs, keys and everything we need automatically for us.
./dehydrated --challenge dns-01 -k $ROOTDIR/le-godaddy-dns/godaddy.py -c

````

You should now have your certs, and the output should tell you where
they are.

You can put the last section in a script and add as a cronjob to
ensure your certificates gets auto-renewed.

You can optionally inspect that they look like they should

````bash
find . -name fullchain.pem -exec openssl x509 -in '{}' -text -noout \;
find . -name fullchain.pem -exec openssl x509 -in '{}' -subject -noout \;
````

You may also decide to customize the `deploy_certificates` hook in
`goddady.py` if you want the certificates automatically copied
to another destination than the one provided by `letsencrypt.sh`.

# Disclaimer

This module is not affiliated with nor endorsed by Godaddy. The
Godaddy API python-modules are not affiliated with nor endorsed by
Godaddy.

This module is not affiliated with nor endorsed by Let's Encrypt.

This module is provided as is and comes with absolutely NO warranties
and I take absolutely NO responsibility should an error resulting from
using this script wipe out your DNS and get your Godaddy account
terminated.

Bugs in dependant Python-modules have resulted in data-loss for the
author, and while the currently published code only uses code proven
to be safe at time of writing, I can make no guarantees about how
things may or may not work in the future.

Testing the module on a test-domain where you can afford downtime is
definitely recommended.

That said, it all works for me.
