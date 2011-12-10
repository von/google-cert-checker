#!/usr/bin/env python
"""Check the Google certificate catalog for a certificate.

See: http://googleonlinesecurity.blogspot.com/2011/04/improving-ssl-certificate-security.html

Requires dnspython: http://www.dnspython.org/: pip install dnspython
"""

import argparse
import binascii
from dns import resolver
import hashlib
import logging
import ssl
import sys
import time

def parse_args(argv):
    """Parse commandline arguments"""
    defaults = {
        "output_level" : logging.INFO,
        }
    parser = argparse.ArgumentParser(
        # print script description with -h/--help
        description=__doc__,
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    parser.set_defaults(**defaults)
    # Only allow one of debug/quiet mode
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-d", "--debug",
                                 action='store_const', const=logging.DEBUG,
                                 dest="output_level", 
                                 help="print debugging")
    verbosity_group.add_argument("-q", "--quiet",
                                 action="store_const", const=logging.WARNING,
                                 dest="output_level",
                                 help="run quietly")
    cert_group = parser.add_mutually_exclusive_group()
    cert_group.add_argument("-s", "--server",
                            help="Get certificate from server",
                            metavar="SERVER:PORT")
    cert_group.add_argument("-c", "--cert_file",
                            help="Read PEM-encoded certificate from file",
                            metavar="FILE")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    args = parser.parse_args(argv[1:])
    if not args.server and not args.cert_file:
        parser.error("Certificate argument (-s|-c) required.")
    return args

def day_to_seconds(day):
    """Given a day since 1970, return number of seconds"""
    return day * 24 * 3600

def cert_PEM_to_hash(cert):
    """Given a certificate in PEM format, return it's hash as string"""
    cert_der = ssl.PEM_cert_to_DER_cert(cert)
    hash = hashlib.sha1()
    hash.update(cert_der)
    digest = hash.digest()
    digest_string = "".join([binascii.b2a_hex(b) for b in bytes(digest)])
    return digest_string

def main(argv=None):
    # Do argv default this way, as doing it in the functional
    # declaration sets it at compile time.
    if argv is None:
        argv = sys.argv

    # Set up out output via logging module
    output = logging.getLogger(argv[0])
    output.setLevel(logging.DEBUG)
    output_handler = logging.StreamHandler(sys.stdout)  # Default is sys.stderr
    # Set up formatter to just print message without preamble
    output_handler.setFormatter(logging.Formatter("%(message)s"))
    output.addHandler(output_handler)

    args = parse_args(argv)

    output_handler.setLevel(args.output_level)

    if args.server:
        hostname, port = args.server.split(":")
        output.info("Getting certificate for {}:{}".format(hostname, port))
        cert = ssl.get_server_certificate((hostname, int(port)))
        output.debug("Got certificate, hashing...")
        digest_string = cert_PEM_to_hash(cert)
        output.debug("Hash is {}".format(digest_string))
    elif args.cert_file:
        with open(args.cert_file) as f:
            lines = f.readlines()
        digest_string = cert_PEM_to_hash("".join(lines))
        output.debug("Hash is {}".format(digest_string))
    else:
        output.error("Certificate argument required.")
        return(1)
    
    query_host = "{}.certs.googlednstest.com".format(digest_string)
    output.debug("Query is for {}".format(query_host))
    try:
        answer = resolver.query(query_host, "TXT")
    except resolver.NXDOMAIN as e:
        output.info("No information found.")
        return(1)
    for rdata in answer:
        output.debug("Raw response is {}".format(rdata))
        # Convert to string and remove quotes
        rdata_str = str(rdata).strip("\"")  
        start_day_str, end_day_str, days_seen_str = rdata_str.split()
        break
    start_day = int(start_day_str)
    end_day = int(end_day_str)
    days_seen = int(days_seen_str)
    start_secs = day_to_seconds(start_day)
    end_secs = day_to_seconds(end_day)
    fmt = "%d %B %Y"
    output.info("Start date: " + time.strftime(fmt, time.localtime(start_secs)))
    output.info("End date: " + time.strftime(fmt,  time.localtime(end_secs)))
    output.info("Days seen: {}/{}".format(days_seen, end_day - start_day))
    return(0)

if __name__ == "__main__":
    sys.exit(main())

