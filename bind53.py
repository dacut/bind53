#!/usr/bin/env python
"""
Convert Route53 resource record sets to bind configuration.
"""

# pylint: disable=C0103,C0111,R0204,R0903,R0913,R0914
from __future__ import absolute_import, print_function
from getopt import getopt, GetoptError
from logging import basicConfig, getLogger, DEBUG, WARNING
from sys import argv, exit as sys_exit, stderr, stdout
from time import sleep, time

from boto3.session import Session
from dns.resolver import NXDOMAIN, query as dns_query
from six.moves import cStringIO as StringIO

log = getLogger("bind53")

class DNSRecord(object):
    """
    A record for a DNS name.
    """

    def __init__(self, name, record_type, ttl, values=None):
        super(DNSRecord, self).__init__()
        self.name = name
        self.record_type = record_type
        self.ttl = ttl
        self.values = set(values) if values is not None else set()
        return

    @property
    def bind_config(self):
        """
        Return the BIND configuration for this record.
        """
        result = StringIO()

        for value in self.values:
            result.write("%-63s %7d IN      %-7s " % (
                self.name, self.ttl if self.ttl is not None else 60,
                self.record_type))

            if self.record_type == "SOA":
                parts = value.split()
                ns = parts[0]
                email = parts[1]
                soa_values = parts[2:]
                result.write("%s %s (%s)" % (ns, email, " ".join(soa_values)))
            else:
                result.write(value)

            result.write("\n")

        return result.getvalue()

    def __repr__(self):
        return "DNSRecord(name=%r, record_type=%r, ttl=%r, values=%r)" % (
            self.name, self.record_type, self.ttl, self.values)

class DNSAliasRecord(DNSRecord):
    """
    A Route53 alias record. This allows for ex-post-facto resolution of DNS
    names.
    """
    # Minimum number of seconds to wait for the next resolution
    min_resolution_delay = 6

    def __init__(self, name, ttl, target, pending_resolve_count=5,
                 next_resolution_time=0, values=None):
        super(DNSAliasRecord, self).__init__(name, "A", ttl, values)
        self.target = target
        self.next_resolution_time = next_resolution_time
        self.pending_resolve_count = pending_resolve_count
        return

    def resolve(self):
        """
        Attempt to resolve this name once.
        """
        ttl = self.min_resolution_delay

        try:
            result = dns_query(self.target, tcp=True)

            for answer in result.response.answer:
                for item in answer.items:
                    self.values.add(item.address)
                    log.debug("Resolved %s (%s): %s", self.name, self.target,
                              item.address)
                ttl = max(ttl, answer.ttl)
                if self.ttl is None:
                    self.ttl = answer.ttl
        except NXDOMAIN as e:
            log.warning("Failed to resolve %s (%s): %s", self.name,
                        self.target, e)

        self.pending_resolve_count -= 1
        self.next_resolution_time = time() + ttl
        return

    def __repr__(self):
        return (("DNSAliasRecord(name=%r, ttl=%r, target=%r, "
                 "pending_resolve_count=%r, next_resolution_time=%r, "
                 "values=%r)") % (
                     self.name, self.ttl, self.target,
                     self.pending_resolve_count, self.next_resolution_time,
                     self.values))

def get_route53_records(hosted_zone_id, profile_name=None):
    """
    Returns the Route53 records for a given hosted zone.
    """
    session = Session(profile_name=profile_name)
    r53 = session.client("route53")

    kw = {"HostedZoneId": hosted_zone_id, "MaxItems": "2"}
    records = []

    while True:
        results = r53.list_resource_record_sets(**kw)
        for rrs in results["ResourceRecordSets"]:
            name = rrs["Name"]
            query_type = rrs["Type"]
            ttl = rrs.get("TTL")

            if "ResourceRecords" in rrs:
                values = [rs["Value"] for rs in rrs["ResourceRecords"]]
                record = DNSRecord(name, query_type, ttl, values)
                log.debug("Received Route53 record for %s: %s", name, values)
            elif "AliasTarget" in rrs:
                atgt = rrs["AliasTarget"]
                target = atgt["DNSName"]
                record = DNSAliasRecord(name, ttl, target)
                log.debug("Received Route53 alias record for %s: %s",
                          name, target)

            records.append(record)

        if not results["IsTruncated"]:
            break

        kw["StartRecordName"] = results["NextRecordName"]
        kw["StartRecordType"] = results["NextRecordType"]
        if "NextRecordIdentifier" in results:
            kw["StartRecordIdentifier"] = results["NextRecordIdentifier"]
        else:
            kw.pop("StartRecordIdentifier", None)

    return records

def resolve_alias_records(records):
    """
    Resolve alias records until there are no more resolutions to be had.
    """
    while len(records) > 0:
        records.sort(key=lambda record: record.next_resolution_time,
                     reverse=True)
        record = records.pop()

        now = time()
        if now < record.next_resolution_time:
            sleep(record.next_resolution_time - now)

        record.resolve()

        if record.pending_resolve_count > 0:
            records.append(record)

    return

def main(args):
    """
    Main entrypoint.
    """
    profile_name = None
    output_filename = None

    basicConfig(format="%(asctime)s %(levelname)s %(name)s "
                       "%(filename)s:%(lineno)d: %(message)s",
                level=DEBUG,
                stream=stderr)
    getLogger("boto").setLevel(WARNING)
    getLogger("botocore").setLevel(WARNING)

    try:
        opts, args = getopt(args, "ho:p:", ["help", "output=", "profile="])
    except GetoptError as e:
        print(e, file=stderr)
        usage()
        return 1

    for opt, val in opts:
        if opt in ("-h", "--help",):
            usage(stdout)
            return 0
        elif opt in ("-o", "--output",):
            output_filename = val
        elif opt in ("-p", "--profile",):
            profile_name = val

    if len(args) == 0:
        print("Missing zone id.", file=stderr)
        usage()
        return 1
    elif len(args) > 1:
        print("Unknown argument %r." % args[1], file=stderr)
        usage()
        return 1

    records = get_route53_records(args[0], profile_name=profile_name)

    alias_records = [r for r in records if isinstance(r, DNSAliasRecord)]
    resolve_alias_records(alias_records)

    if output_filename:
        fd = open(output_filename, "w")
    else:
        fd = stdout

    # Find the SOA record
    soa = [r for r in records if r.record_type == "SOA"][0]
    fd.write(soa.bind_config)

    for r in records:
        if r.record_type == "SOA":
            # Already printed; skip it.
            continue

        fd.write(r.bind_config)

    if fd is not stdout:
        fd.close()

    return 0

def usage(fd=stderr):
    "Print usage information."
    fd.write("""\
Usage: %(argv0)s [options] <zone_id>
Convert a Route 53 hosted zone to a BIND zone file.

Options:
    -h | --help
        Print this usage information.

    -o <filename> | --output <filename>
        Write output to the given file. Defaults to stdout.

    -p <name> | --profile <name>
        Use the specified AWS CLI/Boto profile for access/secret keys.
""" % {"argv0": argv[0]})

if __name__ == "__main__":
    sys_exit(main(argv[1:]))
