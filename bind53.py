#!/usr/bin/env python
"""
Convert Route53 resource record sets to bind configuration.
"""

# pylint: disable=C0103,C0111,C0411,R0204,R0903,R0912,R0913,R0914
from __future__ import absolute_import, print_function
from getopt import getopt, GetoptError
from logging import basicConfig, getLogger, DEBUG, WARNING
from os import rename, unlink
from os.path import exists
from subprocess import PIPE, Popen
from sys import argv, exit as sys_exit, stderr, stdout
from time import asctime, sleep, time

from boto3.session import Session
from dns.resolver import NXDOMAIN, query as dns_query
from dns.rdatatype import A
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
            elif self.record_type == "NS":
                if "." in value and not value.endswith("."):
                    # Some Route 53 NS records are missing the terminating .
                    value += "."
                result.write(value)
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
        Attempt to resolve this name once, following CNAME chains if necessary.
        """
        ttl = self.min_resolution_delay

        try:
            log.debug("Query: %s", self.target)
            answer = dns_query(self.target, rdtype=A, tcp=True)
            log.debug("Answer: %s", answer)
            for item in answer.rrset.items:
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

def get_route53_records(zone_id, profile_name=None):
    """
    Returns the Route53 records for a given hosted zone.
    """
    session = Session(profile_name=profile_name)
    r53 = session.client("route53")

    hosted_zone = r53.get_hosted_zone(Id=zone_id)
    zone_name = hosted_zone["HostedZone"]["Name"]
    records = []

    kw = {"HostedZoneId": zone_id, "MaxItems": "100"}

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

    return zone_name, records

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

def process_zone(zone_id, output_filename, profile_name=None):
    """
    Write the records for a hosted zone to a file.
    """
    zone_name, records = get_route53_records(zone_id, profile_name=profile_name)

    if len(records) == 0:
        log.error("No records for zone %s; will not write zone file.",
                  zone_name)
        return False

    # Find the SOA record
    soa_records = [r for r in records if r.record_type == "SOA"]
    if len(soa_records) == 0:
        raise ValueError(
            "No SOA record for zone %s; will not write zone file." % zone_name)

    if len(soa_records) > 1:
        raise ValueError("Multiple SOA records for zone %s; will not write "
                         "zone file." % zone_name)

    alias_records = [r for r in records if isinstance(r, DNSAliasRecord)]
    resolve_alias_records(alias_records)

    if output_filename:
        fd = open(output_filename % {"zone_name": zone_name}, "w")
    else:
        fd = stdout

    fd.write("$ORIGIN %s\n" % zone_name)

    # Write the SOA record first
    fd.write(soa_records[0].bind_config)

    for r in records:
        if r.record_type == "SOA":
            # Already printed; skip it.
            continue

        fd.write(r.bind_config)

    if fd is not stdout:
        fd.close()

    return zone_name


def update_bind_config(bind_config, zone_names, output_filename):
    if exists(bind_config):
        old_bind_config = bind_config + ".old"

        if exists(old_bind_config):
            unlink(old_bind_config)

        rename(bind_config, old_bind_config)

    with open(bind_config, "w") as fd:
        fd.write('# Generated by bind53 at %s\n' % asctime())

        for zone_name in zone_names:
            zone_filename = output_filename % {"zone_name": zone_name}
            fd.write('zone "%s" IN {\n' % zone_name)
            fd.write('    type master;')
            fd.write('    file "%s";\n' % zone_filename)
            fd.write('};\n\n')

def kick_named():
    proc = Popen(["/sbin/service", "named", "reload"], stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    if out:
        for line in out.split("\n"):
            log.debug("/sbin/service named reload stdout: %s", line)
    if err:
        for line in err.split("\n"):
            log.warning("/sbin/service named reload stderr: %s", line)

    if proc.returncode == 0:
        return

    proc = Popen(["/sbin/service", "named", "restart"], stdout=PIPE,
                 stderr=PIPE)
    out, err = proc.communicate()
    if out:
        for line in out.split("\n"):
            log.debug("/sbin/service named restart stdout: %s", line)
    if err:
        for line in err.split("\n"):
            log.warning("/sbin/service named restart stderr: %s", line)

    if proc.returncode != 0:
        raise ValueError(err)


def main(args):
    """
    Main entrypoint.
    """
    profile_name = None
    output_filename = None
    bind_config = "/etc/bind53.conf"
    kick = False
    zone_names = []

    basicConfig(format="%(asctime)s %(levelname)s %(name)s "
                       "%(filename)s:%(lineno)d: %(message)s",
                level=DEBUG,
                stream=stderr)
    getLogger("boto").setLevel(WARNING)
    getLogger("botocore").setLevel(WARNING)

    try:
        opts, args = getopt(
            args, "c:hko:p:",
            ["bind-config=", "named-config=", "help", "kick", "output=",
             "profile="])
    except GetoptError as e:
        print(e, file=stderr)
        usage()
        return 1

    for opt, val in opts:
        if opt in ("-c", "--bind-config", "--named-config",):
            bind_config = val
        elif opt in ("-h", "--help",):
            usage(stdout)
            return 0
        elif opt in ("-k", "--kick",):
            kick = True
        elif opt in ("-o", "--output",):
            output_filename = val
        elif opt in ("-p", "--profile",):
            profile_name = val

    if len(args) == 0:
        print("Missing zone id.", file=stderr)
        usage()
        return 1

    errors = 0

    for zone_id in args:
        log.info("Processing hosted zone %s", zone_id)
        try:
            zone_name = process_zone(zone_id, output_filename, profile_name)
            zone_names.append(zone_name)
        except Exception as e: # pylint: disable=W0703
            log.error("Failed to process hosted zone %s: %s", zone_id, e,
                      exc_info=True)
            errors += 1

    if not errors:
        try:
            update_bind_config(bind_config, zone_names, output_filename)
            if kick:
                kick_named()
        except Exception as e: # pylint: disable=W0703
            log.error("Failed to restart named: %s", e, exc_info=True)
            errors += 1

    if errors:
        log.error("%d error(s) encountered.", errors)
    else:
        log.info("No errors encountered.")

    return min(errors, 127)

def usage(fd=stderr):
    "Print usage information."
    fd.write("""\
Usage: %(argv0)s [options] <zone_id> [<zone_id> ...]
Convert Route 53 hosted zones to BIND zone files.

Options:
    -c <filename> | --bind-config <filename> | --named-config <filename>
        The BIND configuration file to edit. Defaults to /etc/bind53.conf.

    -h | --help
        Print this usage information.

    -k | --kick
        Restart the BIND server after writing the zone files. This is done
        only if no errors are encountered.

    -o <filename> | --output <filename>
        Write output to the given file. Defaults to stdout.
        This may contain %%(zone_name)s, which will be replaced with the
        zone name.

    -p <name> | --profile <name>
        Use the specified AWS CLI/Boto profile for access/secret keys.
""" % {"argv0": argv[0]})

if __name__ == "__main__":
    sys_exit(main(argv[1:]))
