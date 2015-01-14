## RIRTOOLS

RIRTools is a collection of python tools used to fetch, store,
and process Regional Internet Registry published data.  The RIR statistics
exchange format requires regional registries to publish a current daily
snapshot of Internet number resource allocations.  These consist of
IPv4, IPv6, and Autonomous System Number (ASN) resources.

The files published are made available commonly on FTP servers
for each RIR, these being 'arin', 'lacnic', 'ripe', 'apnic', and 'afrinic'.
The file naming format for the data is always in this format:

    delegated-<registryname>-<yyyymmdd>

with a hash verification file also published adding the '.md5' extension
to the existing filename.  Each RIR file is required to be published
at 23:59:59 in the local timezone of the RIR itself.  The latest file
published is required to have a symbolic link or copy of the data
with the filename of:

    delegated-<registryname>-latest

The published file data itself contains a file header, consisting
of a version, and summary line followed by individual file records.
The file record format contains the actual data of interest and
is delimited by the '|' character.   ISO-3166 country codes are
used as well as IPv4, IPv6, and ASN data.

## build_rir_database.py

This tool is designed to reach out to all of the Regional Internet
Registries and fetch the latest data via the FTP protocol.  As each
data file is fetched, it is parsed and written to a SQLLite3 database
that is created in the home directory of the account that runs the tool.
The SQLLite3 database is created as the filename "~/.rirdb/rir.db".
The utility also creates a file named "lastfetchdate" in this
same directory, and checks this data so that it can only be run
once per day.

This tool is ultimately designed to be run in a UNIX cronjob at 23:59:59 UTC
every day to fetch and update the latest RIR data worldwide.

In addition to fetching RIR data, this tool reaches out to country list
GIT repository and builds a secondary table of ISO-3166 country codes.

Also note that as an additional useful feature, this calculates IPv4
CIDR ranges, and stores the binary value of either the IPv4, or IPv6
starting address presented in order to ease post-processing and to
enable sorting of IP address data directly from SQL queries.

## riracl.py

This tool is designed to produce access control list (ACL) information
in a variety of formats.  Currently the formats supported for both
IPv4 and IPv6 include Linux IPTABLES, Cisco ASA Firewalls, Cisco Switch
extended access lists, and Cisco router prefix lists.  All of the ACL's
produced by this tool are in a "deny access" format, and in the case
of extended access-lists, a bi-directional command line switch is included
to account for the non-statefulness of these ACLs.

In order to select individual country code data, either a "--cc" country
code command line switch, or a "--country" name search switch can be
provided to the tool.

Example uses:

    $ ./riracl.py --ipv4 --iptables --cc KP
    # KP: Korea, Democratic People's Republic of
    -A INPUT -p ip -s 175.45.176.0/22 -j DROP


    $ ./riracl.py --ipv4 --switch --cc BT
    ! BT: Bhutan
    ip access-list extended BT:Bhutan_ip
      10 deny ip 43.241.136.0 0.0.3.255 any
      20 deny ip 45.64.248.0 0.0.3.255 any
      30 deny ip 103.7.252.0 0.0.3.255 any
      40 deny ip 103.29.224.0 0.0.3.255 any
      50 deny ip 103.245.240.0 0.0.3.255 any
      60 deny ip 103.252.84.0 0.0.0.255 any
      70 deny ip 118.103.136.0 0.0.7.255 any
      80 deny ip 119.2.96.0 0.0.31.255 any
      90 deny ip 202.89.24.0 0.0.7.255 any
      100 deny ip 202.144.128.0 0.0.31.255 any
      110 permit ip any any


    $ ./riracl.py --ipv6 --router --country Myanmar 
    ! prefix-list MM:Myanmar
    ipv6 prefix-list MM:Myanmar_ipv6 seq 10 deny 2400:8480::/32
    ipv6 prefix-list MM:Myanmar_ipv6 seq 20 deny 2401:bc80::/32
    ipv6 prefix-list MM:Myanmar_ipv6 seq 30 deny 2401:f200::/32
    ipv6 prefix-list MM:Myanmar_ipv6 seq 40 deny 2406:ea00::/32
    ipv6 prefix-list MM:Myanmar_ipv6 seq 50 deny 2407:6100::/32
    ipv6 prefix-list MM:Myanmar_ipv6 seq 60 deny 2407:f300::/32


## Sponsors

[![Black Hills Information Security](http://www.blackhillsinfosec.com/_images/BHIS-Logo.png)](http://www.blackhillsinfosec.com)

Consulting | Research | Development | Training

