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

## Sponsors

[![Black Hills Information Security](http://www.blackhillsinfosec.com/_images/BHIS-Logo.png)](http://www.blackhillsinfosec.com)

Consulting | Research | Development | Training

