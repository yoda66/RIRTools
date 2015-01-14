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


## Sponsors

[![Black Hills Information Security](http://www.blackhillsinfosec.com/_images/BHIS-Logo.png)](http://www.blackhillsinfosec.com)

Consulting | Research | Development | Training

