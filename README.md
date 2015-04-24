# threataggregator
Aggregates security threats from a number of online sources, and outputs to Syslog CEF, Snort Signatures, Iptables rules, hosts.deny, etc.

feeds.py contains a dictionary list of various feeds to use.
config.py contains a small list of configuration settings for syslog purposes.

Usage:

Simply run threataggregator.py with no arguments.

Applciation will grab HTTP-based feeds from feeds.py, and send syslog packets to the target specified in config.py

standard json-formatted output will also be displayed stdout from threataggregator.py
