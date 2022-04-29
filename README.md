# TransDNS
Archive of the TransDNS codebase for fun and profit

## What is it
This software was used by TransIP to serve its customers DNS records starting in the early 00's and lasting up till 2021. Originally it was running on top of FreeBSD (and it should still build for it), but later it was switched to Linux.

Add the end it was hosting the DNS for over 1 million domains with more than 30 million records, which included roughly 10% of all .nl domains. The main reason for switching away from it was that there was only one person maintaining it, not that there were any significant issues with the software as is. Due to the relative simplicity the software is really optimised and can probably out perform most modern DNS implementations.

## How to build
Building is mostly just GNU make, but you need clang as well as the openssl and mysql libraries and header files.

## How to use
Since this mainly a fun repository to document the old code there is no guide on how to use it. Have fun figuring it out :D
