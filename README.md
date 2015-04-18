# docker-devdns

DNS server resolving .dev domain against docker container names

# Use case

Make docker containers discoverable via DNS for development environments,
like when running a bunch of containers on your laptop.

This does not use any etcd/zookeeper backend or registrator process
but maintains it's own container name cache

See etcd/skydns for a more complete solution.

Names, unlike skydock/progrium-registrator are short: it's $CONTAINER_NAME.dev.
If a container name contains dots that will form subdomains.

# Design

Listens to container creation events and maintains a name<->ip cache.

Requests for a special toplevel domain (default .dev) tries to match any
running docker container with the same name.



Requests for other domains are resolved by the operating system resolver,
This is so that we can cooperate with other special DNS server solutions
installed in your development environment, like VPN-assigned DNS-servers,
vagrant landrush DNS servers etc.


# Usage

There are two cases:

1. Containers trying to resolve each other
2. Non-containers trying to resolve container names

For outside resolving, on OSX:

create a file /etc/resolver/dev:

    nameserver <listen addr of docker-devdns>

outside resolving, other OS:

use a dns server which can selectively forward
requests for the .dev domain to this server. For example
dnsmasq.

for container-to-container resolving, add the following to your docker
daemon options:

    --dns <listen addr of docker-devdns> --dns-search dev

by default we listen to port 53, since this is the easiest
to make containers use.


DO NOT point /etc/resolv.conf of your docker host to this server.
It will cause a resolver error since we try to look up any request for
other names by gethostbyname() which creates a loop. We try to detect
this misconfiguration on startup.

If you only want .dev names to be resolvable, you can disable this
behavior by using

    -local-resolver=false

No upstream server can be configured (yet).


# Flags

    -docker-host="tcp://docker:2375": docker host url, or set DOCKER_HOST
    -domain="dev": domain
    -listen-addr=":53": Listen address for DNS
    -local-resolver=true: Perform local gethostbyname queries for other domains


# Performance

Listens to container creation events and maintains a local cache based
on that

# Limitations

We only respond properly to A and AAAA queries.
