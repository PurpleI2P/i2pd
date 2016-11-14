
# Hacking on I2PD

This document contains notes compiled from hacking on i2pd

## prerequisites

This guide assumes:

* a decent understanding of c++ 
* basic understanding of how i2p works at i2np level and up

## general structure

Notes on multithreading

* every compontent runs in its own thread 

* each component (usually) has a public function `GetService()` which can be used to obtain the `boost::asio::io_service` that it uses.

* when talking between components/threads, **always** use `GetService().post()` and be mindfull of stack allocated memory.


### NetDb

#### NetDb.h

The `i2p::data::netdb` is a `i2p::data::NetDb` instance processes and dispatches *inbound* i2np messages passed in from transports.

global singleton at `i2p::data::netdb` as of 2.10.1

#### NetDbRequests.h

For Pending RouterInfo/LeaseSet lookup and store requests


### ClientContext 

#### ClientContext.h

`i2p::client::ClientContext` spawns all destinations used by the i2p router including the shared local destination.

global singleton at `i2p::client::context` as of 2.10.1



### Daemon

File: Daemon.cpp

`i2p::util::Daemon_Singleton_Private` subclasses implement the daemon start-up and tear-down, creates Http Webui and i2p control server.




### Destinations

#### Destination.h

each destination runs in its own thread

##### i2p::client::LeaseSetDestination

Base for `i2p::client::ClientDestination`

##### i2p::client::ClientDestination

Destination capable of creating (tcp/i2p) streams and datagram sessions.


#### Streaming.h

##### i2p::stream::StreamingDestination

Does not implement any destination related members, the name is a bit misleading.

Owns a `i2p::client::ClientDestination` and runs in the destination thread.

Anyone creating or using streams outside of the destination thread **MUST** be aware of the consequences of multithreaded c++ :^)

If you use streaming please consider running all code within the destination thread using `ClientDestination::GetService().post()`


#### Garlic.h

Provides Inter-Destination routing primatives.

##### i2p::garlic::GarlicDestination

sublcass of `i2p::client::LeaseSetDestination` for sending messages down shared routing paths.

##### i2p::garlic::GarlicRoutingSession

a point to point conversation between us and 1 other destination.

##### i2p::garlic::GarlicRoutingPath

A routing path currently used by a routing session. specifies which outbound tunnel to use and which remote lease set to use for `OBEP` to `IBGW` inter tunnel communication.

members:

* outboundTunnel (OBEP)
* remoteLease (IBGW)
* rtt (round trip time)
* updatedTime (last time this path's IBGW/OBEP was updated)
* numTimesUsesd (number of times this path was used)

### Transports

each transport runs in its own thread

#### Transports.h

`i2p::transport::Transports` contains NTCP and SSU transport instances
