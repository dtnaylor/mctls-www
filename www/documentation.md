---
layout: default
title: mcTLS Specification
---

# Secure Proxy Protocol (SPP) Specification Document (rev.2)

## Table of Contents
* TOC
{:toc}

A SPP session consists of a client, server, and 1 or more proxies in series
between the client and server. This document is an extension to the TLSv1.2
specification in RFC 5246: https://tools.ietf.org/html/rfc5246.

## Design Principles

* Explicit addition of a set of previously discovered proxies to a TLS session
* Agreement between the client and server on the set of proxies in use
* Negotiation of multiple encryption contexts to limit proxy access to a subset of the application data crossing the session
* Detection of modification of application content by proxies through use of end-to-end MAC

## Handshake Protocol

The client generates a list of proxies to be used through a proxy discovery
mechanism outside the scope of this document. The client sends a TLS
ClientHello message with the proxy list included as a TLS extension. See Proxy
List Extension section for format. The extension specifies the number of
encryption contexts, or slices, to generate, the full set of proxies to use,
and the order of proxy traversal. The ClientHello must carry the SPP TLS
version number. When the first proxy sees the ClientHello, it forwards the
message on until the message arrives at the server. Each proxy examines the
compression and cipher suites proposed by the client and eliminates those not
supported by the proxy. The server reads the proxy list and may immediately
terminate the connection if the proxy list violates the application
requirements.

The server sends a ServerHello message specifying the compression and cipher
suites to be used (i.e., the ones it picked from those offered by the client).
At this point, the client will wait to receive a Certificate message from each
proxy and the server. Similarly, the server will wait until it receives a
Certificate message from each proxy. If ephemeral public key encryption is
being used, then Certificate messages must be followed with ServerKeyExchange
messages. Once all Certificate and ServerKeyExchange messages are received, the
client sends a TLS ClientKeyExchange message to the server. With the receipt of
this message, the client and server possess a shared master secret. In TLS, the
master secret is used to generate the session key, which is used for encryption
and integrity; in SPP, the master secret is used to generate, which is used
only for end-to-end integrity (see Message Authentication Code section). 

After distribution of the server and proxy certificates, both the client and
server generate two keys for each slice. The first key, keyREAD, is used to
encrypt the slice and validate that the slice has not been modified on the
communication medium. The second key, keyWRITE, is used to validate writes
performed by middleboxes.

The client and server will send ProxyKeyMaterial messages to each proxy and the
opposite endpoint to distribute key material. ProxyKeyMaterial is a new TLS
message type. See ProxyKeyMaterial Message section for format. The client and
server should receive ProxyKeyMaterial messages containing keys for all slices
in the proxy_list extension. A violation must be treated as a protocol error.
Proxies will receive key material for each slice for which they have read or
write access. Once a ProxyKeyMaterial message arrives at its intended proxy
recipient, it must be forwarded on to the opposite end of the handshake to
insure that both the client and server observe the full sequence of handshake
messages. The ProxyKeyMaterial message for the opposite end of the session must
be sent last.

Once all ProxyKeyMaterial messages have been received, client, server and
proxies have the encryption contexts necessary to transmit application data.
First, however, validation of a successful handshake must be performed. This is
accomplished by the ChangeCipherSpec message to indicate the newly negotiated
encryption contexts should now be used and the transmission of a Finished
message using the negotiated keyE2E. If the client or server fail to validate
the Finished message, then the client and server must not have observed the
same sequence of handshake messages. This is a fatal error.

	Client                                    Proxy1                                     Proxy2                               Server
	ClientHello ------------------------------------------------------------------------------------------------->
																																	  ServerHello
																																		 Certificate
																														ServerKeyExchange
			   <------------------------------------------------------------------------------------------ ServerHelloDone
																								Certificate
																								ServerKeyExchange
			   <-------------------------------------------------------------- ServerHelloDone ------------------>
											   Certificate
											   ServerKeyExchange
			   <----------------------- ServerHelloDone --------------------------------------------------------->
	ClientKeyExchange ---------------------------------------------------------------------------------------->
	ProxyKeyMaterial[P1] -------->
	ProxyKeyMaterial[P2] --------------------------------------------->
	ProxyKeyMaterial[S]
	ChangeCipherSpec 
	Finished ------------------------------------------------------------------------------------------------------->
																									 <------------ ProxyKeyMaterial[P1]
														   <----------------------------------------------- ProxyKeyMaterial[P2]
																														ProxyKeyMaterial[C]
																														  ChangeCipherSpec
			  <------------------------------------------------------------------------------------------------------ Finished
	Application Data <----------------------------------------------------------------------------> Application Data


### Proxy List Extension

We define a new TLS handshake extension proxy_list with tentative type id
0xff06. The extension contains a list of the proxies to be used in the
communication as well as the number of encryption contexts, also known as
slices, that need to be generated and which proxies should have access to which
slices. Therefore, the client application must first derive the minimum number
of slices required for the session from the requirements of all proxies to be
used and feed the distribution among proxies as input to the SPP handshake
operation. The format is as follows:

	proxy_list {
		slice {
			slice_id
			purpose
				}[ ]
		proxy {
			address
			proxy_id
			read_slices[ ]
			write_slices[ ]
		}[ ]
	}

The structure is described below. All elements of variable size are prepended
with their length.  slice_id is a single byte unique identifier that will have
a one-to-one correspondence with an encryption context used within the SPP
session. A slice purpose is a byte array by which the application may specify
the purpose of the slice. Each proxy is identified by an address, which is a
utf8 character array containing either the domain name or IP address of the
proxy, and a proxy_id, which is a one byte unique identifier. Each proxy is
also assigned a set of 0 or more slices from the list slice_ids for which the
proxy has read access and a set of 0 or more slices for which the proxy has
write access. To have write access, a proxy must also have read access. The
proxy_id values 0x00-0x02 are reserved, with 0x01 always identifying the client
and 0x02 always identifying the server.

### Proxy Key Material Message

The delivery of key material to proxies necessitates the inclusion of a new
handshake message type into the TLS Handshake Protocol. During the handshake,
both the client and server will send a ProxyKeyMaterial message to each proxy
with tentative handshake message type 0x28. The payload of the message is
encrypted with a public key provided by the proxy in either the Certificate or
ServerKeyExchange message and contains contributory material for the keys
requested by the proxy. Once a proxy receives and decrypts a ProxyKeyMaterial
message from both the client and the server, it may combine the key material to
produce the keys that will actually be used in the encryption of application
data. The format of the message is as follows:

	ProxyKeyMaterial {
		proxy_id
		key_material {
			slice_id
			read_material
			write_material
		}[ ]
	}

The format of the material varies depending upon the cipher suite agreed upon
in the ServerHello message. Key material provided by the client and the server
are combined using XOR to generate the session keys.

## SPP Record Protocol

### Record Format

TLS record format on the wire includes 1 byte for identifying the type of
message, 2 bytes for the version of TLS in use, and 2 bytes for the message
length. The header is followed by the encrypted payload including the message,
MAC, and padding for block ciphers. We extend the header to include a 1 byte
slice ID: 

	0-------------8-------------------24------------------40--------------48------------------------------------------N
	 |    TYPE   |     VERSION    |     LENGTH     |     SLICE     |      ENCRYPTED PAYLOAD      |
	------------------------------------------------------------------------------------------------------------------------

SPP uses a new TLS version number so that proxies and servers may identify the
new protocol from only decoding the first 3 bytes of the record. Tentatively,
this version number is set to 6.102.

The new wire format expands the functionality of TLS to facilitate the use of
multiple encryption contexts in the encryption and decryption of the payloads.
Upon receiving an SPP record from the wire, the SPP aware client, proxy, or
server must read the slice ID value from the header and apply the correct
encryption context in the decryption operation. If a proxy does not have an
encryption context for a specified slice ID, the record should be forwarded
unmodified to the next proxy or endpoint. If a client or server does not have
the encryption context for a specified slice ID, this should be treated as a
protocol error.

Similarly, when generating a record for transmission on the wire, the SPP aware
application must specify which encryption context to be used in the encryption
of the payload. The slice ID of the specified encryption context must be
encoded in the record header.

### Message Authentication Code

TLS uses a keyed MAC to detect message tampering in the communication medium.
If a middlebox performs a modification of the message, then validation of the
MAC at the recipient will fail as desired. However, the failure will be
indistinguishable from an attack within the communication medium. Therefore,
SPP introduces two additional MACs. The standard TLS MAC is generated using
keyE2E while the two new MACs are generated using keyREAD and keyWRITE from the
record slice. The keyE2E MAC insures that the ends of the SPP session can
detect the presence of modifications of the content by proxies. The keyREAD MAC
is used by proxies to validate that the record has not been modified in the
communication medium. The keyWRITE MAC is used to verify that modifications of
the record have exclusively been performed by proxies with write access. The
MAC format has not changed and is described as follows:

	MAC_function(MAC_write_key, seq_num + record.type + record.version + record.length + record.content)

The plus sign, +, indicates concatenation. Sequence numbers are global across
all encryption contexts to enforce correct ordering of all application data at
the client and server. In order to maintain consistent sequence numbers across
the full session, proxies must never modify the number or order of SPP records
on the communication medium.

The order of the MACs after the record payload is not significant and chosen
arbitrarily to be: payload, read MAC, write MAC, end-to-end integrity MAC.

## Application Programming Interface

To enable SPP applications, the TLS API must be expanded to include new methods
for specifying the encryption context in use, handling of the MAC, and
specifying the proxies to use in a handshake. The following methods have been
added to the API:

	int        SPP_connect(SSL *ssl, SPP_SLICE* slices, int slices_len, SPP_PROXY *proxies, int proxies_len);
	int 	SPP_proxy(SSL *ssl, SSL* ( *connect_func)(SSL *ssl, char *address), SSL **ssl_next);
	int 	SPP_get_slices(SSL *ssl, SPP_SLICE **slices, int *slices_len);
	int 	SPP_get_proxies(SSL *ssl, SPP_PROXY **proxies, int *proxies_len);
	SPP_PROXY* SPP_generate_proxy(SSL *s, char* address);
	SPP_PROXY* SPP_proxy_from_id(SSL *ssl, int proxy_id); **TO BE REMOVED**
	SPP_SLICE* SPP_generate_slice(SSL *s, char* purpose);
	SPP_SLICE* SPP_slice_from_id(SSL *ssl, int slice_id);  **TO BE REMOVED**
	int 	SPP_assign_proxy_write_slices(SSL *s, SPP_PROXY* proxy, SPP_SLICE* slices[ ], int slices_len);
	int 	SPP_assign_proxy_read_slices(SSL *s, SPP_PROXY* proxy, SPP_SLICE* slices[ ], int slices_len);
	int        SPP_read_record(SSL *ssl, void *buf, int num, SPP_SLICE **slice, SPP_CTX **mac);
	int        SPP_write_record(SSL *ssl, const void *buf, int num, SPP_SLICE *slice);
	int        SPP_forward_record(SSL *ssl, const void *buf, int num, SPP_SLICE *slice, SPP_CTX *mac, int modified);

SPP_connect(...) expands on the standard TLS connect method to allow clients to
specify the proxy list to be included in the extension of the handshake.

SPP_generate_proxy(...) is used by the client to generate the state for a
proxy. This should be called once for each proxy in the session and the
resulting state objects passed to SPP_connect(...).

SPP_generate_slice(...) is used by the client to initialize the state for each
slice to be used in a session. It should be called once be slice and the
resulting state objects passed as an array to SPP_connect(...).

SPP_assign_proxy_write_slices(...) and SPP_assign_proxy_write_slices(...) are
used to specify the slices that a proxy has read and write access to. Setting
these will control the distribution of encryption contexts during the
handshake. Write access for a proxy implies read access.

SPP_proxy(...) is the equivalent call of SPP_connect(...) for a proxy
implementation. Upon receiving a connection from a client, the proxy will
instantiate an instance of the SSL library and call SPP_proxy(...) passing a
callback function. The callback function will be called during the handshake to
enable the application to make a connection to the next proxy or the server and
create another SSL library instance for the second connection.

SPP_read_record(...) is used by clients, servers, and proxies to read the next
available record from the communication medium. If there is no record
available, the return value is 0. slice returns the encryption context used to
decrypt the message or an empty encryption context if the specified encryption
context is not available to the proxy. If an encryption context is not
available at either the client or the server, it should be treated as a fatal
error.

SPP_write_record(...) is used by clients and servers. The message is encrypted
using the specified encryption context and written to the communication medium.
If the encryption context is not available, an error is returned.

SPP_forward_record(...) is used by SPP proxies to send a record on after
processing. If the encryption context is not available, then the application
data passed is treated as an encrypted record and forwarded without further
processing. If modified is false, the specified MAC is used and the message is
then encrypted. If modified is true, the specified MAC value is ignore and a
new MAC will be generated before encryption. Because the MAC generation
includes a sequence number, the proxy must insure that the number of sent and
received records remains consistent and ordered upon each side of the proxy.

SPP_SLICE is a new structure that includes the full encryption context of a
traditional TLS session. The SPP client, server, and proxy must maintain one
structure for each encryption context negotiated for the session. The SPP_SLICE
structure includes a slice_id 1 byte value used to identify the slice within
the SPP record format and a have_material boolean value that indicates whether
this client, server, or proxy has the encryption context. Clients and servers
should treat the receipt of any message for a slice where have_material is not
true as a protocol error. The structure has the following members which are
relevant to the application.

	SPP_SLICE {
		int read_access;
		int write_access;
		char *purpose;
	}

Read_access and write_access are boolean values indicating whether the proxy
has read or write access to the slice, respectively. Clients and servers always
have both read and write access to all slices. Purpose is a null terminated
string that is defined by the client before the handshake to assign an
application dependent meaning to the slice. It can be used to indicate what
type of application data should be pass with each slice.

SPP_CTX is context information from a previous call to SPP_read_record(...).
Proxy implementations should pass the context to the related
SPP_forward_record(...) call. Client and server implementations may ignore this
value.

## Areas of Future Expansion

This document does not cover enhancements of the basic protocol such as
performance enhancements. This includes such points as renegotiation for reuse
of previously generated session state and reuse of all or part of the proxy
handshake across different servers. Finally, there may be a desire to provide
more flexibility to the protocol in how control of proxy use is divided between
the client and server. All of these enhancements are likely beyond the scope of
an initial prototype but are critical to a practical implementation of SPP.

