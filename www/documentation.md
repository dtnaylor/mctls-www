---
layout: default
title: mcTLS Specification
---

# The Multi-Context TLS (mcTLS) Protocol
{:.no_toc}

The mcTLS protocol is designed to enable secure communication between a client, server,
and 1 or more middleboxes in series between the client and server. The protocol is built 
as an extension to the TLSv1.2 protocol. This document extends and modifieds the TLSv1.2
specification in [RFC 5246](https://tools.ietf.org/html/rfc5246). Where details are omitted 
here, the reader should assume that no changes are made from the TLSv1.2 specification.

#### Contents
{:.no_toc}

* TOC
{:toc}


## Goals

mcTLS is designed to provide the following five properties:

1. **Entity Authentication:** As in TLS, the client must be able to verify
the identity of the server. Additionally, the endpoints must be able to
authenticate each middlebox.

2. **Payload Secrecy:** Third parties must not be able to read any
application data.

3. **Payload Integrity:** Changes to application data by third parties or by
middleboxes with read-only access must be detectable.

4. **Visibility:** Both endpoints must be aware of all middleboxes in the
session. mcTLS does not support transparent middleboxes.

5. **Least Privilege:** Each middlebox should be granted the minimum level of
access needed to do its jobs.


## Definitions and Notation

* 	mcTLS uses a pseudorandom function, [constructed as in TLS
	1.2](https://tools.ietf.org/html/rfc5246#section-5), to expand secrets into
	blocks of key material:

		PRF(secret, label, seed)

*	In this document, `+` indicates concatenation.

*	This document introduces the idea of an encryption context. We use the
	terms "context" and "slice" interchangeably.



## Handshake Protocol

The client generates a list of middleboxes to be used through a middlebox
discovery mechanism outside the scope of this document. The client sends a TLS
ClientHello message with the middlebox list included as a TLS extension. See
[Middlebox List Extension](#middlebox-list-extension) for the format. The
ClientHello must carry the mcTLS TLS version number. When the first middlebox
sees the ClientHello, it opens a TCP connection with the next middlebox and
forwards the ClientHello. This continues until it reaches the server.
Each middlebox examines the compression and cipher suites proposed
by the client and eliminates those it does not support. The server
reads the middlebox list and may immediately terminate the connection if the
middlebox list violates the application requirements.

The server sends a ServerHello message specifying the compression and cipher
suites to be used (i.e., the ones it picked from those offered by the client).
At this point, the client will wait to receive a Certificate message from each
middlebox and the server. Similarly, the server will wait until it receives a
Certificate message from each middlebox. If ephemeral public key encryption is
being used, then Certificate messages must be followed with ServerKeyExchange
messages. Once all Certificate and ServerKeyExchange messages are received, the
client sends a TLS ClientKeyExchange message to the server. With the receipt of
this message, the client and server possess a shared master secret. In TLS, the
master secret is used to generate the session key, which is used for encrypting
and MAC-protecting application data.  In mcTLS, we refer to this "session key"
as the `endpoint_encryption_key` and the `endpoint_MAC_key`. The
`endpoint_encryption_key` is only used for transferring context key material
between the client and the server and the `endpoint_MAC_key` is used for
generating each record's endpoint MAC (see [Message Authentication
Codes](#message-authentication-codes)).

After distribution of the server and middlebox certificates, both the client
and server generate two secrets for each context: the
`client_read_secret`/`client_write_secret` and
`server_read_secret`/`server_write_secret`. These secrets are used by all
parties (middleboxes and endpoints) to generate the *context keys* (see
[Context Key Generation](#context-key-generation)) that will be used by the
record protocol to encrypt and MAC-protect application data.

The client and server will send MiddleboxKeyMaterial messages to each middlebox and the
opposite endpoint to distribute these secrets. MiddleboxKeyMaterial is a new TLS
message type. See MiddleboxKeyMaterial Message section for format. The client and
server should send one another MiddleboxKeyMaterial messages containing secrets for all contexts
in the middlebox_list extension. A violation must be treated as a protocol error.
Middleboxes will receive secrets for each context for which they have read or
write access. Once a MiddleboxKeyMaterial message arrives at its intended middlebox
recipient, it must be forwarded on to the opposite end of the handshake to
ensure that both the client and server observe the full sequence of handshake
messages. The MiddleboxKeyMaterial message for the opposite end of the session must
be sent last.

Once all MiddleboxKeyMaterial messages have been received, the client, server,
and middleboxes have the encryption contexts necessary to transmit application
data.  First, however, validation of a successful handshake must be performed.
This is accomplished by the ChangeCipherSpec message to indicate the newly
negotiated encryption contexts should now be used and the transmission of a
Finished message including a MAC of all handshake messages using
`endpoint_MAC_key`. If the client or server fail to validate the Finished
message, then the client and server must not have observed the same sequence of
handshake messages. This is a fatal error.

	         CLIENT               MIDDLEBOX 1         MIDDLEBOX 2               SERVER

	      ClientHello -----------------x-------------------x---------------------->

	                                                                         ServerHello
	                                                                         Certificate
	                                                                      ServerKeyExchange
	           <-----------------------x-------------------x-------------- ServerHelloDone

	                                                  Certificate
	                                               ServerKeyExchange
	           < - - - - - - - - - - - o - - - - -  ServerHelloDone - - - - - - - >

	                              Certificate
	                           ServerKeyExchange
	           < - - - - - - -  ServerHelloDone  - - - - - o - - - - - - - - - - ->

	   ClientKeyExchange --------------x-------------------x---------------------->
	MiddleboxKeyMaterial[M1] ----------x-------------------o---------------------->
	MiddleboxKeyMaterial[M2] ----------o-------------------x---------------------->
	MiddleboxKeyMaterial[S] -----------o-------------------o---------------------->
	   ChangeCipherSpec 
	       Finished -------------------x-------------------x---------------------->

	           <-----------------------x-------------------o---------- MiddleboxKeyMaterial[M1]
	           <-----------------------o-------------------x---------- MiddleboxKeyMaterial[M2]
	           <-----------------------o-------------------o---------- MiddleboxKeyMaterial[C]
	                                                                       ChangeCipherSpec
	           <-----------------------x-------------------x------------------ Finished

	    Application Data <-------------x-------------------x-------------> Application Data

(In the figure, ``x`` indicates the middlebox reads and forwards the message;
``o`` indicates it just forwards it. The spaced dashed lines indicate the
middlebox certificate/key exchange messages are sent piggy-backed on the
``ServerKeyExchange`` (toward the client) and ``ClientKeyExchange`` (toward the
server) messages.)


### Middlebox List Extension

mcTLS defines a new TLS handshake extension middlebox_list with tentative type ID
0xff06. The extension contains:

*	A list of context IDs and descriptions. A context description is a string
	meaningful only to the application; mcTLS does not use it.

*	A list of middleboxes. Each entry specifies the middlebox's address, a
	unique ID, a list of the contexts for which the middlebox has read access, and
	a list of the contexts for which the middlebox has write access.

In order to make this list, the client application must know in advance how
many contexts it will need, which middleboxes should be included, and what
their permissions should be. How it knows these things is beyond the scope of
this document.  The format is as follows:

	middlebox_list {
	    slice {
	        slice_id
	        purpose
	            }[ ]
	    middlebox {
	        address
	        middlebox_id
	        read_slices[ ]
	        write_slices[ ]
	    }[ ]
	}

All elements of variable size are prepended with their length.  slice_id is a
single byte unique identifier that will uniquely identify an encryption context
(each record will be tagged with a one of these IDs---see [Record
Format](#record-format)).  A slice purpose is a byte array with which the
application may specify the purpose of the slice. Each middlebox is identified
by an address, which is a utf8 character array containing either the domain
name or IP address of the middlebox, and a middlebox_id, which is a one byte
unique identifier. Each middlebox is also assigned a set of 0 or more contexts
from the list slice_ids for which the middlebox has read access and a set of 0
or more slices for which the middlebox has write access. To have write access,
a middlebox must also have read access.  The middlebox_id values 0x00-0x02 are
reserved, with 0x01 always identifying the client and 0x02 always identifying
the server.


### Middlebox Key Material Message

mcTLS introduces a new handshake message type for delivering context key
material to middleboxes.  During the handshake, both the client and server will
send a MiddleboxKeyMaterial message to each middlebox with tentative handshake
message type 0x28. The payload of the message is encrypted with a symmetric key
shared between the endpoint sending the message and the middlebox receiving it
and contains a "partial secret" for each context to which the middlebox has
access.  Once a middlebox receives and decrypts a MiddleboxKeyMaterial message
from both the client and the server, it uses both secrets to generate the keys
that will actually be used in the encryption of application data (see [Context
Key Generation](#context-key-generation)).  The format of the message is as
follows:

	MiddleboxKeyMaterial {
        middlebox_id
        key_material {
            slice_id
            read_secret
            write_secret
        }[ ]
	}


### Context Key Generation

The keys used to encrypt/decrypt and MAC-protect application data are called
*context keys*.  There are six symmetric keys associated with each context:

*	`client_read_key`: Encrypt/decrypt data from client to server.
*	`server_read_key`: Encrypt/decrypt data from server to client.
*	`client_read_MAC_key`: Compute reader MAC for data from client to server.
*	`server_read_MAC_key`: Compute reader MAC for data from server to client.
*	`client_write_MAC_key`: Compute writer MAC for data from client to server.
*	`server_write_MAC_key`: Compute writer MAC for data from server to client.

For simplicity, when referring to these keys elsewhere in this document, we do
not distinguish between the client-to-server key and the server-to-client key
(for example, we may simply refer to a context's `read_MAC_key`). 

After receiving a MiddleboxKeyMaterial message from each endpoint, all parties
compute the context keys for the contexts that they can access.  For each
context, each party uses the partial secrets (one from the client and one from
the server) to compute two blocks of key material:

	read_key_block = PRF(client_read_secret + server_read_secret, "reader keys", client_random + server_random)
	write_key_block = PRF(client_write_secret + server_write_secret, "writer keys", client_random + server_random)

The `read_key_block` is partitioned into `client_read_key`, `server_read_key`,
`client_read_MAC_key`, and `server_read_MAC_key`; the `write_key_block` is
partitioned into `client_write_MAC_key` and `server_write_MAC_key`.


## Record Protocol

### Record Format

The TLS record format includes 1 byte for identifying the type of message, 2
bytes for the version of TLS in use, and 2 bytes for the message length. The
header is followed by the encrypted payload including the message, MAC, and
padding for block ciphers. We extend the header to include a 1 byte context ID: 

	0-------8---------------24--------------40------48----------------------------N
	| TYPE  |    VERSION    |    LENGTH     | CTXT  |      PROTECTED PAYLOAD      |
	-------------------------------------------------------------------------------

mcTLS uses a new TLS version number so that middleboxes and servers can
identify an mcTLS message by decoding only the first 3 bytes of the record.
Tentatively, this version number is set to 6.102.

Upon receiving an mcTLS record from the wire, the mcTLS-aware client,
middlebox, or server must read the context ID value from the header and apply
the correct encryption context in the decryption operation. If a middlebox does
not have keys for a particular context, it should forward the record unmodified
to the next middlebox or endpoint. If a client or server does not have keys for
the context, this should be treated as a protocol error.

Similarly, when generating a record for transmission on the wire, the
mcTLS-aware application must specify an encryption context. The record protocol
uses the corresponding keys to encrypt and MAC-protect the payload and places
the context ID in the record header.

### Message Authentication Codes

TLS uses a keyed MAC to detect message tampering by parties. mcTLS uses three
MACs for each record:

*	A *reader MAC*, generated with the context's `read_MAC_key`. This is used
	to detect changes by third parties.

*	A *writer MAC*, generated with the context's `write_MAC_key`. This is used
	to detect (illegal) changes by middleboxes with read-only access.

*	An *endpoint MAC*, generated with the `endpoint_MAC_key`. This is used to
	detect (legal) changes by middleboxes with write access.

The MAC format has not changed:

	MAC_function(MAC_write_key, seq_num + record.type + record.version + record.length + record.content)

The plus sign, +, indicates concatenation. Sequence numbers are global across
all encryption contexts to enforce correct ordering of all application data at
the client and server. In order to maintain consistent sequence numbers across
the full session, middleboxes must never modify the number or order of mcTLS records
on the communication medium.

The order of the MACs after the record payload is not significant and chosen
arbitrarily to be: payload, reader MAC, writer MAC, endpoint MAC.

## Application Programming Interface

To enable mcTLS applications, the TLS API must be expanded to include new methods
for specifying the encryption context in use, handling of the MAC, and
specifying the middleboxes to use in a handshake. The following methods have been
added to the API:

	int          mcTLS_connect(SSL *ssl, mcTLS_SLICE* slices, int slices_len, mcTLS_PROXY *middleboxes, int middleboxes_len);
	int          mcTLS_middlebox(SSL *ssl, SSL* ( *connect_func)(SSL *ssl, char *address), SSL **ssl_next);
	int          mcTLS_get_slices(SSL *ssl, mcTLS_SLICE **slices, int *slices_len);
	int          mcTLS_get_middleboxes(SSL *ssl, mcTLS_PROXY **middleboxes, int *middleboxes_len);
	mcTLS_PROXY* mcTLS_generate_middlebox(SSL *s, char* address);
	mcTLS_PROXY* mcTLS_middlebox_from_id(SSL *ssl, int middlebox_id); **TO BE REMOVED**
	mcTLS_SLICE* mcTLS_generate_slice(SSL *s, char* purpose);
	mcTLS_SLICE* mcTLS_slice_from_id(SSL *ssl, int slice_id);  **TO BE REMOVED**
	int 	     mcTLS_assign_middlebox_write_slices(SSL *s, mcTLS_PROXY* middlebox, mcTLS_SLICE* slices[ ], int slices_len);
	int 	     mcTLS_assign_middlebox_read_slices(SSL *s, mcTLS_PROXY* middlebox, mcTLS_SLICE* slices[ ], int slices_len);
	int          mcTLS_read_record(SSL *ssl, void *buf, int num, mcTLS_SLICE **slice, mcTLS_CTX **mac);
	int          mcTLS_write_record(SSL *ssl, const void *buf, int num, mcTLS_SLICE *slice);
	int          mcTLS_forward_record(SSL *ssl, const void *buf, int num, mcTLS_SLICE *slice, mcTLS_CTX *mac, int modified);

``mcTLS_connect(...)`` expands on the standard TLS connect method to allow clients to
specify the middlebox list to be included in the extension of the handshake.

``mcTLS_generate_middlebox(...)`` is used by the client to generate the state for a
middlebox. This should be called once for each middlebox in the session and the
resulting state objects passed to ``mcTLS_connect(...)``.

``mcTLS_generate_slice(...)`` is used by the client to initialize the state for each
slice to be used in a session. It should be called once be slice and the
resulting state objects passed as an array to ``mcTLS_connect(...)``.

``mcTLS_assign_middlebox_write_slices(...)`` and ``mcTLS_assign_middlebox_write_slices(...)`` are
used to specify the slices that a middlebox has read and write access to. Setting
these will control the distribution of encryption contexts during the
handshake. Write access for a middlebox implies read access.

``mcTLS_middlebox(...)`` is the equivalent call of ``mcTLS_connect(...)`` for a middlebox
implementation. Upon receiving a connection from a client, the middlebox will
instantiate an instance of the SSL library and call ``mcTLS_middlebox(...)`` passing a
callback function. The callback function will be called during the handshake to
enable the application to make a connection to the next middlebox or the server and
create another SSL library instance for the second connection.

``mcTLS_read_record(...)`` is used by clients, servers, and middleboxes to read the next
available record from the communication medium. If there is no record
available, the return value is 0. slice returns the encryption context used to
decrypt the message or an empty encryption context if the specified encryption
context is not available to the middlebox. If an encryption context is not
available at either the client or the server, it should be treated as a fatal
error.

``mcTLS_write_record(...)`` is used by clients and servers. The message is encrypted
using the specified encryption context and written to the communication medium.
If the encryption context is not available, an error is returned.

``mcTLS_forward_record(...)`` is used by mcTLS middleboxes to send a record on after
processing. If the encryption context is not available, then the application
data passed is treated as an encrypted record and forwarded without further
processing. If modified is false, the specified MAC is used and the message is
then encrypted. If modified is true, the specified MAC value is ignore and a
new MAC will be generated before encryption. Because the MAC generation
includes a sequence number, the middlebox must insure that the number of sent and
received records remains consistent and ordered upon each side of the middlebox.

``mcTLS_SLICE`` is a new structure that includes the full encryption context of a
traditional TLS session. The mcTLS client, server, and middlebox must maintain one
structure for each encryption context negotiated for the session. The ``mcTLS_SLICE``
structure includes a slice_id 1 byte value used to identify the slice within
the mcTLS record format and a have_material boolean value that indicates whether
this client, server, or middlebox has the encryption context. Clients and servers
should treat the receipt of any message for a slice where have_material is not
true as a protocol error. The structure has the following members which are
relevant to the application.

	mcTLS_SLICE {
        int read_access;
        int write_access;
        char *purpose;
	}

``read_access`` and ``write_access`` are boolean values indicating whether the
middlebox has read or write access to the slice, respectively. Clients and
servers always have both read and write access to all slices. Purpose is a null
terminated string that is defined by the client before the handshake to assign
an application dependent meaning to the slice. It can be used to indicate what
type of application data should be pass with each slice.

``mcTLS_CTX`` is context information from a previous call to ``mcTLS_read_record(...)``.
Middlebox implementations should pass the context to the related
``mcTLS_forward_record(...)`` call. Client and server implementations may ignore this
value.









## Security Analysis

### Handshake Protocol

The mcTLS handshake is ultimately responsible for two things:

1. **Distributing context keys to the correct entities.** (The context keys are
used to encrypt/decrypt/MAC application data, so if only the correct entities
have the context keys then only the correct entities can access/alter
application data.)

2. **Negotiating session configuration parameters between the client and ther
server.** *[cipher suite, session path (list of middleboxes + server), number
of contexts, middleboxes permissions for each context].* (Doing this
successfully implies that no one but the client and server—including
middleboxes—can force the session to use a weak encryption cipher or give
middleboxes higher permissions than the application intended.)


#### Distributing Context Keys

Like TLS, mcTLS can operate in multiple
authentication modes. Any party may optionally authenticate any other party,
with the exception that middleboxes never authenticate one another. As we argue
below, as long as each middlebox and the server are authenticated by at least
one endpoint (though clearly the client must be the one to authenticate the
server), a man-in-the-middle attack is not possible. In particular, *it is
sufficient for the client to authenticate each middlebox and the server*; the
middleboxes and the server do not need to authenticate anyone. For simplicity,
in the rest of this document we assume that the client authenticates everyone.

Since the client sends partial context keys to each party encrypted under a
symmetric key it shares with that party, *it is sufficient to show that each
symmetric key the client establishes is really shared by the correct entity
(see below).* (Even if the server does not authenticate anyone and sends partial
context keys to an adversary, the server’s partial keys are useless without
partial keys from the client as well.)

#### Session Configuration

Many configuration parameters are exchanged before any parties have established
shared keys, so they are sent in the clear. These values’ being visible is not
a security risk, but an attacker could weaken the security of the session by
actively modifying these messages in flight (e.g., to make the endpoints pick a
weaker encryption algorithm than they ordinarily would). 

**Endpoints:** If handshake messages are modified, the client and server will
compute different handshake transcript hashes and will abort the session when
they notice the discrepancy. Since these hashes are protected by K_endpoints,
an adversary cannot update them to reflect any changes it made to earlier
handshake messages. Therefore, to show that configuration parameters are safe,
*it is sufficient to show that the client establishes a shared key with the
correct server (see below).*

**Middleboxes:** mcTLS does not give middleboxes a way to verify the handshake
transcript. This means an adversary could arbitrarily alter any handshake
message sent to a middlebox. Middleboxes forward all handshake messages to the
opposite endpoint, but the adversary could drop the forwarded modified message
and replay the correct message to the endpoint, making this attack undetectable
by the endpoints when they exchange Finished messages. For each piece of
information carried by the handshake in the clear, we argue that the security
of the session is not compromised if the middlebox cannot verify it.

* *Cipher Suite:* The endpoints pick a cipher suite without input from
middleboxes. If the cipher suite is modified by anyone (attacker or middlebox),
the endpoints will detect the change. Attackers cannot influence the choice of
cipher suite by modifying the cipher suite right before the
ClientHello/ServerHello passes through a middlebox and correcting the change
before it is forwarded to an endpoint. In this case, the middlebox will not be
able to decrypt application data, but this is a denial of service attack (no
different from the adversary dropping all packets to that middlebox).

* *Number of Contexts:* Same argument.

* *Middlebox Context Permissions:* Same argument.

* *Session Path:* The session path is more subtle because middleboxes actually
use this information during the handshake process—it tells each one what “next
hop” to connect to. An adversary could replace the last hop in the path—the
intended server S—with an alternate server, S’. The last middlebox in the path,
M, would connect to S’ and successfully establish a key with it. (This works
even if M authenticates the server, because authentication depends on checking
a certificate, which requires that you know the domain name of the correct
party. In this case, the adversary has altered the domain name in the session
path, making M think that S’ is the correct server.) Meanwhile, the adversary
sends S copies of all of the expected handshake messages, so the client and the
server do not detect that anything is amiss. However, this attack does not
succeed: S’ does not learn the context keys. This is because middleboxes never
use the shared keys they establish with each endpoint to forward context key
material; they only use them to receive context key material. So, S’ can send
bogus context keys to M (a DoS attack). And even though the client sends
legitimate context keys to M, M never forwards these to S’ encrypted under a
key S’ knows.




#### Key Exchange

So far we have determined that the mcTLS handshake succeeds in its two goals if
the client successfully establishes a shared key with each party (known only to
the client and that party). Here we argue that this is the case:

**Client-Server Key Exchange:** The client and server use a standard TLS KE
mechanism to derive a shared secret. Although mcTLS adds extra information to
these handshake messages for other purposes, the information related to
client-server KE is unchanged and is used exactly as it is used in TLS.
Therefore, with respect to client-server KE, mcTLS inherits TLS’ security
properties. (The fact that these messages are now forwarded via one or more
middleboxes is irrelevant; as far as client-server KE is concerned, the
middleboxes are just like any other third-party entity that TLS was designed to
protect against.)

**Client-Middlebox Key Exchange:** mcTLS adds client-middlebox key exchanges to the
TLS handshake. These KEs are performed using standard TLS KE mechanisms. By
considering the middleboxes one at a time, the messages exchanged between the
client and each middlebox look like a standard client-server TLS KE (and are
generated/used just as they would be if the middlebox were a server in a normal
TLS KE). Therefore, the client establishes a shared secret with each middlebox
with the same security properties as a normal TLS KE.




*Note:* It may seem strange that the middleboxes do not need to authenticate anyone.
This is because mcTLS is designed with the philosophy that the session "belongs
to" the endpoints. The endpoints decide which middleboxes should be able to
access/alter application data and mcTLS enforces this. In contrast, middlebox A
cannot ensure that middlebox B does or does not have access to a session; we
view this as a policy issue, not a security property for mcTLS to guarantee. 





### Record Protocol

The mcTLS record protocol carries data which has been assigned by the
application to one of multiple encryption contexts. Each context has two keys:
a read key and a write key. The endpoints also share a key (the endpoint key)
that is not particular to any one context. Before sending a record, mcTLS
MAC-protects and encrypts it in the same way TLS would, except that mcTLS
encrypts using the context’s read key and generates three MACs, one for each
key. The handshake protocol ensures that the correct parties have the correct
context keys.

#### Read/Write Access

Which contexts an entity can read or write depends on which keys it has.

* *Third parties.* The handshake ensures that third parties learn no context
keys, so they cannot decrypt application data or recompute MACs (so they can
neither read nor write). The same security properties that apply to third
parties in TLS apply in mcTLS.

* *Readers.* Middleboxes with read-only permission for a context are given only
the read key. This means they can decrypt the data, but cannot recompute the
writer or endpoint MACs, so they do not have write access. (More on checking
MACs below.)

* *Writers.* Middleboxes with read+write permission for a context have both the
read key and the write key, meaning they can decrypt (read access) and
recompute the write MAC (write access).

* *Endpoints.* Endpoints know all context keys, so they have full read+write
access to the data stream.

**Detecting Illegal Writes:** "Illegal reads" simply cannot happen; parties
without read permission do not know the decryption key. Illegal writes (i.e.,
modifications by middleboxes with read-only access) are possible in the sense
they can use the read key to decrypt, change, and re-encrypt application data.
mcTLS’ endpoint-writer-reader MAC scheme allows endpoints and writers to detect
such modifications.

*Readers*

* **Can** detect **third party** changes because each record includes a MAC
computed with the read key. (Endpoints and writers generate this MAC whenever
they modify a record.)

* **Cannot** detect changes by **other readers** because all readers know the
read key, so another reader could make an illegal change and generate a new,
valid read MAC. Developers of middlebox software should be aware of this
limitation and take appropriate precautions if illegal changes by another
reader could pose a security risk to their application.

* **Cannot** detect **writer** changes because they do not know the write key
(and so cannot verify the writer MAC). This is okay, because a change by a
writer is not a security violation.


*Writers*

* **Can** detect **third party** changes by checking the reader MAC.

* **Can** detect **reader** changes by checking the writer MAC.

* **Cannot** detect changes by **other writers** because all writers know the
write key, so they can generate a new, valid writer MAC. Again, a change by a
writer is not a security violation.


*Endpoints*

* **Can** detect **third party** changes by checking the reader MAC.

* **Can** detect **reader** changes by checking the writer MAC.

* **Can** detect **writer** changes by checking the endpoint MAC. Again, a
writer change is not a security violation, but the endpoint application may be
curious whether or not the record was changed by a middlebox.


#### Dropping, Reordering, or Replaying Records

Like TLS, records in mcTLS carry sequence numbers (included in the MACs) to
prevent dropping, reordering, or replaying records. In mcTLS, sequence numbers
are global across contexts, otherwise attackers could delete a context entirely
or drop the last record in a context without detection. Like TLS, separate
encryption/MAC keys in each direction prevent replaying a record from one
direction in the other direction.








## Future Work

This document does not cover enhancements of the basic protocol such as
performance optimizations. Examples include reusing previously generated
session state in future connections and reuse of all or part of the middlebox
handshake across different servers. Finally, there may be a desire for more
flexibility in how control of middlebox use is divided between the client and
server. All of these enhancements are likely beyond the scope of an initial
prototype but are critical to a practical implementation of mcTLS.
