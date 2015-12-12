### Ashish / Stiteler chat application

Usage:

    Username/Passwords:
        'bob': 'soccer_fan_89!',
        'sally': 'por0s_are_cute54@',
        # the following are for debugging quickly..
        'chris': 'pass',
        'ashish': 'ashish',

    User protocols (commands recognized by the chat client):
        '@list' - List the users connected to the server.
        '@invite' - Invite a user to chat with you.
        '@logout' - Logout of the server.
        '@msg' - Message someone you are connected with. Usage is
            '@msg USERNAME: Your Message'
        '@help' - Prints this Dialog.

    Dependencies include the python cryptography package (and depending on your platform, 
        the python "select" builtin.)

    In order to generate new Server Keys:
        python server_keygen.py

    To watch debug messages, set the line of code `logger.setLevel(logging.INFO)` to logging.DEBUG


    TESTING:
    1.) Start the Server:
        python server.py

    2.) Start the Client
        python client.py




Uncompleted Goals:
    - Comprehensive Brownlisting for added DDoS protection
        - We implemented a DoS cookie protocol, however, so this is somewhat
        helpful in prevent DoS attacks.  With more time, our server would
        keep a list of users and IPs that have failed a connection for a
        variety of suspicious reasons, and would begin rate limiting their
        ability to connect to the server.

    - Client <-> Client and Server <-> Client Heartbeat protocol.
        - This wasn't actually in our original design, however as an added
        feature, we felt it would be necessary to ensure a good chat
        experience if users knew if the server and/or those they are connected
        to were still online.  This heartbeat comes with it's own set of
        security considerations, and we opted to default to a bad user
        experience over an insecure one.

    - Stronger Password Security.  Currently the users password is included
        unhashed by the client (but still encrypted inside the servers public key). Ideally, we could have implemented a protocol that disguised the
        users password.  We felt it was more important to store the user's
        random salt locally on the server, and since we can't store this value
        locally on the client side, we weren't sure how to overcome this limitation.  Basically, it requires even more trust in the server, which is the most likely point of security failure in our system.

    - Obfuscated Protocol Types: In our original design we wrapped each
        of the outgoing messages from both the server and the client
        (except the initial "LOGIN") protocol inside the encrypted body
        when possible.  This was to prevent a passive attacker from 
        at least decoding who was doing what at what time.  However,
        in order to translate messages on the wire properly, we're sending
        the protocol in plain text. (i.e. 'INVITE') so that the receiver
        of this message knows how to handle it. In the future we would like
        to devise a better method of identifying protocol sequence between
        the client and the server (perhaps map each protocol on either side
        to a random nonce that each can look up in the context of a given
        user/server relationship)


Documented Bugs:
    - We need more error handling.  There are a few weak points in our
    error checking code that could be improved both internally and for
    the benefit of the chat user.

Changes we've added to the original design document (which is below):
    - As mentioned before we took the protocol types outside of the
        encrypted body to better handle these messages without extra
        time to obfuscate them.
    - The RSA payload size to send the public key was way too big for
        even a 4096 bit RSA key, so we had to split the encryption of this
        portion by two, both encrypted with RSA.  See the 
        client.handle_login_cookie method.  This introduces a weaker security,
        and allows an attacker to discover the servers public key in an offline attack.  But this isn't super important since the payload
        that requires more security (as with the username/password inside)
        includes a nonce that fits in the RSA key size.
    - In order to do two way HMAC, we had to include the public key of the 
        invitee to be sent back to the inviter in our Niedman Shroeder
        based session key establishment.  It is public, anyways...

Discussion of services:
    - PFS: We believe we've achieved PFS on a SESSION wide level.  No user, server/client side
        can use any information gathered in the current chat session to discover the results
        of a previous session. 
    - DoS resistance: We have achieved partial DoS resistance with the DoS cookie, but the brown
        list remains unimplemented because of the code freeze approaching.
    - Endpoing Hiding: We do successfully hide endpoints via a combination of symmetric
        and asymmetric encryption scheme.
    - Message Authenticity: Once a session is established with a connected client, all messages
        therein are authenticated by HMAC.


---- ORIGINAL DESIGN SPECIFICATION ----
Ashish Kumar & Chris Stiteler
PSET 4 - Report

SECURE CHAT MESSENGING APPLICATION SPEC:

Overview: Users (A, B, C etc) authenticate individually via client with a server (S)
The server mediates authentication between all users.

------
Services:
    Perfect Forward Secrecy - Attained by creating temporary public/private keys
        as well as temporary symmetric session keys between both the server and client
        and between all users who are engaged in a chat.
    DoS resistance - We protect against DoS attacks by enforcing a SYN cookie policy for
        all clients wishing to connect to the server.  In addition we are going to implement
        rate limiting by both USERNAME and IP/Port (by preventing a client from requesting
        a login from the server too fast).  (An additional protection we can add is a
        peer to peer DoS protection, by rate limiting the messages via the client itself. But
        this policy can't be enforced because the clients manage their own connections to other
        users, and server does not play an intermediate role, for good reason).
    Endpoint Identity Hiding: The addresses of all clients are shared only after a user has been
        authenticated with the server.  Additionally, the address/ip combination for each user
        is stored in memory upon authentication, and is NOT stored on disk at all.  This information
        is destroyed upon a successful "LOGOUT" protocol, and is never saved to disk.
    Message Authenticity: All messages sent after a successful authentication protocol will be hashed
        and the HMAC will be attached to every message and confirmed by the receiving client/server

------
Assumptions:
    - The server's public key and IP/Port information are known to all clients
    - The client has enforced strong password policies upon registering clients
    - All users are preregistered with the server (This means the server has data
        that represents the user's password (a hash|salt thereof, stored on disk))

------
Algorithm Choices:
    All symmetric keys are going to be AES in CBC mode with 256 bit keys
    All Nonces will be 64-bit cryptographically random numbers
        the generators of which store a LOCAL IN MEMORY copy (no unique user TIMESTAMP is sent on the wire)
    All asymmetric keys are going to be RSA 2048 bit
    All messages sent after authentication and establishment of a session key in any RELATIONSHIP will be sent
        with an HMAC (internal hash: SHA-256)

------
User to Server Relationship - Protocols
LOGIN (user and server mutually authenticate)
LIST (user requests a list of other users)
CONNECT (user requests to connect with another user)
LOGOUT (user requests to terminate session)

User to User Relationship - Protocols
INVITE - (A requests to chat with B)
MESSAGE - (A sends a message to B)

------
INTIALIZATION OF CLIENT:
Client generates an in memory public/private key pair for this session (Kuser_priv, Kuser_pub) [RSA, 2048]
This pair is forgotten upon termination of the client (PFS)
Client parses server information from file (Kserv_pub, server_address)
Client then begins LOGIN protocol with server information (see next slide)

------
User/Client (C) to Server(S): LOGIN Mutual Auth.

C -> S: ‘LOGIN’
S -> C: DoS_cookie (unique cookie that C must possess to auth with S)
[client prompts user for username (UN) and password (PWD)]
C -> S: {UN, Nu, hash(PWD), Kuser_pub}Kserv_pub, DoS_cookie

/** At this point, the server FIRST checks the IP/Port of C and the SYN COOKIE,
 *  It then should validate the username (check that user is registered and that the
 *  user is not already logged in, that the user is not on the "brown-list")
 *  Therafter the server will check the hash(SALT|PASSWORD) against the stored value.
 *  If all is well, it generates the Ksession symmetric AES key.
 */

S -> C: {Ksession, UN, Nu, Ns}Kuser_pub
C -> S: Ksession{Ns}

------
User (U) to Server (S): ‘LIST’ protocol
U’s symmetric session key from LOGIN is Kus

U -> S: Kus{‘LIST’, U, Nu}
S -> U: Kus{[user1, user2, ...], Nu}

/** The user can check the 'freshness' of this user list with Nu **/

------
User (A) to Server (S): CONNECT to User (B) protocol:
A’s session key from login is Ksa, TTB is a ticket to B (based on Needham Shroeder)

A -> S: Ksa{‘CONNECT’, A, B, Na}

/** The server confirms that B is logged in and is currently STILL on the internal list **/

S -> A: Ksa{TTB, A, B, Na, serv_ts, ip_port_b}
TTB = Ksb{A, B, ip_port_a, Na, server_timestamp, Ka_pub}

/** Ticket to B allows A to check it's freshness (Na), B to check it's freshness(serv_ts),
    It allows B to know where A lives on the network, and confirms to both parties
    that A requested to connect to B, it let's B know what A's public key is to respond to
    the ticket.  Only B can read the ticket with the CURRENT SESSION KEY.  Once B logs out
    the ticket is no longer useful by anyone in any replay attack. **/

------
User (U) to Server (S): ‘LOGOUT’ protocol:

U -> S: Ksu{‘LOGOUT’, U, Nu}
S -> U: Ksu{‘LOGOUT_ACK’, Nu}
U -> S: Ksu{Nu}

After logout, server will remove user from userlist, forgetting all temporary information,
in particular the symmetric session key, the public key of the client, and the client's
current network endpoint.

------
User (A) to user(B): "INVITE" protocol:

A -> B: A, ‘INVITE’, TTB
/**
    Here B confirms the ticket is fresh and valid, and the fact that B's current
    key even decrypts relevant values will mean that the ticket was created with B's
    current session key. (Check that the server timestamp is reasonable does this for B).
    B can also double check that the sender conforms to the value "A" in this message, and, if possible,
    can check A's network address against the information in the ticket as well.

    If all is well B creates a symmetric session key between A and B
**/

B -> A: {serv_ts, Na, A, B, Kab, Nb}Ka_pub

/**
    Here A can then check that the message from B is valid.  This is
    done by checking the nonce, Na.
**/
A -> B: Kab{Nb}

------
User (A) to User (B): "MESSAGE" protocol:

A -> B: HMAC(Kab{ ‘MESSAGE’, A, a_ts, message})
B -> A: Kab{ ‘MESSAGE_ACK’, a_ts}

The message is also hashed to guarantee authenticity.
If a MESSAGE_ACK is not returned within a specified time period, A can assume B has been disconnected,
logged out, or otherwise, and will terminate the session key, Kab, warning the user.
In the event that A either disconnects from the server and/or logs out, or exits the program,
then the shared key with B will be forgotten as well (never persisted to disk)


Discussion:
    Issues 1, 2, and 3 were talked about in previous sections
    4.) If the users do not trust the server can you devise a scheme that prevents the server from decrypting the communication
    between the users without requiring the users to remember more than a password? Discuss the cases when the user trusts
    (vs. does not trust) the application running on his workstation.

        If the server is compromised, the server can connect users to an attacker rather than to the requested user.
        This is hard to prevent when the server mediates all connection between users. This requires that the attacker
        who compromised the server be active.  If the attacker is passive, it cannot set up such a scheme (the session key
        created with the server differs from that created between the chatting users.) Even if the server stores old session
        keys, it will only be able to figure out WHO A wanted to talk to, not WHAT they were talking about.

        In the case the user can trust the client, the major weakness is, as discussed, a compromised server. Just as in other Key
        Distribution frameworks, the KDC being compromised can cause some pain for the system, particularly denial of service, man in
        the middle attacks etc.

        If the user can't trust the client, then user's password and username are not going to be secure.  The workstation will
        be able to figure out what this plaintext is before sending it in the authentication protocol to the server.  If a user
        doesn't trust a workstation, they should change their password asap. That being said, any information that the client receives
        in that session is not secure, however if the user were to log in from another trusted client, the old compromised client will
        not be able to gain any advantage, so long as the user has changed their password.