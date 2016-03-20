%%%
    #
    # Solution Framework for Private Media
    # Generation tool: mmark (https://github.com/miekg/mmark)
    #
    Title = "A Solution Framework for Private Media in Privacy Enhanced RTP Conferencing"
    abbrev = "Private Media Framework"
    category = "std"
    docName = "draft-jones-perc-private-media-framework-02"
    ipr= "trust200902"
    area = "Internet"
    keyword = ["PERC", "Private Media Framework", "conferencing"]

    [[author]]
    initials="P."
    surname="Jones"
    fullname="Paul Jones"
    organization = "Cisco"
      [author.address]
      email = "paulej@packetizer.com"
      phone = "+1 919 476 2048"
      [author.address.postal]
      street = "7025 Kit Creek Rd."
      city = "Research Triangle Park"
      region = "North Carolina"
      code = "27709"
      country = "USA"
    [[author]]
    initials="D."
    surname="Benham"
    fullname="David Benham"
    organization = "Cisco"
      [author.address]
      email = "dbenham@cisco.com"
      [author.address.postal]
      street = "170 West Tasman Drive"
      city = "San Jose"
      region = "California"
      code = "95134"
      country = "USA"
    [[author]]
    initials="N."
    surname="Ismail"
    fullname="Nermeen Ismail"
    organization = "Cisco"
      [author.address]
      email = "nermeen@cisco.com"
      [author.address.postal]
      street = "170 West Tasman Drive"
      city = "San Jose"
      region = "California"
      code = "95134"
      country = "USA"
%%%

.# Abstract

This document describes a solution framework for ensuring that media confidentiality and integrity are maintained end-to-end within the context of a switched conferencing environment where media distribution devices are not trusted with the end-to-end media encryption keys.  The solution aims to build upon existing security mechanisms defined for the real-time transport protocol (RTP).

{mainmatter}

# Introduction

Switched conferencing is an increasingly popular model for multimedia conferences with multiple participants using a combination of audio, video, text, and other media types.  With this model, real-time media flows from conference participants are not mixed, transcoded, transrated, recomposed, or otherwise manipulated by a media distribution device (MDD), as might be the case with a traditional media server or multipoint control unit (MCU).  Instead, media flows transmitted by conference participants are simply forwarded by the MDD to each of the other participants, often forwarding only a subset of flows based on voice activity detection or other criteria.  In some instances, the switching MDDs may make limited modifications to RTP [@!RFC3550] headers, for example, but the actual media content (e.g., voice or video data) is unaltered.

An advantage of switched conferencing is that MDDs can be deployed on general-purpose computing hardware.  This, in turn, means that it is possible to deploy switching MDDs in virtualized environments, including private and public clouds. Deploying conference resource in a cloud environment might introduce a higher security risk.  Whereas traditional conference resources were usually deployed in private networks that were protected, cloud-based conference resources might be viewed as less secure since they are not always physically controlled by those who use the hardware.  Additionally, there are usually several ports open to the public in cloud deployments, such as for remote administration, and so on.

This document defines a solution framework wherein privacy is ensured by making it impossible for an MDD to gain access to keys needed to decrypt or authenticate the actual media content sent between conference participants.  At the same time, the framework allows for the switching MDD to modify certain RTP headers; add, remove, encrypt, or decrypt RTP header extensions; and encrypt and decrypt RTCP packets.  The framework also prevents replay attacks by authenticating each packet transmitted between a given participant and the switching MDD by using a key that is independent from the media encryption and authentication key(s) and is unique to the participating endpoint and the switching MDD.

A goal of this framework is to define a framework for enhanced privacy in RTP-based conferencing environments while utilizing existing security procedures defined for RTP with minimal enhancements.

# Conventions Used in This Document

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in [@!RFC2119] when they appear in ALL CAPS.  These words may also appear in this document in lower case as plain English words, absent their normative meanings.

This solution framework uses the following terms:

Endpoint:  An RTP terminating entity that terminates the end-to-end (E2E) security context.  This may include user endpoints, gateways, MCUs and more that are considered a PERC Trusted Element in any given deployment.

MDD:  Media Distribution Device - An RTP middlebox that is not allowed to be part of end-to-end security context.  It may operate according to any of the RTP topologies (NOTE: add reference I-D.ietf-avtcore-rtp-topologies-update) per the constraints defined by the PERC system, which includes, but not limited to, having no access to RTP media and have limits on what RTP header fields can be altered.

KMF:  An entity that is a logical function passes end-to-end key material to endpoints.  The KMF might be co-resident with another entity trusted with E2E key material.

PERC Trusted Elements:  Endpoint and KMF  (NOTE: elaborate more)

PERC Untrusted Elements:   MDD, Call Processing, Third Parties (NOTE: elaborate more)

Third Party:  Any entity that is not an Endpoint, MDD, KMF or Call Processing entity (NOTE: elaborate more)


# PERC Trust Model

The architectural model described in this framework document enables MDDs to be hosted in domains, such as in a cloud conferencing provider facility, where the trustworthiness is below the level needed to have the privacy of conference's media transmitted compromised.  The MDDs and supporting infrastructure in such a domain are still trusted with reliably connecting the participants together in a conference, but not trusted with key material needed to decrypyt any of the participant's media.  This has the benefit of protecting the confidentiality of participant's media in the case of attacks on those MDD, for example.

From the PERC model system perspective, entities in lower trustworthiness domains will simply be referred to as Unstrusted from this point forward.  This does not mean that they are completely untrusted; it only means that they are not trusted with media decryption. 

From the PERC model system perspective, entities considered trusted (Refer to (#fig-trustmodel)) can be in possession of the E2E media encryption key(s) for a past, current, or potentially future conference (or portion thereof) used to protect media content. In the general case, only the endpoint and an associated key management function needs to be trusted.  

Please note that some elements classified as untrusted in the simple, example case used in this document may be considered trusted in some deployments.  One example might be a gateway, traditional media server or other MDD in a trusted environment connecting endpoints via cascade link in to a private media conference.  This document does not preclude such deployment combinations, but will keep the definitions and examples focused by only using the the simple, general case.

Each of the elements discussed below has a direct or indirect relationship with each other.  The following diagram depicts the trust relationships described in the following sub-sections and the media or signaling interfaces that exist between them, showing the trusted elements on the left and untrusted elements on the right.  Note that this is a functional diagram and elements may be co-located or further divided into multiple separate physical entities.  Further, it is not necessary that every interface exist between all elements, such as both an interface from the endpoint and call processing function to a key management function, though both are possible options.

{#fig-trustmodel align="center"}
```

                       |
                       |
   +----------+        |       +-----------------+
   | Endpoint |        |       | Call Processing |
   +----------+        |       +-----------------+
                       |
                       |
+----------------+     |       +--------------------+
| Key Management |     |       | Media Distribution |
|    Function    |     |       |       Device       |
+----------------+     |       +--------------------+
                       |
     Trusted           |         Untrusted w/ Media
     Elements          |              Elements
                       |
                       |
```
Figure: Relationship of Trusted and Untrusted Elements

## Trusted Elements

The endpoint is considered a trusted element, as it will be sourcing media flows transmitted to other endpoints and will be receiving media for rendering.  While it is possible for an endpoint to be compromised and perform in unexpected ways, such as transmitting a decrypted copy of media content to an adversary, such security issues and defenses are outside the scope of this document.

The other trusted element is a key management function (KMF), which may be integrated with the endpoints or exist standalone.  This function is responsible for providing cryptographic keys to the endpoints for encrypting and authenticating media content.  The KMF is also responsible for providing cryptographic keys to the conferencing resources, such as the MDD, to enable authentication of media packets received by an endpoint.  Interaction between the KMF and untrusted call processing functions may be necessary to ensure endpoints are delivered the appropriate keys.  The KMF needs to be tightly controlled and managed to prevent exploitation by an adversary, as any kind of security compromise of the KMF puts the security of the conference at risk.

## Untrusted Elements

The call processing function is responsible for such things as authenticating the user or endpoint for the purpose of joining a conference, signing messages, and processing call signaling messages.  This element is responsible for ensuring the integrity, and optionally the confidentiality, of call signaling messages between itself, the endpoint, and other network elements.  However, it is considered an untrusted element for the purposes of this document, as it cannot be trusted to have access to or be able to gain access to cryptographic key material that provides privacy and integrity of media packets.

There might be several independent call processing functions within an enterprise, service provider network, or the Internet that are classified as untrusted.  Any signaling information that passes through these untrusted entities is subject to inspection by that element and might be altered by an adversary.

Likewise, there may be certain deployment models where the call processing function is considered trusted.  In such cases, trusted call processing functions **MUST** take responsibility for ensuring the integrity of received messages before delivering those to the endpoint.  How signaling message integrity is ensured is outside the scope of this document, but might use such methods as defined in [@RFC4474].

The final element is the switching MDD, which is responsible for forwarding encrypted media packets and conference control information to endpoints in the conference.  It is also responsible for conveying secured signaling between the endpoints and the key management function, acquiring per-hop authentication keys from the KMF, and performing per-hop authentication operations for media packets.  This function might also aggregate conference control information and initiate various conference control requests.  Forwarding of media packets requires that the switching MDD have access to RTP headers or header extensions and potentially modify those message elements, but the actual media content **MUST** not be decipherable by the switching MDD.

Further, the switching MDD does not have the ability to determine whether an endpoint is authorized to have access to media encryption keys.  Merely joining a conference **MUST NOT** be interpreted as having authority.  Media encryption keys are conveyed to the endpoint by the KMF in such a way as to prevent the switching MDD from having access to those keys.

It is assumed that an adversary might have access to the switching MDD and have the ability to read any of the contents that pass through.  For this reason, it is untrusted to have access to the media encryption keys.

As with the call processing functions, it is appreciated that there may be some deployments wherein the switching MDD is trusted.  However, for the purposes of this document, the switching MDD is considered untrusted so that we can be ensure to develop a solution that will work even in the most hostile environments.

It is expected that an MDD performs its role in properly forwarding media packets, taking measures to safeguard against replay attacks, etc.  If a MDD is exploited, an adversary may do such things as discard packets, replay packets, or introduce unacceptable delay in packet delivery.

# Framework for PERC 

The purpose for this framework is to define a means through which media privacy can be ensured when communicating within a conferencing environment consisting of one or more centrally located media distribution devices (MDD) that only switch, hence not terminate, media.  This framework specifies the reuse of several technologies, including SRTP [@!RFC3711], EKT [@!I-D.ietf-avtcore-srtp-ekt], and DTLS-SRTP [@!RFC5764].  For the purposes of this document, a conference refers to any session with two or more participants, attached via trusted devices, exchanging RTP flows through one or more MDDs.



  flat diagram will go here with HBH Key(j) and E2E Key(i), etc




## Media Privacy through an MDD

There may be situations where the MDD needs to modify the RTP packet received from an endpoint, such as by adding or removing an RTP header extension, modifying the payload type value, etc.  It would be the responsibility of the  MDD to ensure that media of the expected type and containing the correct information is received by a recipient.

Thus, there is a need to utilize an end-to-end encryption and authentication key (or pair of keys) and a hop-by-hop encryption and authentication key (or pair of keys).  The end-to-end encryption and authentication key(s) are to ensure that media remains private to the trusted endpoints.  The hop-by-hop authentication key allows the MDD to authenticate RTP and RTCP packets and to optionally modify certain elements of those packet.  The hop-by-hop encryption key is to optionally encrypt RTP header extensions and optionally encrypt RTCP packets [TODO: This changes with "double".  With "double", we use one SRTP master key and salt to encrypt end-to-end, optionally including RTP header extensions.  Then, we encrypt hop-by-hop using a second SRTP master key and salt, again optionally encrypting RTP header extensions.].  The current SRTP and related specifications do not define use of a dual-key (hop-by-hop and end-to-end) approach.  However, such an approach is possible and would result in ensuring the privacy of media is a scalable switching MDD conferencing model [REF Double Draft?].

This dual-key model does necessitate a change in the way that keys are managed.  However, the topic of key management is outside the scope of this document.  High-level assumptions, such as if the end-to-end context uses a group key as SRTP master key or if individual SRTP master keys (that may be derived/negotiated from another group key), are likely to influence the solution derived from this document.

## End-to-End Media Privacy

This solution framework focuses on the end-to-end (E2E) confidentiality and integrity of the participant's media content.  It does not attempt to hide the fact that a conference between participants is taking place.  

To ensure the confidentiality and integrity of RTP media packets, endpoints will first utilize a shared key that is known by all of the trusted endpoints in a conference. That shared key, a PERC EKT key [REF I-D.cullen-ekt-version], will be used to subsequently encrypt E2E key material and security context information (E2E Key(i); i={a given endpoint}) that each endpoint will be using to encrypt their media (i.e., RTP payload) via authenticated SRTP encryption [REF Double Draft?].

This PERC EKT key may need to change from time-to-time during the life of a conference, such as when a new participant joins or leaves a conference.  Dictating when a conference is to be re-keyed is outside the scope of this document, but this framework does enable re-keying during the life of a conference.

Endpoints **MUST** maintain a list of SSRCs from received RTP flows and each SSRC's associated E2E Key(i) material, which **SHOULD** subquently be discarded shortly after the PERC EKT key is changed or upon leaving the conference itself.  However, following a change of the PERC EKT key, prior E2E Key(i) material **SHOULD** be retained just long enough to ensure that late-arriving or out-of-order packets can be successfully played.

## Hop-by-Hop Security

To ensure the integrity of transmitted media packets, this framework requires that every packet be authenticated hop-by-hop (HBH).  The authentication key used for hop-by-hop authentication is derived from an SRTP master key shared only on the respective hop between the endpoint and the MDD to which it is attached (HBH Key(j); j=(a given hop)).  If MDDs are cascaded, then there will also be an SRTP master key and derived authentication key shared between the cascaded servers.  Each HBH Key(j) is distinct per hop and no two hops ever intentionally use the same SRTP master key.

Using hop-by-hop authentication gives the MDD the ability to change certain values present in the RTP header.  Which values the MDD may change in the RTP header are defined in [@!I-D.jennings-perc-double].

If there is a need to encrypt one or more RTP header extensions, an encryption key is derived from the hop-by-hop SRTP master key to encrypt header extensions as per [@!RFC6904].  This will still give the switching MDD visibility into header extensions, such as the one used to determine audio level [@!RFC6464] of conference participants.  Note that when RTP header extensions tare encrypted, all hops (in the untrusted doamin) will need to decrypt and re-encrypt these encrypted header extensions.

RTCP is optionally encrypted and mandatorily authenticated hop-by-hop using the encryption and authentication keys derived from the SRTP master key for the hop.  This gives the switching MDD the flexibility of either forwarding RTCP packets unchanged, transmit compound RTCP packets, or to create RTCP packets to report statistics or convey other information.

One of the reasons for performing hop-by-hop authentication is to provide replay protection (see (#attacks)).  If a media packet is replayed to the switching MDD, it will be detected and rejected.  Likewise, the endpoint can detect replayed packets originally sent by the MDD.  Packets received by an endpoint that were originally sent to a different endpoint will fail to pass authentication checks.

# SRTP Cryptographic Context

For any given media source identified by its SSRC, there is a single SRTP cryptographic context as described in Section 3.2 of [@!RFC3711] used in this framework.

For end-to-end encryption, this framework extends the parameter set of the cryptographic context by adding an identifier for the end-to-end authenticated encryption algorithm.  That parameter has associated with it an EKT key (and associated EKT information, such as master salt, key length, etc.), one or more SRTP master keys, and as outlined in Section 3.2.1 of [@!RFC3711], other associated values that relate to the master keys (e.g., master salt and key length values).

For hop-by-hop encryption, the existing parameters in the SRTP cryptographic context are used, including for the optional encryption of RTP header extensions, authentication tag generation, etc.

# Key Exchange

Within this framework, there are various keys each endpoint needs: those for end-to-end encryption/authentication and those for hop-by-hop authentication, optional encryption of RTP header extensions, SRTCP authentication, and optional SRTCP encryption.  Likewise, the MDD needs a hop-by-hop key for authenticated encryption between it and endpoints and for cascaded communications to another MDD, etc

To facilitate key exchange required to fullfill all of the above, this framework utilizes a DTLS-SRTP session between endpoints and the KMF via a DTLS tunnel between it and an MDD [add reference to tunnel I-D] and via procedures defined in PERC EKT [add reference to EKT diet I-D].  

## Negotiating SRTP Protection Profiles and Key Exchange

```
         E2E KEK info +---------+ HBH Key info   
         to endponts  |   KMF   | to endpoints & MDD
                      +---------+  
                        | ^ ^ | 
                        | | | |-DTLS Tunnel    
                        | | | |
+-----------+         +---------+         +-----------+
| Endpoint  |  DTLS   |   MDD   |  DTLS   | Endpoint  |
|  E2E KEK  |<--------|         |-------->|  E2E KEK  |
| HBH Key(j)| to KMF  | HBH Keys| to KMF  | HBH Key(j)|
+-----------+         +---------+         +-----------+

```
Figure: Key Management Function and Negotiating Key Information

### Endpoint and KMF

### MDD and KMF



## Session Signaling



# Attacks on Privacy Enhanced RTP Conferencing {#attacks}

This framework, and the individual protocols defined to support it, must take care to not increase the exposure to Denial of Service (DoS) Attacks by untrusted or third-party entities and should take measures to mitigate, where possible, more serious DoS attacks form on-path and off-path attackers.  

The following section enumerates the kind of attacks that will be considered in the development of this framework’s solution.

##  Third Party Attacks
On-path attacks are mitigated by HBH integrity protection and encryption.  The integrity protection mitigates packet modification and encryption makes selective blocking of packets harder, but not impossible.

Off-path attackers may try connecting to different PERC entities and send specifically crafted packets.  A successful attacker might be able to get the MDD to forward such packets.  If not making use of HBH authentication on the MDD, such an attack could only be detected in the receiving endpoints where the forged packets would finally be dropped.  

Another potential attack is a third party claiming to be an MDD, fooling endpoints in to sending packets to the false MDD instead of the correct one.  The deceived sending endpoints could incorrectly assuming their packets have been delivered to endpoints when they in fact have not.  Further, the false MDD may cascade to another legitimate MDD creating a false version of the real conference.  To mitigate, endpoints and MDDs should authenticate with the MDDs they are attached to.

##   MDD Attacks
   The MDD can attack the session in a number of possible ways.
   
###   Denial of service
Any modification of the end-to-end authenticated data will result in the receiving endpoint to get an integrity failure when performing authentication on the received packet.

The MDD can also attempt perform resource consumption attacks on the receiving endpoint.  One such attack would be to provide random SSRC/CSRC value to any RTP packet with an inband key-distribution message attached.  Since such message would trigger the receiver to form a new crypto context, the MDD can attempt to consume the receiving endpoints resources.  

An denial of service attack is that the MDD rewrites the PT field to indicate a different codec.  The effect of this attack is that an payload packetized and encoded according to one RTP payload format is then processed using another payload format and codec.  Assuming that the implementation is robust to random input it is unlikely to cause crashes in the receiving software/hardware.  However, it is not unlikely that such rewriting will cause severe media degradations.

For audio formats, this attack is likely to cause highly disturbing audio and/or can be damaging to hearing and playout equipment.  

###  Replay Attack
Replay attack is when an already received packets from a previous point in the RTP Stream is replayed as new packets.  This could, for example, allow an MDD to transmit a sequence of packets identified as a user saying "yes", instead of the "no" the user actually said.

The mitigation for a replay attack is to prevent old packets beyond a small-to-modest jitter and network re-ordering sized window to be rejected.  The end-to-end replay protection should be provided for the whole duration of the conference.

###  Delayed Playout Attack
The delayed playout attack is an variant of the replay attack.  This attack is possible even if e2e replay protection is in place.   However, due to that the MDD is allowed to select a sub-set of streams and not forward the rest to a receiver, such as in forwarding only the most active speakers, the receiver has to accept gaps in the e2e packet sequence.  The issue with this is that an MDD can select to not deliver a particular stream for a while.  

Within the window from last packet forward to the receiver and the latest received by the MDD, the MDD can select an arbitrary starting point when resuming forwarding packets.  Thus what the media source said, can be substantially delayed at the receiver with the receiver believing that it is what was said just now and only delayed by the transport delay.

###  Splicing Attack
The splicing attack is an attack where a MDD receiving multiple media sources splices one media stream into the other.  If the MDD is able to change the SSRC without the receiver having any method for verifying the original source ID, then the MDD could first deliver stream A and then later forward stream B under the same SSRC as stream A was previously using.  Not allowing the MDD to change the SSRC mitigates this attack.


# To-Do List

## What is Needed to Realize this Framework

- Endpoint must securely convey its certificate information to the KMF so the KMF can recognize a valid endpoint.

- A means through EKT or another mechanism to negotiate the SRTP security profiles for end-to-end encryption/authentication (e.g., proposing to negotiate AEAD_AES_128_GCM for end-to-end security) and hop-by-hop operations (draft [@!I-D.jennings-perc-double] will do that if adopted by the WG)

- A means through EKT or another extension of sending the participant identifier (the participant identifier could implicitly identify the conference) so the KMF will know which keys to provide for a given conference and RTP sessions related to that conference.  Alternatively, this could be an element of the tunneling protocol, wherein the MDD indicates the associated identifiers.  (Consider the case where the same person joins the conference from two different devices. The KMF could use distinct certificates per device. What if the user joins a conference twice from the same machine? Is this a corner case not worth allowing?)

- A change to EKT such that the ROC is transmitted in the clear, with integrity check performed by XORing the ROC with the IV used in AES Key Wrap.  The reason for having the ROC in the clear is that if there are long periods where Bob does not receive media from Sue and then Sue's media is forwarded to Bob, Bob would not be able to decrypt the media without guessing at the ROC.  Likewise, if Bob joins the conference already in progress for hours, he'll have the same issue.  The reason for XORing the ROC with the IV used in Key Wrap is to provide integrity protection for the ROC value, which we would get today with the way EKT is specified having the ROC inside the EKT Tag.

- Remove of the SSRC from the Full EKT Field if we allow MDDs to modify the original SSRC value. (What are the arguments for keeping it there?)

- A change to EKT to use neither the ISN (per IETF 93) nor MKI (per IETF 93)

- A means of conveying per-hop SRTP master key and salt information to the switching MDD (which can be accomplished using the DTLS-SRTP tunneling protocol specified in [I-D.jones-perc-dtls-tunnel])

- Investigate adding ability to enable one-way media from a non-trusted device (e.g., announcements). 

# IANA Considerations

There are no IANA considerations for this document.

# Security Considerations

\[TBD\]

# Acknowledgments

The authors would like to thank Mo Zanaty and Christian Oien for invaluable input on this document.

<reference anchor="H.323" target="https://www.itu.int/rec/T-REC-H.323">
  <front>
   <title>Packet-based multimedia communications systems</title>
   <author>
     <organization>ITU-T</organization>
   </author>
   <date month="December" year="2009"/>
  </front>
</reference>

{backmatter}
