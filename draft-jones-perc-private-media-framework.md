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

This solution framework uses the following terms or conventions:

Endpoint:  An RTP flow terminating entity that also terminates the end-to-end (E2E) security context.  This may include user endpoints, gateways, MCUs and more that are in a trusted domain for given deployment.

MDD:  Media Distribution Device - An RTP middlebox that is not allowed to be part of end-to-end media security.  It may operate according to any of the RTP topologies [@I-D.ietf-avtcore-rtp-topologies-update] per the constraints defined by the PERC system, which includes, but not limited to, having no access to RTP media and having limits on what RTP header fields can be altered. 

KMF:  An entity that is a logical function passes end-to-end key material to endpoints.  The KMF might be co-resident with another entity trusted with E2E key material.

Conference: Any session with two or more participants, via trusted endpoints, exchanging RTP flows through one or more MDDs.

Third Party:  Any entity that is not an Endpoint, MDD, KMF or Call Processing entity (EDITOR NOTE: elaborate more)


# PERC Entities and Trust Model

The following diagram depicts the trust relationships, direct or indirect, between entities described in the subsequent sub-sections.  Note that this these entities may be co-located or further divided into multiple, separate physical devices.   

Please note that some entities classified as untrusted in the simple, general deployment scenario used most commonly in this document may be considered trusted in other deployments.  This document does not preclude such scenarios, but will keep the definitions and examples focused by only using the the simple, most general deployment case.

{#fig-trustmodel align="center"}
```

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
     Entities          |             Entities
                       |

```
Figure: Trusted and Untrusted Entities in PERC


## Untrusted Entities

The architecture described in this framework document enables conferencing infrastructure to be hosted in domains, such as in a cloud conferencing provider's facilities, where the trustworthiness is below the level needed to assume the privacy of participant's media will not be compromised.  The conferencing infrastructure in such a domain is still trusted with reliably connecting the participants together in a conference, but not trusted with key material needed to decrypyt any of the participant's media.  Entities in such lower trustworthiness domains will simply be referred to as Unstrusted from this point forward.  This does not mean that they are completely untrusted with non-media related aspects of hosting a conference. 

### MDD 

An MDD forwards RTP flows between endpoints in the conference while performing per-hop authentication of each RTP packet.  The MDD may need access to one or more RTP headers or header extensions, potentially adding or modifying a certain subset.  The MDD will also relay secured messaging between the endpoints and the key management function and will acquire per-hop key information from the KMF.  The actual media content **MUST NOT** not be decryptable by an MDD, so it is untrusted to have access to the E2E media encryption keys, which this framework's key exchange mechanisms will prevent.  

An endpoint's ability to join a conference hosted by an MDD **MUST NOT** alone be interpreted as being authorized to have access to the E2E media encryption keys as the MDD does not have the ability to determine whether an endpoint is authorized.

An MDD **MUST** perform its role in properly forwarding media packets while taking measures to mitigate the adverse effects of denial of service attacks (Refer to (#attacks)), etc, to a level equal to or better than pre-PERC deployments.

An MDD or associated conferencing infrastructure may also initiate or terminate various conference control related messaging, which is outside the scope of this framework dosument.  

### Call Processing 

The call processing function is untrusted in the simple, general deployment scenario.  It cannot be trusted to have access to E2E key information and a physical subset of the call processing function may reside in facilities outside the trusted domain.

The call processing function may include the processing of call signaling messages and the signing of those messages, and may authenticate the endpoints for the purpose of starting the call signaling and subsequent joining of a conference hosted through one or more MDDs.  Call processing may optionally ensure the confidentiality call signaling messages between itself, the endpoint, and other entities.  

In any deployment scenario where the entire call processing function is considered trusted, the call processing function **MUST** ensure the integrity of received messages before forwarding to other entities.  

## Trusted Entities

From the PERC model system perspective, entities considered trusted (Refer to (#fig-trustmodel)) can be in possession of the E2E media encryption key(s) for a past, current, or potentially future conferences.   

### Endpoint

An endpoint is considered trusted and will have access to E2E key information.  While it is possible for an endpoint to be tampered with and become compromised, subsequently performing in undesired ways, defining endpoint resistence to compromise is outside the scope of this document.  Endpoints will take measures to mitigate the adverse effects of denial of service attacks from other entities (Refer to (#attacks)), etc, to a level equal to or better than pre-PERC deployments.

### KMF

The KMF, which may be colocated with an endpoint or exist standalone, is responsible for providing key information to endpoints for both end-to-end and hop-by-hop security contexts and for providing key information for the hop-by-hop security contexts to MDDs.  

Interaction between the KMF and the call processing function may be necessary to for proper conference-to-endpoint correlations, which may or may not be satisfied by getting info directly from the endpoints or via some other means. TODO: Need to revisit this design choice in the context of all the alternatives.

Obviously, the KMF needs to be closely  managed to prevent exploitation by an adversary, as any kind of security compromise of the KMF puts the security of the conference at risk.

# Framework for PERC 

The purpose for this framework is to define a means through which media privacy can be ensured when communicating within a conferencing environment consisting of one or more centrally located media distribution devices (MDD) that only switch, hence not terminate, media.  This framework specifies the reuse of several technologies, including SRTP [@!RFC3711], EKT [@!I-D.ietf-avtcore-srtp-ekt], and DTLS-SRTP [@!RFC5764].  



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

Within this framework, there are various keys each endpoint needs: those for end-to-end encryption/authentication and those for hop-by-hop authentication, optional encryption of RTP header extensions, SRTCP authentication, and optional SRTCP encryption.  Likewise, the MDD needs a hop-by-hop key for authenticated encryption between it and endpoints and for cascaded SRTP connections to another MDD, etc

To facilitate key exchange required to fullfill all of the above, this framework utilizes a DTLS-SRTP session between endpoints and the KMF via a DTLS tunnel between it and an MDD as defined in DTLS Tunnel for PERC [@!I-D.jones-perc-dtls-tunnel] and via procedures defined in PERC EKT [add reference to EKT diet I-D].  

## Initial Key Exchange and KMF

The procedures defined in DTLS Tunnel for PERC [@!I-D.jones-perc-dtls-tunnel] establish one or more DTLS tunnels between the MDD and KMF, making it is possible for the MDD to facilitate the establishment of a secure DTLS association between each endpoint and the KMF as shown the following figure.  The DTLS association between endpoints and the KMF will enable each endpoint to receive E2E Key Encryption Key (KEK) information and HBH key information.  At the same time, the KMF can securely provide only the HBH key information to the MDD.  The key information summarized here may include the master key and salt as well as the negotiated cryptographic transform.

{#fig-initialkeyexchange align="center"}
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
Figure: Exchanging Key Information Between Entities

Endpoints will establish DTLS-SRTP associations over the RTP session’s media ports for the purposes of key information exchange with the KMF.  The MDD will not terminate the DTLS signaling and instead forward DTLS packets received from endpoints on to the KMF, and vice versa, via a tunnel established between MDD and the KMF.  This tunnel used to encapsulate the DTLS-SRTP signaling between the KMF and endpoints will also be used to convey HBH key information from the KMF to the MDD, so no additional protocol or interface is required.

Following the key information exchange with the KMF, endpoints will be able to encrypt media end-to-end with their E2E Key(i), sending that E2E Key(i) to other endpoints encrypted with E2E KEK, and will be able to encrypt and authenticate RTP packets using local HBH Key(j).  The procedures defined do not allow the MDD to gain access to E2E KEK information, preventing it from gaining access to any endpoints’ E2E Key and subsequently decrypting media .

## Key Exchange during Conference




# Entity Trust

It is important to this solution framework that the entities can full trust and validate the authenticity of other entities, especially the KMF and Endpoints.  This may be satisfied via identity assertions from a trusted provider or via device certificates manually exchanged outside this frameowrk or via device certificate fingerprint information conveyed during session signaling.  [EDIT TO DO:  Cullen, others, perhaps you can add a small amount of elaboration here.]

## Identity Assertions
[EDIT TO DO:  Cullen, others, perhaps you can add a small amount of elaboration here.]

## Certificate Fingerprints in Session Signaling

Entities managing session signaling are generally assumed to be untrusted in the PERC framework.  However, there are some deployment scenarios where session signaling may be assumed trustworthy for the purposes of exchanging, in a manner that can be authenticated, the fingerprint of an entity’s certificate.  

As a concrete example, SIP [@RFC3261] and SDP [@!RFC4566] can be used to convey the fingerprint information per [@!RFC5763].  An endpoint’s SIP User Agent would send an INVITE message containing SDP for the media session along with the endpoint's certificate fingerprint, which **MUST** be cryptographically signed so as to prevent unauthorized modification of the fingerprint value.  For example, the endpoint can send a message to a call processing function (e.g., B2BUA) over a TLS connection.  And the B2BUA might sign the message using the procedures described in [@RFC4474] for the benefit of forwarding the message to other entities.  

Ultimately, if using session signaling, an endpoint's certificate fingerprint would need to be securely convey to the KMF and visa versa, as it will be necessary that KMF's certificate fingerprint be conveyed to endpoints in a manner that can be authenticated.

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
