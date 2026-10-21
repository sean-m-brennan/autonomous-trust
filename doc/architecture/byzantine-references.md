# Byzantine references

The verified reading list behind the Byzantine sections of `R+D.md`: §13
(Byzantine resilience at bounded fault counts) and §14 (the dishonest
majority). Each entry gives the full citation, what the R+D text uses it for,
and where in the paper the property it relies on is stated.

> **Verification.** The §13 entries were checked on 2026-09-17 against
> publisher and author-hosted copies, and the §14 entries on 2026-10-20 by the
> same method. Each §14 entry has three checks: the publisher record (ACM DL,
> SIAM, IEEE Xplore, USENIX, Springer, with Crossref as the machine record), a
> second author list from the paper's own title page, and a claim check that
> reads the section the R+D sentence relies on and records a locator. The §13
> entries record the first two checks only.
>
> **Corrections, 2026-09-17 (§13).** Every year and venue in the original list
> was right; the errors were in author lists. Gil et al.'s fourth author is
> Dina Katabi (not "Katz"), and Mark Mazumder is on both versions. The third
> author of the PODC 2012 paper is Guanfeng Liang; the original list repeated
> Vaidya. The coNP-completeness of deciding robustness is established by Zhang,
> Fata & Sundaram, not by Usevitch & Panagou.
>
> **Corrections, 2026-10-20 (§14).** Metadata errors were small: Polygraph's
> venue is confirmed as ICDCS 2021, and pages and DOIs are filled in. Two R+D
> sentences claim more than their papers state (accountability, and the
> max-flow bound), and two §14.1 bounds rest on Fitzi's thesis rather than on
> the paper they sit beside or on nothing. They are listed under
> [Claim errors](#claim-errors), and the corrected wording was applied to
> `R+D.md` on 2026-10-20.

---

## The W-MSR core

- **LeBlanc, Zhang, Koutsoukos & Sundaram**, "Resilient Asymptotic Consensus in
  Robust Networks," *IEEE Journal on Selected Areas in Communications* 31(4),
  2013. The canonical W-MSR paper. It defines r-robustness and
  (r,s)-robustness and proves that they, not connectivity, are the right
  condition. §13's bibliography records its Lemma 4 as the locator for the
  trimmed-mean bound.
- **LeBlanc & Koutsoukos**, "Consensus in networked multi-agent systems with
  adversaries," HSCC 2011; and "Low complexity resilient consensus in networked
  multi-agent systems with adversaries," HSCC 2012. The precursors.
- **Zhang & Sundaram**, "Robustness of information diffusion algorithms to
  locally bounded adversaries," ACC 2012.
- **Sundaram & Hadjicostis**, "Distributed function calculation via linear
  iterative strategies in the presence of malicious agents," *IEEE Transactions
  on Automatic Control* 56(7), 2011. The structured-systems view that came
  before the robustness framing.

## The parallel PODC line

- **Vaidya, Tseng & Liang**, "Iterative approximate Byzantine consensus in
  arbitrary directed graphs," PODC 2012. A tight necessary and sufficient
  condition for digraphs, derived independently of the JSAC paper. Reading the
  two side by side shows what r-robustness buys.
- **Dolev, Lynch, Pinter, Stark & Weihl**, "Reaching approximate agreement in
  the presence of faults," *Journal of the ACM* 33(3), 1986. The ancestor of
  every MSR algorithm.
- **Fischer, Lynch & Merritt**, "Easy impossibility proofs for distributed
  consensus problems," *Distributed Computing* 1(1):26–39, 1986,
  doi:10.1007/BF01843568. The source of the 2f+1 connectivity bound. It covers
  the unauthenticated case only, so it is not a source for any §14 bound.

## Graph properties and construction

- **Zhang, Fata & Sundaram**, "A Notion of Robustness in Complex Networks,"
  *IEEE Transactions on Control of Network Systems* 2(3):310–320, 2015.
  Thresholds for robustness in random and preferential-attachment graphs, and
  the proof that deciding whether a graph is robust to a given extent is
  coNP-complete. The extended arXiv version (1203.6119, from CDC 2012) is
  titled "Robustness of Complex Networks with Implications for Consensus and
  Contagion"; the result is the same.
- **Usevitch & Panagou**, "Determining r-Robustness of Digraphs Using Mixed
  Integer Linear Programming," ACC 2019, pp. 2257–2263; extended to
  (r,s)-robustness as "Determining r- and (r,s)-robustness of digraphs using
  mixed integer linear programming," *Automatica* 111, 2020, art. 108586. The
  practical answer to the coNP-completeness above, not its source.
- **Guerrero-Bonilla, Prorok & Kumar**, "Formations for resilient robot teams,"
  *IEEE Robotics and Automation Letters* 2(2), 2017. Formations that keep the
  required robustness while they move.

## Resilient consensus on mobile and flocking systems

- **Saulnier, Saldaña, Prorok, Pappas & Kumar**, "Resilient flocking for mobile
  robot teams," *IEEE Robotics and Automation Letters* 2(2), 2017.
- **Saldaña, Prorok, Sundaram, Campos & Kumar**, "Resilient consensus for
  time-varying networks of dynamic agents," ACC 2017.
- **Park & Hutchinson**, "Fault-tolerant rendezvous of multirobot systems,"
  *IEEE Transactions on Robotics* 33(3), 2017.

## Identity and Sybil resistance

- **Douceur**, "The Sybil Attack," IPTPS 2002. The origin, and still the
  clearest statement of why anonymous membership is fatal.
- **Newsome, Shi, Song & Perrig**, "The Sybil attack in sensor networks:
  analysis & defenses," IPSN 2004. Radio resource testing.
- **Gil, Kumar, Mazumder, Katabi & Rus**, "Guaranteeing Spoof-Resilient
  Multi-Robot Networks," Robotics: Science and Systems XI, 2015, paper 20;
  extended in *Autonomous Robots* 41(6):1383–1400, 2017. Multipath signal
  profiles from a multi-antenna receiver bound how many identities one physical
  transmitter can present, and the bound feeds the control layer. The paper
  closest to AT's position.
- **Wheeler, Bharathi & Gil**, "Switching topology for resilient consensus
  using Wi-Fi signals," ICRA 2019. The follow-on from Gil's group.
- **Yu, Kaminsky, Gibbons & Flaxman**, "SybilGuard," SIGCOMM 2006; and
  **Viswanath, Post, Gummadi & Mislove**, "An analysis of social network-based
  Sybil defenses," SIGCOMM 2010. The second shows that the social-graph defenses
  are all community detection under different names, which names their common
  failure mode. SybilGuard is also where the term "attack edge" comes from.
- **Danev, Zanetti & Čapkun**, "On physical-layer identification of wireless
  devices," *ACM Computing Surveys* 45(1), 2012. RF fingerprinting and its
  limits.

## Blockchain approaches

- **Strobel, Castelló Ferrer & Dorigo**, "Managing Byzantine robots via
  blockchain technology in a swarm robotics collective decision making
  scenario," AAMAS 2018. It works, but its communication and latency
  assumptions do not survive a real radio link.

## Surveys

- **Ishii, Wang & Feng**, "An overview on multi-agent consensus under
  adversarial attacks," *Annual Reviews in Control* 53, 2022. The best single
  entry point to the area.
- **Pasqualetti, Bicchi & Bullo**, "Consensus computation in unreliable
  networks: a system theoretic approach," *IEEE Transactions on Automatic
  Control* 57(1), 2012.

**The gap between the two literatures.** The W-MSR literature and the Sybil
literature barely cite each other. W-MSR papers assume a node can count its
distinct neighbors and that at most F of them are malicious; Sybil papers are
about why that count is unreliable. Gil's work is the main attempt to close the
gap, and it does so through a physical channel property rather than a
cryptographic identity, so its guarantee is probabilistic and tied to one radio
environment. A binding identity needs either a trusted issuer or a costly name
allocation, and neither composes cleanly with an F-bounded threat model. Most of
the open problems sit in that gap.

---

## The dishonest-majority line (§14)

### Bounds

- **Pease, Shostak & Lamport**, "Reaching Agreement in the Presence of Faults,"
  *Journal of the ACM* 27(2):228–234, 1980, doi:10.1145/322186.322188.
  *Used in:* §14.1 (n/3 is the unauthenticated bound, so 3f+1 is the wrong
  theorem for AT), §14.5. *Locator:* §3 (sufficiency for n ≥ 3m+1), §4
  (impossibility for n ≤ 3m), §5 (with authenticators, solvable for any
  n ≥ m ≥ 0). The problem it solves is interactive consistency, where every
  correct processor computes the same vector of everyone's values.
- **Lamport, Shostak & Pease**, "The Byzantine Generals Problem," *ACM
  Transactions on Programming Languages and Systems* 4(3):382–401, 1982,
  doi:10.1145/357172.357176. *Locator:* Theorem 1, p. 390 (oral messages,
  OM(m), for more than 3m generals); Theorem 2, p. 393 (signed messages, SM(m),
  for any number of traitors). "Oral messages" is this paper's term, not the
  1980 paper's.
- **Dolev & Strong**, "Authenticated Algorithms for Byzantine Agreement," *SIAM
  Journal on Computing* 12(4):656–666, 1983, doi:10.1137/0212045. *Used in:*
  §14.1 (with signatures, broadcast for any f < n). *Locator:* the abstract: with
  authentication, agreement on a single transmitter's value takes at least t+1
  rounds, and t+1 rounds with O(nt) messages suffice, with no bound on t. Its
  "Byzantine agreement" is broadcast. It does not state the f < n/2 bound for
  agreement over honest inputs; Fitzi does.
- **Fitzi**, *Generalized Communication and Security Models in Byzantine
  Agreement*, Diss. ETH No. 14761, ETH Zürich, 2002 (often cited as 2003),
  doi:10.3929/ethz-a-004521924. *Used in:* §14.1, "f ≥ n/2: agreement with
  validity is impossible" and "Byzantine agreement still needs f < n/2."
  *Locator:* Proposition 3.1, §3.1, p. 39: consensus among n ≥ 2 players secure
  against t ≥ n/2 active corruptions is impossible. The proof splits the players
  into two input-homogeneous halves, uses nothing about the communication model,
  and so holds with a PKI and with randomization. Theorem 4.17, §4.2, p. 83:
  with a PKI, broadcast is possible for any t < n and consensus if and only if
  t < n/2.

### Detectability, fork consistency, accountability

- **Fitzi, Gottesman, Hirt, Holenstein & Smith**, "Detectable Byzantine
  Agreement Secure Against Faulty Majorities," PODC 2002, pp. 118–126,
  doi:10.1145/571825.571841. *Used in:* §14.1 (detectable agreement, goal (a),
  open question 1). *Locator:* the abstract and §1: detectable broadcast is
  achievable for all t < n. Honest outputs are consistent and may be ⊥; with an
  honest sender the output is the sender's value or ⊥; with no faults it is the
  sender's value. *Model:* synchronous, pairwise authenticated channels, known
  identities, no PKI, no broadcast channel and no trusted setup. The protocols
  are randomized and use a Send-Echo setup phase; the unconditional protocol
  takes t+5 rounds, the computational one t+3 on top of Dolev–Strong. The
  notion is stronger than Lamport's 1983 "weak broadcast" and is not the same
  thing. The paper body is a bitmap scan, so no theorem number is recorded.
- **Mazières & Shasha**, "Building secure file systems out of Byzantine
  storage," PODC 2002, pp. 108–117, doi:10.1145/571825.571840. *Used in:* §14.1
  (fork consistency, goal (c)), §14.3. *Locator:* §4, Definitions 5 (forking
  tree) and 6 (fork consistency). The paragraph after Definition 6 gives the
  guarantee §14.1 relies on: forked clients split into groups "that will never
  again see each others' operations," which out-of-band communication exposes.
  This paper both defines the property and states the guarantee.
- **Li, Krohn, Mazières & Shasha**, "Secure Untrusted Data Repository (SUNDR),"
  OSDI 2004, pp. 121–136 (USENIX, no DOI). *Used in:* §14.1, as the system that
  realizes fork consistency. *Locator:* §3 cites the 2002 paper for the
  definition; §3.2 (the attack is detected if the users ever communicate or see
  each other's later operations); §3.3 (users who signed incompatible version
  structures never again sign compatible ones).
- **Haeberlen, Kuznetsov & Druschel**, "PeerReview: Practical Accountability for
  Distributed Systems," SOSP 2007, pp. 175–188, doi:10.1145/1294261.1294279;
  also *ACM SIGOPS Operating Systems Review* 41(6). The ACM record spells the
  second author "Kouznetsov"; the paper's title page has "Kuznetsov." *Used
  in:* §14.1 (accountability, goal (b)), §14.6's accountability tension.
  *Locator:* §3.4 (completeness and accuracy), §4.3 (assumptions). A node that
  sends observably wrong messages is *exposed* with proof; a node that only
  ignores messages is *suspected*, with no proof. For a detectably faulty node
  the guarantee is that some faulty accomplice of it is eventually exposed or
  forever suspected. *Model:* deterministic state machines, a reference
  implementation, eventual delivery between correct nodes, unforgeable
  signatures, and at least one correct node in each node's witness set.
- **Civit, Gilbert & Gramoli**, "Polygraph: Accountable Byzantine Agreement,"
  IEEE ICDCS 2021, pp. 403–413, doi:10.1109/ICDCS51616.2021.00046. Earlier forms
  are IACR ePrint 2019/587 and a DISC 2020 brief announcement (LIPIcs 179,
  paper 45). *Used in:* §14.1 (accountability). *Locator:* Definition 1, §III;
  Theorem V.2, §V-F. When two honest processes disagree, every honest process
  eventually holds proof of guilt for at least ⌈n/3⌉ processes (t₀+1, with
  t₀ = ⌈n/3⌉−1). *Model:* partial synchrony, an idealized PKI, any t < n
  Byzantine for accountability; agreement and termination hold only for t ≤ t₀.
- **Sheng, Wang, Nayak, Kannan & Viswanath**, "BFT Protocol Forensics," ACM CCS
  2021, pp. 1722–1743, doi:10.1145/3460120.3484566. *Used in:* §14.1
  (accountability). *Locator:* Definition 3.2 ((m,k,d)-forensic support);
  Theorem 4.1 (PBFT with signatures, n = 3t+1: (2t, 1, t+1), so one honest
  transcript proves t+1 culprits when at most 2t are Byzantine, and nothing is
  provable beyond 2t); Theorems 5.1, 7.1, A.1 (HotStuff-view, LibraBFT, VABA).
  PBFT with MACs (Theorem 4.2), HotStuff-null (Theorem 5.3) and Algorand
  (Theorem 6.1) give no useful forensics, and Theorem B.1 rules it out for
  synchronous protocols with n = 2t+1.

### Trust metrics

- **Levien & Aiken**, "Attack-Resistant Trust Metrics for Public Key
  Certification," 7th USENIX Security Symposium, 1998, pp. 229–242 (USENIX, no
  DOI). *Used in:* §14.2, for the attack-cost framework only. *Locator:* §1 (no
  metric resists an attack on d keys or more), §5.4 (edge attacks, bounded by
  d²), §6.1 and §6.3 (the network-flow metric nearly reaches both bounds). It
  bounds how many keys an attacker must compromise to make one victim accept a
  bad key. It does not bound the number of bad nodes accepted.
- **Levien & Aiken**, "An Attack-resistant, Scalable Name Service,"
  unpublished draft, c. 1999 (Levien's draft submission to Financial
  Cryptography 2000), https://levien.com/fc.ps. *Used in:* §14.2, the bounded-Sybil
  property. *Locator:* §3.2, Theorem 1, p. 5: the number of bad servers the
  metric accepts is at most Σ(c_x − 1) over the confused servers x it accepts,
  where c_x is a server's capacity, and so depends only on the confused servers
  and not on the number of bad ones. *Model:* a certificate graph of good,
  confused and bad nodes, no edge from a good node to a bad one, a trusted
  seed, capacities set by distance from the seed, max-flow. Ruderman
  (https://squarefree.com/?p=263, 2005) argues the proof uses the capacities
  after the attack, which lets an attacker gain roughly quadratically.
- **Levien**, *Attack Resistant Trust Metrics*, PhD dissertation draft, UC
  Berkeley, title page 2002, last built 2004, never filed,
  https://levien.com/thesis/. The bound does not appear in it in a usable form:
  the group trust metric chapter is an outline and the §6.1 bound is a stub. Cite
  the name-service draft above, not the thesis.
- **Ziegler & Lausen**, "Spreading Activation Models for Trust Propagation,"
  IEEE International Conference on e-Technology, e-Commerce and e-Service
  (EEE '04), 2004, pp. 83–97, doi:10.1109/EEE.2004.1287293; extended as
  "Propagation Models for Trust and Distrust in Social Networks," *Information
  Systems Frontiers* 7(4–5):337–358, 2005, doi:10.1007/s10796-005-4807-3. Cite
  the journal version. *Used in:* §14.2 (Appleseed). *Locator:* Ziegler's
  thesis, *Towards Decentralized Recommender Systems*, Freiburg 2005, §5.3.3
  item (F.1), p. 84, which is the chapter both papers come from: Appleseed meets
  Levien's bottleneck property, since the trust a node receives depends only on
  its predecessors and does not rise when it adds more nodes. The argument is
  informal. Neither version proves a bound in terms of edges into a Sybil
  region.
- **Kamvar, Schlosser & Garcia-Molina**, "The EigenTrust Algorithm for
  Reputation Management in P2P Networks," WWW 2003, pp. 640–651,
  doi:10.1145/775152.775242. *Used in:* §14.2 (the contrast case). *Locator:*
  §4.1, Eq. 2 (normalized local trust); §4.2–§4.4 and Algorithm 1 (global trust
  as the principal left eigenvector of the normalized matrix); §4.5 (a set of
  pre-trusted peers, mixed in to resist malicious collectives).

### Background cited in §14.5

- **Nakamoto**, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008,
  https://bitcoin.org/bitcoin.pdf. *Locator:* the abstract and §1: secure while
  honest nodes together control more CPU power than any cooperating group of
  attackers. An honest-majority assumption, so it does not help §14.
- **Shamir**, "How to Share a Secret," *Communications of the ACM*
  22(11):612–613, 1979, doi:10.1145/359168.359176. *Locator:* p. 612: in a
  (k,n) threshold scheme any k pieces determine the secret and any k−1 leave it
  completely undetermined, so the scheme holds only while fewer than k
  participants collude.
- **Desmedt & Frankel**, "Threshold Cryptosystems," CRYPTO '89, LNCS 435,
  Springer, 1990, pp. 307–315, doi:10.1007/0-387-34805-0_28. The origin of
  threshold decryption; metadata only, not read for a claim.

### Leaderless Paxos

- **Lamport**, "Brief Announcement: Leaderless Byzantine Paxos," DISC 2011, LNCS
  6950, pp. 141–142, doi:10.1007/978-3-642-24100-0_10; the author's copy
  (https://lamport.azurewebsites.net/pubs/disc-leaderless-web.pdf) carries a
  correction dated 2011-12-27. *Used in:* the "leaderless Byzantine Multi-Paxos"
  wording §13 quotes from `reputation.md`. *Locator:* the whole two pages. A
  virtual leader replaces the real one: each server proposes the leader's next
  message, the servers run a synchronous interactive-consistency algorithm on
  the proposals, and a deterministic rule picks one. Progress needs synchrony.

---

## Claim errors

The R+D sentences below cited a paper for something it does not state, or
stated a bound with no source. The wording given for each was applied to
`R+D.md` on 2026-10-20.

1. **§14.1, accountability bullet.** "when safety *does* break, the protocol
   emits transferable cryptographic proof naming culprits." Each of the three
   papers qualifies this. *Applied:* "when safety does break, honest nodes can
   obtain transferable proof against some of the culprits: at least ⌈n/3⌉ in
   Polygraph, t+1 of at most 2t in the signed PBFT and HotStuff variants Sheng
   et al. analyze, and in PeerReview any node whose wrong messages reach a
   correct node, though a node that only stays silent is suspected without
   proof. Some protocols provably admit no such proof (PBFT with MACs, and any
   synchronous protocol at n = 2t+1)."
2. **§14.1, Dolev–Strong bullet.** "Byzantine *agreement* … still needs
   f < n/2" sits under Dolev–Strong, which is a broadcast result. The statement
   is right. *Applied:* keep it and add "(Fitzi's thesis, ETH 2002, Theorem
   4.17)".
3. **§14.1, "f ≥ n/2: agreement with validity is impossible, under any
   assumptions."** Right, and uncited. *Applied:* add "(Fitzi's thesis,
   Proposition 3.1)".
4. **§14.2, the max-flow paragraph.** "the same property the local max-flow
   trust metrics prove formally (Levien & Aiken's attack-resistant metrics, the
   Advogato/Appleseed family): a malicious collective's accepted membership is
   bounded by the capacity of edges *from honest nodes into it*." The formal
   bound is in Levien and Aiken's unpublished name-service draft, it is stated
   over the capacities of *confused* nodes rather than edges, and its proof is
   disputed; Appleseed's version is informal; and "edges from honest nodes into
   it" is SybilGuard's later attack-edge framing. *Applied:* "the property the
   local max-flow trust metrics aim at (Levien & Aiken's Advogato metric;
   Ziegler & Lausen's Appleseed): a malicious collective's accepted membership
   is bounded by the capacity of the honest-but-confused nodes that vouch for
   it, independently of how many identities it holds. Levien and Aiken state
   this as a theorem in an unpublished draft, with a proof that has been
   disputed; Appleseed argues it informally. A million Sybils behind one
   confused node get that node's capacity, not a million votes."

The fork consistency bullet in §14.1, "(Mazières & Shasha, PODC 2002; realized
in SUNDR)," is correct as written: the 2002 paper defines the property and
states the "permanent and detectable" guarantee, and SUNDR is the system.
