# CONOPS


## Objectives

Primary: Seek and destroy a hidden mobile target with surgical precision - meaning no collateral damage and (preferably) delayed notice.

Secondary: Do so with plausible deniability.


## Strategy

Due to comprehensive air and ground defenses, not to mention considerable uncertainty with respect to the target's location, a frontal assault would certainly moot the secondary objective and strongly jeopardize the first.

Therefore, a single infiltration team will be sent in with tiered, stealth and/or non-attributable ISR support. This also necessitates *electronic* stealth as well as audiovisual.

## Participants

### Ground assets (< 1000 ft)

1. 12-man team
2. Several recon microdrones (high bandwidth, tight-beam)
3. Man-carried ISR fusion platforms
4. Pre-populated local ISR (friendly)
5. Spontaneous local ISR (bot-netted enemy)

### Direct-link aerospace assets

6. Low bandwidth, intermittent ELEO uplink to SOCOM
7. Medium-high bandwidth RQ-series drone (2)

### Indirect-link assets

8. High bandwidth orbital ISR platforms
9. High bandwidth, high-latency computation platforms


## Authorities / Responsibilities

### In-situ

Voice and data exfiltration is risky and intermittent at best, therefore the team leader has full local decision authority from team infil to exfil.

Team specialists (#1 via #3) are responsible for data fusion from numerous ISR sources. They have the authority to call on any available source with maximum priority, including emergency (noisy) voice comms.

Microdrones (#2) protect themselves from detection and electronic countermeasures. They are also responsible for their own path-finding guidance (often following team members) to free team specialists from constant control. This of course can be overridden at any time to perform specific functions.

### Remote

RQ-series drones (#7) also protect themselves from detection and countermeasures. They provide a broad view of the environment in a wide variety of modalities. They may additionally emit their own electronic countermeasures on request. These drones also serve as a gateway to more remote assets such as #8 and #9.

All other assets are required to maximally prioritize any requests from the team for the duration of the operation.

## Operations

The enemy is presumed to be at a peer-level or better. The infil team will be hunted and all outbound transmissions intercepted and tracked. Maximizing both situational awareness and stealth are critical to mission success, but are at odds with each other. Friendly local ISR (#9) may be corrupted and enemy local ISR (#10) may yield false feeds. Overhead support (#7, #6) may be neutralized or falsified. Yet reliable reconnaissance is crucial; therefore the ability to discern trustworthy data is primary. Participants must have high-trust established wherever possible, or be subject to persistent (automated) scrutiny if not possible (such as #9, #10).

The mission's geographic pathway is a traveling-salesman problem with unpredictable obstacles, an NP-hard problem that cannot be precomputed. All remote operator and AI-controlled platforms must be responsive to suddenly changing conditions.

## Process

### Preparation

To facilitate man-machine and machine-to-machine cooperation and trust, all known participants will engage in pre-mission training. Wherever possible and/or advisable, participants should know one-another from previous missions as well. Caveats to this guidance includes pairings with low machine-trust metrics.  

### Execution-time

The ground participants will initially follow a pre-planned route based on prior intelligence. However, the team lead may, at his discretion, change routes or targeted locations, or split-up the team. Once the target has been destroyed, the team will, together or in groups, travel to one (or more) of several exfiltration points.

Due to the need for stealth, failure to locate the target within the allotted time span will end the mission and trigger exfiltration. 

Pre-populated assets are unreliable, but may collectively contribute significantly to locating the target via SIGINT and HUMINT.

Near overhead platforms will track all ground participants whenever possible, manoeuvring as needed. Maintaining line-of-sight is very important to facilitate minimally-radiative communications.

Likewise, ELEO assets should be scheduled, or scheduled around, to maximize availability for the duration of the mission (note: these sats have a very low period, and thus short engagement time). ELEO cubesat comms is necessarily noisy, so its use is discouraged.


## Post-mission

Machine-debrief at base will consist of uploading all locally-streamed (single-hop) data for review. Lessons learned will be incorporated into the software stack.


# Addendum

## Telemetry list

*NB:* all comms encrypted and spread spectrum

#### All

   - negotiation streams
   - reputation gossip

#### Microdrones
   - Flight sensors
      - barometer
      - battery
      - GPS
      - IMU
      - magnetometer
      - motors
      - TOF

   - Flight data
      - altitude
      - angles
      - position
      - velocity

   - Camera stabilization
      - angles
      - position

   - Camera settings

   - Video
      - front
      - down
      - stereo
      - disparity
      - depth map
      - depth from motion
      - occupancy grid
   
   - Optional
      - acoustic
      - IR
      - night vision

#### RQ-series
   - electro-optical
   - infrared
   - synthetic aperture radar (SAR)
   - moving target indication (MTI) radar
   - high and low band SIGINT sensors
   - EQ-4 communication relay
   - ECM
   - laser data transfer

#### ELEO cubesat
   - low band emergency signalling  
