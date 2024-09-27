AutonomousTrust
===============

***AutonomousTrust*** is a high-trust cooperative computing concept --- a data messaging framework that allows for dynamic composibility, requesting and serving encrypted data *only* with trusted peers and only to the extent of that fine-grained trust.
Said trust is dynamically evaluated in real time to rapidly eliminate incoming threats and even reclassify existing peers as their behavior changes and thus protect resources.
Increased risk requires a greater trust threshold.
An autonomous agent using this framework can adaptively: 1) refuse communications from severely untrusted peers, conserving bandwidth; 2) communicate with but refuse computation services to faintly trusted peers, protecting CPU time; 3) offer services but refuse data-sharing to moderately trusted peers, protecting data; _and_ 4) offer data-sharing to well trusted peers; all with a configurable gradient of access at every level, and all within the same application.

In more concrete terms, *AutonomousTrust* is an operations framework for a vast distributed system that dynamically composes numerous individual microservices into a coherent application on-demand -- with security at its core.
We follow the Unix philosophy: do one thing well, work together, use a universal (text) interface; yet implemented such that each microservice can choose its level of participation.


QuickStart
----------

Run `bin/trust-tools emulate` from a bash shell.

Requires:
  * Docker https://www.docker.com/get-started/

The script downloads/installs all required software dependencies into the container(s).


Alternatively, AutonomousTrust can be built as a virtual machine instead of a container.

Run `bin/trust-tools actuate` from a bash shell.

Requires:
  * QEMU https://wiki.qemu.org/Hosts

Downloads/installs (local to working dir):
  * Unikraft
  * pyNaCl
  * libffi

