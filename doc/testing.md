Testing approach
================

We use _pytest_, either directly <code>python -m tests</code>, or through _tox_. For integration and system testing, we also use _testcontainers_ placing AutonomousTrust in Docker containers.

For capturing code coverage, our containers run test instances (i.e they generate faults), while the code-under-test is a nominal version of AutonomousTrust.



