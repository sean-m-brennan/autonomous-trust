#!/bin/sh

cp -a ../src/autonomous-trust/autonomous_trust/core autonomous_trust/
cp -a ../src/autonomous-trust/autonomous_trust/__main__.py autonomous_trust/
cp -a ../src/autonomous-trust-services/autonomous_trust/services autonomous_trust/
cp -a ../src/autonomous-trust-inspector/autonomous_trust/inspector autonomous_trust/
cp -a ../src/autonomous-trust-simulator/autonomous_trust/simulator autonomous_trust/
mkdir -p ../examples/mission/coordinator/var
mkdir -p ../examples/mission/participant/var
mkdir -p ../examples/mission/simulator/etc
