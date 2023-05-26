from ..conftest import QuickTrust, Configuration


def run_nominal(mp=True, debug=False, runtime=None):
    at = QuickTrust(runtime=runtime, multiproc=mp, logfile=Configuration.log_stdout)
    at.debug = debug
    at.run_forever()
    return at


######################
# Tests:

def test_multiproc_nominal(setup_local_net_teardown):
    at = run_nominal(True)
    assert len(at.exceptions) == 0


def test_threading_nominal(setup_local_net_teardown):
    at = run_nominal(False)
    assert len(at.exceptions) == 0

# FIXME test pathologies
