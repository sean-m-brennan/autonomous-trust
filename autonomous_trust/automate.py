import os
import time

CFG_VAR_NAME = 'AUTONOMOUS_TRUST_CONFIG'
CFG_DEFAULT = os.path.join('etc', 'at')


def banner():
    print("")
    print("You are using\033[94m AutonomousTrust\033[00m from\033[96m TekFive\033[00m.")
    print("")


def configure():
    for cfg in os.listdir(os.environ.get(CFG_VAR_NAME, '/' + CFG_DEFAULT)):
        pass
        # TODO initialize AT per configuration files in os.environ["AUTONOMOUS_TRUST_CONFIG"] or /etc
    print("Configuring for (unknown domain)")
    return ['communications', 'reputation', 'computing services', 'data services']


def main():
    banner()
    procs = configure()
    for proc in procs:
        # TODO start child processes (comms, sensors, data-processing, etc)
        print("Starting %s ..." % proc)
    try:
        print('                                        Ready.')
        i = 0
        while True:
            # TODO run forever unless signalled
            if i > 1000:
                break
            time.sleep(0.1)
            i += 1
    except KeyboardInterrupt:
        pass
    for proc in reversed(procs):
        # TODO clean up
        print("Halting %s" % proc)
    print("Shutdown")
