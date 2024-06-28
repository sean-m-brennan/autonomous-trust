# Copyright (C) 2024 tekfive

import guidance.core as gdnc_core


class WatchTeam(gdnc_core.Mode):

    def __init__(self, guidance, name):
        super().__init__(guidance, name)
        self.loop = self.guidance.get_loop()

    def shutdown(self):
        self.loop = None

    def get_triggers(self):
        return (gdnc_core.Trigger.TIMER, 30, 30)

    def configure(self, msg, disable_oa, override_fcam, override_stereo):
        pass

    def enter(self):
        pass

    def exit(self):
        pass

    def begin_step(self):
        pass

    def end_step(self):
        pass

    def generate_drone_reference(self):
        pass

    def correct_drone_reference(self):
        pass

    def generate_attitude_reference(self):
        pass


GUIDANCE_MODES = {"com.tekfive.missions.sparverius.watch_team": WatchTeam}