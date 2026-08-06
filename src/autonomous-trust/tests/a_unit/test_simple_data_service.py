# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
import pytest

from autonomous_trust.simple.data_service import (
    Ident, DataService, ExactService, CloseEnoughService,
    BlindService, FaultyService, BiasedService, DeceitService, ALL_SERVICES,
)


STRUCT = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}


class TestIdent:
    def test_init(self):
        i = Ident('Test')
        assert 'Test' in i.name
        assert i.uuid is not None

    def test_repr(self):
        i = Ident('Foo')
        assert 'Foo' in repr(i)


class TestDataService:
    def test_prob(self):
        p = DataService.prob(4)
        assert len(p) == 4
        assert abs(sum(p) - 1.0) < 0.01

    def test_observables(self):
        obs = DataService.observables(4, 100)
        assert len(obs) == 100
        assert all(1 <= x <= 4 for x in obs)


class TestExactService:
    def test_report(self):
        srv = ExactService(STRUCT)
        report = srv.report()
        assert len(report) > 0
        for obs in report:
            assert isinstance(obs, set)
            assert len(obs) == 1

    def test_send_data(self):
        srv = ExactService(STRUCT)
        data = srv.send_data()
        assert len(data) > 0

    def test_send_report(self):
        srv = ExactService(STRUCT)
        result, ident, elapsed = srv.send_report()
        assert len(result) > 0
        assert isinstance(ident, Ident)
        assert elapsed >= 0


class TestCloseEnoughService:
    def test_report(self):
        srv = CloseEnoughService(STRUCT)
        report = srv.report()
        assert len(report) > 0


class TestBlindService:
    def test_report(self):
        srv = BlindService(STRUCT)
        report = srv.report()
        assert len(report) > 0
        # All observations should be the last category
        for obs in report:
            assert STRUCT[4] in obs


class TestFaultyService:
    def test_report(self):
        srv = FaultyService(STRUCT)
        report = srv.report()
        assert len(report) > 0
        # May be shorter than data length due to dropping


class TestBiasedService:
    def test_report(self):
        srv = BiasedService(STRUCT)
        report = srv.report()
        assert len(report) > 0


class TestDeceitService:
    def test_report(self):
        srv = DeceitService(STRUCT)
        report = srv.report()
        assert len(report) > 0


class TestAllServices:
    def test_all_services_list(self):
        assert len(ALL_SERVICES) == 6
        assert ExactService in ALL_SERVICES
        assert DeceitService in ALL_SERVICES
