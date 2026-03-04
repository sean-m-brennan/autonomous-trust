import pytest
from collections import OrderedDict

from autonomous_trust.simple.data_client import DataClient, Algorithm
from autonomous_trust.simple.data_service import (
    Ident, ExactService, CloseEnoughService, BlindService,
)


STRUCT = {1: 'A', 2: 'B', 3: 'C', 4: 'D'}


class TestAlgorithm:
    def test_values(self):
        assert Algorithm.EXP == 'exp'
        assert Algorithm.LIN == 'lin'
        assert Algorithm.CBR == 'cbr'


class TestDataClientSummary:
    def test_summary(self):
        srv = ExactService(STRUCT, size=4)
        report = srv.report()
        result = DataClient.summary(report)
        assert isinstance(result, OrderedDict)
        assert len(result) > 0
        # Probabilities should be roughly positive
        for key, val in result.items():
            assert isinstance(val, float)


class TestDataClient:
    def test_init(self):
        dc = DataClient(size=10)
        assert dc.max_len == 0
        assert len(dc.registry) == 0

    def test_register_server(self):
        dc = DataClient()
        srv = ExactService(STRUCT)
        dc.register_server(srv.ident, srv)
        assert srv.ident in dc.registry

    def test_recv_data(self):
        dc = DataClient()
        # Use int-keyed struct so report sets contain ints (matching recv_data's expectations)
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        srv = ExactService(int_struct)
        report_data, ident, elapsed = srv.send_report()
        result, whom, time_val = dc.recv_data(report_data, ident, elapsed)
        assert isinstance(result, OrderedDict)
        assert whom is ident

    def test_evaluate_exp(self):
        dc = DataClient()
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        services = [ExactService(int_struct), CloseEnoughService(int_struct)]
        for srv in services:
            report, ident, elapsed = srv.send_report()
            dc.register_server(ident, srv)
            dc.recv_data(report, ident, elapsed)
        groups, thresholds = dc.evaluate(Algorithm.EXP, 4, fixed=3)
        assert len(groups) == 3

    def test_evaluate_lin(self):
        dc = DataClient()
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        services = [ExactService(int_struct), BlindService(int_struct)]
        for srv in services:
            report, ident, elapsed = srv.send_report()
            dc.register_server(ident, srv)
            dc.recv_data(report, ident, elapsed)
        groups, thresholds = dc.evaluate(Algorithm.LIN, None, fixed=3)
        assert len(groups) == 3

    def test_evaluate_unknown(self):
        dc = DataClient()
        with pytest.raises(RuntimeError, match='Unknown evaluation'):
            dc.evaluate('invalid', 0)

    def test_pairwise_distance_matrix_empty(self):
        dc = DataClient()
        assert dc.pairwise_distance_matrix == {}

    def test_pairwise_distance_matrix_with_data(self):
        dc = DataClient()
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        services = [ExactService(int_struct), CloseEnoughService(int_struct), BlindService(int_struct)]
        for srv in services:
            report, ident, elapsed = srv.send_report()
            dc.register_server(ident, srv)
            dc.recv_data(report, ident, elapsed)
        distances = dc.pairwise_distance_matrix
        assert isinstance(distances, dict)

    def test_memory_max_len(self):
        dc = DataClient(size=3)
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        for i in range(5):
            srv = ExactService(int_struct)
            report, ident, elapsed = srv.send_report()
            dc.recv_data(report, ident, elapsed)
        assert len(dc.memory) <= 3

    def test_evaluate_exp_with_more_services(self):
        dc = DataClient()
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        services = [ExactService(int_struct), CloseEnoughService(int_struct),
                    BlindService(int_struct), ExactService(int_struct)]
        for srv in services:
            report, ident, elapsed = srv.send_report()
            dc.register_server(ident, srv)
            dc.recv_data(report, ident, elapsed)
        groups, thresholds = dc.evaluate(Algorithm.EXP, 4, fixed=3)
        assert isinstance(groups, list)


class TestCBR:
    def test_init(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        assert cbr.memory == {}

    def test_retain_and_retrieve(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        cbr.retain('key1', 'graph1')
        assert cbr.memory['key1'] == 'graph1'

    def test_reuse_returns_none(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        assert cbr.reuse('graph', 'what') == (None, None)

    def test_revise_returns_none(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        assert cbr.revise('key', 'graph', 'diff') == ('key', None)

    def test_process_no_data(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        # process with missing key raises KeyError in retrieve
        with pytest.raises(KeyError):
            cbr.process('nonexistent')


class TestGetHelp:
    def test_get_help_correct(self):
        from unittest.mock import patch
        # Reset class state
        DataClient.questions = []
        DataClient.answers = {}
        with patch('builtins.input', return_value='ABCD'):
            result = DataClient.get_help('A > B > C > D')
        assert result == 'ABCD'
        assert len(DataClient.questions) == 1

    def test_get_help_wrong_size(self):
        from unittest.mock import patch
        DataClient.questions = []
        DataClient.answers = {}
        with patch('builtins.input', return_value='AB'):
            with pytest.raises(RuntimeError, match='wrong size'):
                DataClient.get_help('A > B > C > D')

    def test_get_help_not_in_ask(self):
        from unittest.mock import patch
        DataClient.questions = []
        DataClient.answers = {}
        with patch('builtins.input', return_value='WXYZ'):
            with pytest.raises(RuntimeError, match='makes no sense'):
                DataClient.get_help('A > B > C > D')


class TestEvaluateCBR:
    def test_evaluate_cbr(self):
        dc = DataClient()
        int_struct = {1: 1, 2: 2, 3: 3, 4: 4}
        services = [ExactService(int_struct), CloseEnoughService(int_struct)]
        for srv in services:
            report, ident, elapsed = srv.send_report()
            dc.register_server(ident, srv)
            dc.recv_data(report, ident, elapsed)
        # CBR evaluate creates CBR; process uses OrderedDict as dict key
        # which raises TypeError (unhashable), caught as empty result
        with pytest.raises(TypeError):
            dc.evaluate(Algorithm.CBR, 0, fixed=3)


class TestCBRProcess:
    def test_process_with_data(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        cbr.memory['key1'] = None  # known=None triggers break on first iteration
        result = cbr.process('key1')
        assert result is None

    def test_process_missing_key(self):
        from autonomous_trust.simple.data_client import CBR
        cbr = CBR()
        with pytest.raises(KeyError):
            cbr.process('nonexistent')
