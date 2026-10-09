"""Agent action loop, grounding, persistence, provider opt-in and safety tests."""
import json
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from reverselab.agent import AgentError, _parse_decision, run_agent
from reverselab.core import analyze_bytes
from reverselab.sandbox import validate_candidate, verify_candidate
from reverselab.store import save_investigation, read_investigation, list_investigations


def demo_report():
    r = analyze_bytes(b'BIN_TEST_ONLY\x00')
    r['deep_analysis'] = {'functions': [
        {'name': 'sum', 'address': '0x401000', 'size': 24, 'calls': ['0x401020'],
         'pseudocode': 'int sum(int a, int b) { return a + b; }'},
        {'name': 'helper', 'address': '0x401020', 'size': 14, 'calls': [],
         'pseudocode': 'int helper(int a, int b) { return a - b; }'}],
         'edges': [{'from': '0x401000', 'to': '0x401020'}]}
    return r


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='reverselab-tests-')
        self.env = patch.dict(os.environ, {'REVERSELAB_DB_PATH': str(Path(self.tmp.name)/'test.sqlite3')})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def _script(self, *steps):
        answers = iter(steps)
        seen = []
        def decide(messages, provider, model, key):
            seen.append(messages)
            return json.dumps(next(answers))
        return decide, seen

    def test_research_tools_and_reconstruction_without_execution(self):
        decide, seen = self._script(
            {'tool': 'list_functions', 'args': {}},
            {'tool': 'inspect_function', 'args': {'address': '0x401000'}},
            {'tool': 'propose_c', 'args': {'address': '0x401000',
                'source': 'int target(int a, int b) { return a + b; }',
                'tests': [{'a': 2, 'b': 3, 'expected': 5}],
                'rationale': 'Pseudocódigo mostra soma.'}},
            {'tool': 'verify_c', 'args': {}},
            {'tool': 'finish', 'args': {'summary': 'Reconstrução hipotética da função sum.'}})
        result = run_agent(demo_report(), 'reconstrua sum', provider='openrouter', model='test/ai',
                           key='fake-only', allow_candidate_tests=False, decide=decide)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['steps_used'], 5)
        self.assertEqual([x['tool'] for x in result['trace']],
                         ['list_functions', 'inspect_function', 'propose_c', 'verify_c', 'finish'])
        self.assertEqual(result['candidate']['verification']['status'], 'not_run')
        self.assertFalse(result['equivalent_to_original'])
        self.assertEqual(len(list_investigations(demo_report()['sha256'])), 1)
        self.assertNotIn('fake-only', json.dumps(result))
        self.assertIn('0x401000', json.dumps(seen[2]))

    def test_agent_traces_calls_and_records_finding(self):
        decide, _ = self._script(
            {'tool': 'trace_calls', 'args': {'address': '0x401020'}},
            {'tool': 'record_finding', 'args': {'address': '0x401020', 'claim': 'Recebe chamada de sum', 'confidence': 'alta'}},
            {'tool': 'finish', 'args': {'summary': 'Grafo investigado.'}})
        result=run_agent(demo_report(),'trace',steps=3,decide=decide)
        self.assertEqual(result['trace'][0]['result']['called_by'], ['0x401000'])
        self.assertTrue(result['trace'][1]['result']['recorded'])
        self.assertEqual(result['status'], 'completed')

    def test_real_openrouter_adapter_contract_with_fake_http(self):
        decisions=iter([
            {'tool':'list_functions','args':{}},
            {'tool':'inspect_function','args':{'address':'0x401000'}},
            {'tool':'propose_c','args':{'address':'0x401000',
             'source':'int target(int a,int b){return a+b;}',
             'tests':[{'a':2,'b':4,'expected':6}],
             'rationale':'O pseudocódigo soma dois inteiros.'}},
            {'tool':'verify_c','args':{}},
            {'tool':'finish','args':{'summary':'Hipótese de soma construída; teste não executado.'}}
        ])
        requests=[]
        def reply(request, timeout):
            data=json.loads(request.data)
            requests.append((data,timeout))
            output=json.dumps(next(decisions))
            return io.BytesIO(json.dumps({'choices':[{'message':{'content':output}}]}).encode())
        with patch('urllib.request.urlopen',side_effect=reply):
            result=run_agent(demo_report(),'Investigar soma',provider='openrouter',model='test/candidate',
                             key='fake-secret',steps=5,persist=False)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(len(requests),5)
        self.assertEqual(requests[0][0]['model'],'test/candidate')
        self.assertIn('list_functions',requests[0][0]['messages'][0]['content'])
        self.assertIn('pseudocódigo',str(result['candidate']['rationale']))
        self.assertEqual(result['candidate']['verification']['status'],'not_run')
        self.assertNotIn('fake-secret',json.dumps(result))

    def test_hallucinated_function_is_rejected(self):
        decide,_=self._script(
            {'tool': 'inspect_function', 'args': {'address': '0x999999'}},
            {'tool': 'finish', 'args': {'summary': 'Não há essa função.'}})
        result=run_agent(demo_report(),'inspect',steps=2,decide=decide,persist=False)
        self.assertIn('não foi encontrada',result['trace'][0]['result']['error'])
        self.assertEqual(result['status'], 'completed')

    def test_arbitrary_shell_tool_blocked(self):
        with self.assertRaises(AgentError):
            _parse_decision('{"tool":"shell","args":{"command":"whoami"}}')
        with self.assertRaises(AgentError):
            _parse_decision('irrelevant unparseable string')
        with self.assertRaises(AgentError):
            _parse_decision('{"tool":"finish","args":{},"extra":1}')

    def test_bad_json_model_can_recover(self):
        answers=iter(['not-json',json.dumps({'tool':'finish','args':{'summary':'Pronto'}})])
        result=run_agent(demo_report(),'foo',steps=2,decide=lambda *args:next(answers),persist=False)
        self.assertEqual(result['trace'][0]['tool'],'invalid_decision')
        self.assertEqual(result['status'],'completed')

    def test_steps_budget_and_invalid_report(self):
        for n in [0,7,True]:
            with self.subTest(n=n), self.assertRaises(AgentError):
                run_agent(demo_report(),'test',steps=n,persist=False)
        with self.assertRaises(AgentError):
            run_agent({'binary': {}},'test',persist=False)

    def test_no_deep_analysis_blocks_reconstruction(self):
        r=analyze_bytes(b'GENERIC_BINARY')
        decide,_=self._script({'tool':'propose_c','args':{'address':'0x401000',
                                'source':'int target(int a,int b){return a+b;}',
                                'tests':[{'a':1,'b':2,'expected':3}], 'rationale':'test'}},
                              {'tool':'finish','args':{'summary':'Não há evidências.'}})
        result=run_agent(r,'test',steps=2,decide=decide,persist=False)
        self.assertEqual(result['candidate'],None)
        self.assertIn('não foi encontrada',result['trace'][0]['result']['error'])

    def test_history_does_not_persist_tokens(self):
        report=demo_report()
        decide,_=self._script({'tool':'finish','args':{'summary':'acabou'}})
        out=run_agent(report,'test',provider='openrouter',key='secret-only-in-request',decide=decide)
        record=read_investigation(out['investigation_id'])
        self.assertEqual(record['provider'],'openrouter')
        self.assertNotIn('secret-only-in-request',json.dumps(record))
        with self.assertRaises(ValueError):
            list_investigations('ABC')
        self.assertIsNone(read_investigation('a'*32))


class SandboxTests(unittest.TestCase):
    SOURCE='int target(int a, int b) { return a+b; }'
    CASES=[{'a':2,'b':3,'expected':5}, {'a':-1,'b':2,'expected':1}]

    def test_default_never_executes(self):
        with patch('subprocess.run') as run:
            result=verify_candidate(self.SOURCE,self.CASES)
        self.assertEqual(result['status'],'not_run')
        run.assert_not_called()

    def test_docker_missing_no_host_execution(self):
        with patch('shutil.which',return_value=None),patch('subprocess.run') as run:
            result=verify_candidate(self.SOURCE,self.CASES,approved=True)
        self.assertEqual(result['status'],'unavailable')
        run.assert_not_called()

    def test_docker_isolation_parameters(self):
        mock=MagicMock(returncode=0,stdout='PASS 0\nPASS 1\n',stderr='')
        with patch('shutil.which',return_value='/usr/bin/docker'),patch('subprocess.run',return_value=mock) as run:
            result=verify_candidate(self.SOURCE,self.CASES,approved=True)
        self.assertEqual(result['status'],'self_tests_passed')
        self.assertFalse(result['equivalent_to_original'])
        argv=run.call_args.args[0]
        self.assertIn('--network=none',argv)
        self.assertIn('--read-only',argv)
        self.assertIn('--pull=never',argv)
        self.assertIn('--cap-drop=ALL',argv)
        self.assertIn('--memory=256m',argv)
        self.assertIn('--user=65534:65534',argv)
        self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_invalid_tests_and_large_source(self):
        with self.assertRaises(ValueError):
            validate_candidate(self.SOURCE,[{'a':True,'b':1,'expected':1}])
        with self.assertRaises(ValueError):
            validate_candidate('X'*12001,self.CASES)
        with self.assertRaises(ValueError):
            validate_candidate(self.SOURCE,[])


if __name__=='__main__': unittest.main()
