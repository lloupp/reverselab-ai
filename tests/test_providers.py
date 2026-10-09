"""No external service or real credential is used in these tests."""
import io
import json
import os
import unittest
import urllib.error
from unittest.mock import patch, MagicMock
from reverselab.ai import explain, _model, codex_status, _codex, list_openrouter_models, OPENROUTER_BASE_URL
from reverselab.core import analyze_bytes


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.report = analyze_bytes(b'HELLO_FROM_TEST\x00')

    def test_model_validation_and_arbitrary_slug(self):
        self.assertEqual(_model('anthropic/claude-sonnet-4.5', 'x'),'anthropic/claude-sonnet-4.5')
        self.assertEqual(_model('~openai/gpt-sol-latest', 'x'),'~openai/gpt-sol-latest')
        for invalid in ('../../ --verbose','', 'x'*161):
            with self.subTest(invalid=invalid):
                if not invalid: continue
                with self.assertRaises(ValueError): _model(invalid,'x')

    def test_requires_openrouter_key(self):
        with patch.dict(os.environ, {'OPENROUTER_API_KEY':''}):
            with self.assertRaisesRegex(ValueError, 'OpenRouter'):
                explain(self.report, provider='openrouter', model='test/mock')

    def test_openrouter_auth_header_and_evidence_only(self):
        seen = {}
        answer = {'choices':[{'message':{'content':'Hipótese: é um teste.'}}]}
        def fake_urlopen(request,timeout):
            seen['request']=request
            return io.BytesIO(json.dumps(answer).encode())
        with patch('urllib.request.urlopen',side_effect=fake_urlopen):
            result=explain(self.report, 'Explique', 'openrouter','test/my-model','fake-key-for-test')
        req=seen['request']
        self.assertEqual(result, 'Hipótese: é um teste.')
        self.assertEqual(req.full_url,OPENROUTER_BASE_URL+'/chat/completions')
        self.assertEqual(req.get_header('Authorization'),'Bearer fake-key-for-test')
        body=json.loads(req.data)
        self.assertEqual(body['model'],'test/my-model')
        self.assertNotIn('fake-key-for-test',str(body))
        self.assertNotIn(self.report['sha256'],str(body))

    def test_http_error_does_not_leak_token(self):
        err=urllib.error.HTTPError('https://openrouter.ai/api/v1/chat/completions', 401, 'test-secret-token', {}, None)
        with patch('urllib.request.urlopen',side_effect=err):
            with self.assertRaisesRegex(RuntimeError, 'HTTP 401') as ctx:
                explain(self.report, provider='openrouter',key='test-secret-token')
        self.assertNotIn('test-secret-token',str(ctx.exception))

    def test_codex_missing(self):
        with patch('shutil.which',return_value=None):
            self.assertFalse(codex_status()['installed'])
            with self.assertRaisesRegex(RuntimeError,'Codex CLI'):
                explain(self.report,provider='chatgpt')

    def test_codex_cli_no_shell_read_only(self):
        event={'type':'item.completed','item':{'type':'agent_message','text':'Análise de exemplo concluída.'}}
        proc=MagicMock(returncode=0,stdout=json.dumps(event)+'\n')
        with patch('shutil.which',return_value='/usr/bin/codex'),patch('subprocess.run',return_value=proc) as run:
            self.assertIn('exemplo',_codex([{'content':'Evidências fictícias'}]))
            args=run.call_args.args[0]
            self.assertEqual(args[1:4],['exec','--json','--ephemeral'])
            self.assertIn('read-only',args)
            self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_catalog_fallback(self):
        payload={'data':[{'id':'openai/gpt-4','name':'GPT 4'}]}
        with patch('urllib.request.urlopen',return_value=io.BytesIO(json.dumps(payload).encode())):
            self.assertEqual(list_openrouter_models()[0]['id'],'openai/gpt-4')

if __name__=='__main__':unittest.main()
