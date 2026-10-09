import contextlib
import json
import os
import socket
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch

from reverselab.ai import explain_with_local_llm,local_url
from reverselab.core import analyze_bytes
from reverselab.server import Handler


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True)
        cls.thread.start()
        cls.url=f'http://127.0.0.1:{cls.http.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join(timeout=2)

    def request(self, method,path,body=None,ctype=None):
        hdr={'Content-Type':ctype} if ctype else {}
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url+path,body,hdr,method=method),timeout=4) as res:
                return res.status,res.read(),dict(res.headers)
        except urllib.error.HTTPError as e:
            return e.code,e.read(),dict(e.headers)

    def test_static_ui_and_status(self):
        code,body,headers=self.request('GET','/')
        self.assertEqual(code,200)
        self.assertIn(b'ReverseLab AI',body)
        self.assertIn('Content-Security-Policy',headers)
        code,body,_=self.request('GET','/api/status')
        self.assertEqual(json.loads(body)['status'],'online')

    def test_binary_upload(self):
        code,body,_=self.request('POST','/api/analyze?filename=test.bin',b'ABCD SAMPLE_STRING','application/octet-stream')
        self.assertEqual(code,200)
        self.assertEqual(json.loads(body)['filename'],'test.bin')

    def test_rejected_content_type_and_size(self):
        code,body,_=self.request('POST','/api/analyze',b'ABC','text/plain')
        self.assertEqual(code,415)
        # Announce an excessive length without transmitting a huge request body.
        import http.client
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=4)
        c.putrequest('POST','/api/analyze')
        c.putheader('Content-Type','application/octet-stream')
        c.putheader('Content-Length',str(16*1024*1024+1))
        c.endheaders()
        response=c.getresponse()
        self.assertEqual(response.status,413)
        response.read()
        c.close()
        code,body,_=self.request('GET','/not-found')
        self.assertEqual(code,404)


class LocalAiTests(unittest.TestCase):
    def test_rejects_remote_urls(self):
        for x in ('https://api.somewhere.example/v1','http://192.168.1.5:8002/v1',
                  'http://127.0.0.1:8002/v1@evil.example'):
            with self.subTest(url=x),patch.dict(os.environ,{'REVERSELAB_LLM_BASE_URL':x}):
                with self.assertRaises(ValueError): local_url()

    def test_mock_openai_local_endpoint(self):
        class Mock(BaseHTTPRequestHandler):
            seen=None
            def do_POST(self):
                self.server.seen=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                content=json.dumps({'choices':[{'message':{'content':'Observação: foram encontradas strings; sem execução.'}}]}).encode()
                self.send_response(200); self.send_header('Content-Length',str(len(content))); self.end_headers();self.wfile.write(content)
            def log_message(self,*args):pass
        srv=ThreadingHTTPServer(('127.0.0.1',0),Mock)
        th=threading.Thread(target=srv.serve_forever,daemon=True);th.start()
        try:
            r=analyze_bytes(b'TEST_12345\x00')
            with patch.dict(os.environ,{'REVERSELAB_LLM_BASE_URL':f'http://127.0.0.1:{srv.server_port}/v1','REVERSELAB_MODEL':'mock'}):
                answer=explain_with_local_llm(r,'Explique este teste')
                self.assertIn('Observação',answer)
                self.assertEqual(srv.seen['model'],'mock')
                self.assertEqual(srv.seen['messages'][0]['role'],'system')
                self.assertNotIn(r['sha256'],json.dumps(srv.seen))
        finally:
            srv.shutdown();srv.server_close();th.join(timeout=2)


if __name__=='__main__':unittest.main()
