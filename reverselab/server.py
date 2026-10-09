"""Private loopback-only web server exposing byte inspection and local LLM."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .ai import explain, local_url, codex_status, list_openrouter_models
from .core import MAX_FILE_SIZE, analyze_bytes

STATIC = Path(__file__).parent/'static'
MAX_JSON_SIZE = 128*1024


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status: int, payload: bytes, mime: str) -> None:
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError,ConnectionResetError):
            pass

    def _json(self, status: int, obj: object) -> None:
        self._reply(status,json.dumps(obj,ensure_ascii=False).encode('utf-8'),'application/json; charset=utf-8')

    def do_GET(self) -> None:
        route=urlsplit(self.path).path
        if route=='/api/status':
            try:
                endpoint=local_url()
            except ValueError:
                endpoint='Endpoint inválido'
            self._json(200,{'status':'online','version':'0.2.0','max_file_size':MAX_FILE_SIZE,
                             'ai_endpoint':endpoint,'codex':codex_status(),
                             'providers':['local','openrouter','chatgpt'],
                             'note':'Provedores externos recebem somente evidências e apenas sob clique.'})
            return
        if route=='/api/models':
            try:
                self._json(200,{'models':list_openrouter_models()})
            except RuntimeError as exc:
                self._json(503,{'error':str(exc)})
            return
        resources={'/':('index.html','text/html; charset=utf-8'),
                   '/app.js':('app.js','text/javascript; charset=utf-8'),
                   '/style.css':('style.css','text/css; charset=utf-8')}
        if route not in resources:
            self._json(404,{'error':'Rota não encontrada.'})
            return
        name,mime=resources[route]
        self._reply(200,(STATIC/name).read_bytes(),mime)

    def _read_body(self, limit:int) -> bytes | None:
        length=self.headers.get('Content-Length','')
        if not length.isdecimal():
            self._json(411,{'error':'Content-Length obrigatório.'})
            return None
        size=int(length)
        if size < 1:
            self._json(400,{'error':'Corpo vazio.'})
            return None
        if size>limit:
            self._json(413,{'error':f'Limite: {limit} bytes.'})
            return None
        body=self.rfile.read(size)
        if len(body)!=size:
            self._json(400,{'error':'Arquivo incompleto.'})
            return None
        return body

    def do_POST(self) -> None:
        # Deny browser cross-origin requests to this loopback-only service.
        origin=self.headers.get('Origin')
        if origin and origin not in (f'http://127.0.0.1:{self.server.server_port}',
                                    f'http://localhost:{self.server.server_port}'):
            self._json(403,{'error':'Origin não autorizado.'})
            return
        parts=urlsplit(self.path)

        if parts.path=='/api/analyze':
            if self.headers.get('Content-Type','').split(';')[0] != 'application/octet-stream':
                self._json(415,{'error':'Envie bytes com Content-Type application/octet-stream.'})
                return
            body=self._read_body(MAX_FILE_SIZE)
            if body is None:
                return
            filename=parse_qs(parts.query).get('filename',['arquivo.bin'])[0]
            try:
                self._json(200,analyze_bytes(body,filename))
            except (ValueError,TypeError) as ex:
                self._json(400,{'error':str(ex)})
            return
        if parts.path=='/api/explain':
            if self.headers.get('Content-Type','').split(';')[0] != 'application/json':
                self._json(415,{'error':'JSON obrigatório.'})
                return
            body=self._read_body(MAX_JSON_SIZE)
            if body is None:
                return
            try:
                message=json.loads(body)
                report=message['report']
                # Validate minimum shape, since all messages are browser-controlled.
                if not isinstance(report,dict) or not all(x in report for x in ('binary','strings','disassembly','observations','size')):
                    raise ValueError('Relatório inválido.')
                provider=message.get('provider','local')
                model=message.get('model','')
                key=message.get('api_key','')
                if not all(isinstance(v,str) for v in (provider,model,key)):
                    raise ValueError('Configurações de provedor inválidas.')
                result=explain(report,str(message.get('question','')),provider,model,key)
                self._json(200,{'explanation':result,'backend':provider,'model':model or '(padrão)'})
            except (ValueError,TypeError,KeyError,IndexError,RuntimeError) as ex:
                self._json(400,{'error':str(ex)[:700]})
            except Exception as ex:
                self._json(502,{'error':'Falha ao consultar IA: '+str(ex)[:300]})
            return
        self._json(404,{'error':'Rota não encontrada.'})

    def log_message(self, fmt: str, *args: object) -> None:
        # no filenames in logs by default
        if ' 200 ' not in (fmt % args):
            super().log_message(fmt,*args)


def serve(port:int=8765) -> None:
    if not 1024<=port<=65535:
        raise ValueError('Escolha uma porta entre 1024 e 65535.')
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.daemon_threads=True
    print(f'ReverseLab AI em http://127.0.0.1:{port} (somente nesta máquina)',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
