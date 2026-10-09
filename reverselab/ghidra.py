"""Opt-in Ghidra Headless adapter. Never executes analyzed binaries."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from .core import MAX_FILE_SIZE, detect

# A single heavyweight Ghidra analysis at a time on 8 GB machines.
_ANALYSIS_LOCK = threading.BoundedSemaphore(1)
_SCRIPT_DIR = Path(__file__).resolve().parent / 'ghidra_scripts'
_ADDRESS = re.compile(r'0x[0-9a-fA-F]{1,16}\Z')
MAX_OUTPUT_BYTES = 2_000_000


class GhidraError(RuntimeError):
    pass


def launcher_path() -> Path | None:
    """Only the administrator sets GHIDRA_INSTALL_DIR or GHIDRA_HEADLESS."""
    configured = os.environ.get('GHIDRA_HEADLESS', '').strip()
    if configured:
        candidate = Path(configured).expanduser()
    else:
        root = os.environ.get('GHIDRA_INSTALL_DIR', '').strip()
        if root:
            candidate = Path(root).expanduser() / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')
        else:
            found = shutil.which('analyzeHeadless')
            candidate = Path(found) if found else None
    if candidate is None or not candidate.is_file():
        return None
    return candidate.resolve()


def ghidra_status() -> dict[str, Any]:
    launcher = launcher_path()
    return {'available': launcher is not None, 'backend': 'Ghidra Headless',
            'message': 'Ghidra disponível para análise aprofundada.' if launcher else
            'Ghidra não encontrado. Configure GHIDRA_INSTALL_DIR ou GHIDRA_HEADLESS para habilitar.'}


def _validated_export(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('functions'), list):
        raise GhidraError('Formato de exportação Ghidra inválido.')
    funcs = []
    for item in data['functions'][:100]:
        if not isinstance(item, dict):
            continue
        address = str(item.get('address', '')).lower()
        if not _ADDRESS.fullmatch(address):
            continue
        name = item.get('name', '')
        raw_calls = item.get('calls', [])
        raw_code = item.get('pseudocode', '')
        if not isinstance(name, str) or not isinstance(raw_calls, list) or not isinstance(raw_code, str):
            continue
        size = item.get('size', 0)
        calls = [x.lower() for x in raw_calls[:48] if isinstance(x, str) and _ADDRESS.fullmatch(x)]
        funcs.append({'name': name[:180], 'address': address,
                      'size': max(0, min(size, 10_000_000)) if isinstance(size, int) else 0,
                      'calls': list(dict.fromkeys(calls)),
                      'pseudocode': raw_code[:5000], 'source': 'Ghidra Headless'})
    known = {f['address'] for f in funcs}
    edges = [{'from': f['address'], 'to': dest} for f in funcs for dest in f['calls'] if dest in known]
    return {'backend': 'Ghidra Headless', 'functions': funcs, 'edges': edges[:600],
            'truncated': bool(data.get('truncated', False) or len(data['functions']) > 100),
            'language': str(data.get('language', ''))[:120],
            'note': 'Pseudocódigo inferido pelo Ghidra; não representa código-fonte original nem prova de comportamento dinâmico.'}


def analyze_with_ghidra(data: bytes, filename: str = 'arquivo.bin', timeout: int = 120) -> dict[str, Any]:
    if not data or len(data) > MAX_FILE_SIZE:
        raise ValueError('Arquivo vazio ou maior que 16 MiB.')
    binary = detect(data)
    if binary['format'] not in ('ELF', 'PE (Windows)'):
        raise ValueError('Análise Ghidra inicialmente disponível somente para ELF e PE válidos.')
    if binary['entry_point'] is None or not binary['sections']:
        raise ValueError('Cabeçalho incompleto: não é seguro solicitar análise aprofundada.')
    launcher = launcher_path()
    if launcher is None:
        raise GhidraError('Ghidra Headless não instalado/configurado. Consulte a documentação.')
    if not _ANALYSIS_LOCK.acquire(blocking=False):
        raise GhidraError('Já existe uma análise Ghidra em execução.')
    try:
        with tempfile.TemporaryDirectory(prefix='reverselab-ghidra-') as dirname:
            tmp = Path(dirname)
            target = tmp / ('sample.exe' if binary['format'] == 'PE (Windows)' else 'sample.elf')
            target.write_bytes(data)
            out = tmp / 'result.json'
            project_dir = tmp / 'projects'
            project_dir.mkdir()
            args = [str(launcher), str(project_dir), 'RLAnalysis', '-import', str(target),
                    '-readOnly', '-deleteProject', '-max-cpu', '2',
                    '-analysisTimeoutPerFile', '50', '-scriptPath', str(_SCRIPT_DIR),
                    '-postScript', 'ReverseLabExport.py', str(out)]
            try:
                proc = subprocess.run(args, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      timeout=max(5, min(int(timeout), 180)), check=False,
                                      encoding='utf-8', errors='replace')
            except subprocess.TimeoutExpired:
                raise GhidraError('Ghidra excedeu o limite de tempo; nenhum resultado parcial foi aceito.') from None
            except OSError:
                raise GhidraError('Não foi possível iniciar Ghidra Headless.') from None
            if proc.returncode != 0 or not out.is_file():
                # Do not leak temporary file paths / file names in Java logs.
                raise GhidraError('A análise Ghidra falhou. Verifique sua instalação e o suporte ao formato.')
            if out.stat().st_size > MAX_OUTPUT_BYTES:
                raise GhidraError('Resultado Ghidra excedeu o limite permitido.')
            try:
                return _validated_export(json.loads(out.read_text(encoding='utf-8')))
            except (ValueError, UnicodeError, OSError) as exc:
                raise GhidraError('Não foi possível interpretar a exportação do Ghidra.') from exc
    finally:
        _ANALYSIS_LOCK.release()
