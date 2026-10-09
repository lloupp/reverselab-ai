"""Optional Docker-only candidate testing. Never run original executables.

This is *not* a strong security boundary against kernel/container escape exploits.
For adversarial binaries or generated programs prefer an isolated VM. A Docker
image is never pulled implicitly and no unsandboxed execution fallback exists.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MAX_C_SOURCE = 12_000
IMAGE = 'gcc:13'


class SandboxUnavailable(RuntimeError):
    pass


def sandbox_status() -> dict[str, Any]:
    available = bool(shutil.which('docker'))
    return {'available': available, 'backend': 'Docker (sem execução automática)',
            'message': 'Docker CLI encontrado; exige imagem gcc:13 já presente e confirmação do usuário.' if available else
                       'Docker não encontrado; geração de código disponível, execução de testes indisponível.'}


def validate_candidate(source: str, tests: list[Any]) -> list[dict[str, int]]:
    """Restrict the demo reconstruction to int target(int,int), not arbitrary scripts."""
    if not isinstance(source, str) or not source.strip() or len(source) > MAX_C_SOURCE or '\x00' in source:
        raise ValueError('Código C vazio ou acima do limite de 12 mil caracteres.')
    if not isinstance(tests, list) or not (1 <= len(tests) <= 8):
        raise ValueError('Forneça entre 1 e 8 casos de teste.')
    checked = []
    for row in tests:
        if not isinstance(row, dict) or set(row) != {'a', 'b', 'expected'}:
            raise ValueError('Formato de teste esperado: {a, b, expected}.')
        values = {}
        for key in ('a', 'b', 'expected'):
            value = row[key]
            if type(value) is not int or not (-100_000 <= value <= 100_000):
                raise ValueError('Argumentos dos testes devem ser inteiros entre -100000 e 100000.')
            values[key] = value
        checked.append(values)
    return checked


def _test_harness(tests: list[dict[str, int]]) -> str:
    cases = ',\n'.join('{%d,%d,%d}' % (r['a'], r['b'], r['expected']) for r in tests)
    return ('\n#include <stdio.h>\n'
            'extern int target(int a, int b);\n'
            'struct test {int a,b,want;};\n'
            'int main(void) {\n'
            f'  const struct test cases[] = {{{cases}}};\n'
            '  int failed = 0;\n'
            '  for (unsigned i=0; i<sizeof(cases)/sizeof(cases[0]); ++i) {\n'
            '    int got=target(cases[i].a,cases[i].b);\n'
            '    if (got!=cases[i].want) { ++failed; printf("FAIL %u: got %d expected %d\\n",i,got,cases[i].want); }\n'
            '    else printf("PASS %u\\n",i);\n'
            '  }\n'
            '  return failed ? 1 : 0;\n}\n')


def verify_candidate(source: str, tests: list[dict[str, int]], *, approved: bool = False,
                     timeout: int = 18) -> dict[str, Any]:
    """Compile+run only explicitly approved *generated* C, inside Docker.

    Passing cases supplied by an LLM means *self-consistency only*, NOT equivalence
    with the unavailable original source or the original executable.
    """
    checked = validate_candidate(source, tests)
    if not approved:
        return {'status': 'not_run', 'reason': 'Execução requer autorização explícita na interface.',
                'tests': len(checked), 'equivalent_to_original': False}
    docker = shutil.which('docker')
    if not docker:
        return {'status': 'unavailable', 'reason': 'Docker não instalado; sem fallback fora da sandbox.',
                'tests': len(checked), 'equivalent_to_original': False}
    with tempfile.TemporaryDirectory(prefix='reverselab-test-') as tmp_dir:
        filename = Path(tmp_dir) / 'candidate.c'
        filename.write_text(source + '\n' + _test_harness(checked), encoding='utf-8')
        try:
            os.chmod(filename, 0o644)
            args = [docker, 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=32',
                    '--memory=256m', '--cpus=1', '--user=65534:65534',
                    '--tmpfs', '/tmp:rw,exec,nosuid,size=32m',
                    '--mount', f'type=bind,src={filename.resolve()},dst=/src/candidate.c,readonly',
                    '-w', '/tmp', IMAGE, 'sh', '-c',
                    'gcc -std=c11 -O0 -Wall -Wextra /src/candidate.c -o /tmp/reverselab-test && /tmp/reverselab-test']
            proc = subprocess.run(args, capture_output=True, text=True, timeout=min(30, max(5, timeout)),
                                  check=False, encoding='utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'reason': 'Teste isolado excedeu tempo limite.',
                    'tests': len(checked), 'equivalent_to_original': False}
        except OSError:
            return {'status': 'unavailable', 'reason': 'Não foi possível iniciar Docker.',
                    'tests': len(checked), 'equivalent_to_original': False}
        # Do not forward potentially secret-bearing Docker failure paths to UI.
        lines = [x[:120] for x in proc.stdout.splitlines() if x.startswith(('PASS ', 'FAIL '))][:8]
        passed = sum(x.startswith('PASS ') for x in lines)
        status = 'self_tests_passed' if proc.returncode == 0 and passed == len(checked) else 'failed'
        return {'status': status, 'passed': passed, 'tests': len(checked), 'details': lines,
                'reason': 'Casos declarados passaram; equivalência com o binário original NÃO comprovada.' if status == 'self_tests_passed' else
                          'Compilação, ambiente ou testes falharam (detalhes internos suprimidos).',
                'equivalent_to_original': False}
