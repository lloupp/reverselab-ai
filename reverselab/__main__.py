"""ReverseLab command line."""
import argparse
import json
import sys
from pathlib import Path
from .core import MAX_FILE_SIZE, analyze_bytes, markdown_report


def main(argv=None) -> int:
    cli=argparse.ArgumentParser(prog='python -m reverselab',description='Análise estática de binários sem executá-los.')
    subs=cli.add_subparsers(dest='command',required=True)
    run=subs.add_parser('analyze',help='Analisar um arquivo offline')
    run.add_argument('file',type=Path)
    run.add_argument('--format',choices=('json','md'),default='md')
    run.add_argument('--output',type=Path)
    web=subs.add_parser('serve',help='Iniciar interface web local')
    web.add_argument('--port',type=int,default=8765)
    a=cli.parse_args(argv)
    if a.command=='serve':
        from .server import serve
        serve(a.port)
        return 0
    try:
        if a.file.stat().st_size > MAX_FILE_SIZE:
            raise ValueError(f'Limite de {MAX_FILE_SIZE//1024//1024} MiB.')
        data=a.file.read_bytes()
        report=analyze_bytes(data,a.file.name)
        output=(json.dumps(report,ensure_ascii=False,indent=2)+'\n') if a.format=='json' else markdown_report(report)
        if a.output:
            a.output.write_text(output,encoding='utf-8')
            print(f'Relatório salvo em {a.output}')
        else:
            print(output)
        return 0
    except (OSError,ValueError) as ex:
        print(f'Erro: {ex}',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
