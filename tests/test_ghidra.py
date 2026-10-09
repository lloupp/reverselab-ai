"""Ghidra contract tests. Tests do NOT require a Ghidra installation."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverselab.ai import _evidence
from reverselab.core import analyze_bytes
from reverselab.ghidra import GhidraError, _validated_export, analyze_with_ghidra, ghidra_status


EXPORT = {
    'schema_version': 1, 'backend': 'Ghidra Headless', 'language': 'x86:LE:64:default',
    'functions': [
        {'name': 'main', 'address': '0x401100', 'size': 50, 'calls': ['0x401200'],
         'pseudocode': 'int main() { return helper(); }'},
        {'name': 'helper', 'address': '0x401200', 'size': 16, 'calls': [],
         'pseudocode': 'int helper() { return 42; }'},
    ],
}


class ExportTests(unittest.TestCase):
    def test_function_graph(self):
        result = _validated_export(EXPORT)
        self.assertEqual(len(result['functions']), 2)
        self.assertEqual(result['edges'], [{'from': '0x401100', 'to': '0x401200'}])
        self.assertEqual(result['functions'][0]['pseudocode'], EXPORT['functions'][0]['pseudocode'])

    def test_discard_bad_entries_and_cap_pseudocode(self):
        fixture = {'schema_version': 1, 'functions': [
            {'name': 'ok', 'address': '0x1000', 'size': 1, 'calls': ['bad', '0x1001'],
             'pseudocode': 'x'*9000},
            {'name': 'bad', 'address': 'banana', 'size': 0, 'calls': [], 'pseudocode': ''},
        ]}
        result = _validated_export(fixture)
        self.assertEqual(len(result['functions']), 1)
        self.assertEqual(len(result['functions'][0]['pseudocode']), 5000)
        self.assertEqual(result['edges'], [])
        with self.assertRaises(GhidraError):
            _validated_export({'functions': []})

    def test_missing_launcher(self):
        with patch('reverselab.ghidra.launcher_path', return_value=None), patch('reverselab.ghidra.detect', return_value={'format': 'ELF', 'entry_point': 1, 'sections': [{'name': '.text'}]}):
            self.assertFalse(ghidra_status()['available'])
            with self.assertRaisesRegex(GhidraError, 'não instalado'):
                analyze_with_ghidra(b'\x7fELF' + b'\x00'*100)

    def test_reject_unrecognized_file_without_launch(self):
        with patch('reverselab.ghidra.launcher_path') as launcher:
            with self.assertRaisesRegex(ValueError, 'ELF e PE'):
                analyze_with_ghidra(b'not executable')
            launcher.assert_not_called()

    def test_selected_evidence_minimal(self):
        report = analyze_bytes(b'HELLO_FROM_TEST\0')
        report['deep_analysis'] = _validated_export(EXPORT)
        report['selected_function_address'] = '0x401100'
        evidence = _evidence(report)
        self.assertEqual(evidence['ghidra_selected_function']['address'], '0x401100')
        self.assertNotIn('helper() { return 42', str(evidence))
        report['selected_function_address'] = '0x00000000'
        self.assertIsNone(_evidence(report)['ghidra_selected_function'])


@unittest.skipUnless(shutil.which('gcc'), 'GCC não disponível')
class IntegrationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.programs = []
        for i, text in enumerate((
            'int helper(void) {return 42;} int main(void) {return helper();}',
            'int multiply(int a, int b) {return a*b;} int main(void) {return multiply(7,6);}',
        )):
            path = Path(cls.tmp.name) / ('program%d.c' % i)
            path.write_text(text)
            target = path.with_suffix('')
            subprocess.run(['gcc', '-O0', '-g', str(path), '-o', str(target)], check=True)
            cls.programs.append(target.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_two_distinct_real_elf_binaries_and_ghidra_contract(self):
        for data in self.programs:
            report = analyze_bytes(data, 'program.elf')
            self.assertEqual(report['binary']['format'], 'ELF')
            self.assertIn('main', {x['name'] for x in report['binary']['functions']})
            def fake_run(args, **kwargs):
                self.assertIn('-readOnly', args)
                self.assertIn('-deleteProject', args)
                self.assertIn('-analysisTimeoutPerFile', args)
                self.assertEqual(args[args.index('-max-cpu')+1], '2')
                # Headless would write to the script output path in this isolated workspace.
                path = Path(args[args.index('-postScript')+2])
                path.write_text(json.dumps(EXPORT), encoding='utf-8')
                return subprocess.CompletedProcess(args, 0, 'REVERSELAB_EXPORT_OK', '')
            with patch('reverselab.ghidra.launcher_path', return_value=Path('/fake/ghidra/analyzeHeadless')):
                with patch('reverselab.ghidra.subprocess.run', side_effect=fake_run):
                    deep = analyze_with_ghidra(data)
            self.assertEqual(len(deep['functions']), 2)
            self.assertEqual(len(deep['edges']), 1)

    def test_timeout_is_reported(self):
        with patch('reverselab.ghidra.launcher_path', return_value=Path('/fake/ghidra/analyzeHeadless')):
            with patch('reverselab.ghidra.subprocess.run', side_effect=subprocess.TimeoutExpired('ghidra', 5)):
                with self.assertRaisesRegex(GhidraError, 'limite de tempo'):
                    analyze_with_ghidra(self.programs[0])

if __name__ == '__main__':
    unittest.main()
