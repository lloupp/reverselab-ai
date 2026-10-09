import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from reverselab.core import analyze_bytes, detect, markdown_report, _normalize_n64, MAX_FILE_SIZE


class AnalysisTests(unittest.TestCase):
    def test_unknown_data_never_guesses_behavior(self):
        r=analyze_bytes(b'hello error: example.com\n' * 10, '../../my.bin')
        self.assertEqual(r['binary']['format'],'Desconhecido')
        self.assertEqual(r['filename'],'my.bin')
        self.assertIn('hex' if False else 'sha256',r)
        self.assertEqual(r['disassembly']['instructions'],[])
        self.assertFalse(any('malware' in o['label'].lower() for o in r['observations']))

    def test_empty_and_size(self):
        with self.assertRaisesRegex(ValueError,'vazio'):
            analyze_bytes(b'')
        with self.assertRaisesRegex(ValueError,'limite'):
            analyze_bytes(b'Q'*(MAX_FILE_SIZE+1))

    def test_macho(self):
        b=b'\xcf\xfa\xed\xfe'+struct.pack('<I',0x01000007)+b'\0'*56
        r=analyze_bytes(b,'sample')
        self.assertEqual(r['binary']['format'],'Mach-O')
        self.assertEqual(r['binary']['architecture'],'x86-64')

    def test_pe(self):
        b=bytearray(1024)
        b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80)
        b[0x80:0x84]=b'PE\0\0'
        struct.pack_into('<HHIIIHH',b,0x84,0x8664,1,0,0,0,0xf0,0)
        opt=0x98
        struct.pack_into('<H',b,opt,0x20b)
        struct.pack_into('<I',b,opt+16,0x1000)
        struct.pack_into('<Q',b,opt+24,0x140000000)
        s=opt+0xf0
        b[s:s+8]=b'.text\0\0\0'
        struct.pack_into('<IIII',b,s+8,32,0x1000,32,0x200)
        struct.pack_into('<I',b,s+36,0x60000020)
        b[0x200:0x203]=b'\x90\x90\xc3'
        r=analyze_bytes(bytes(b),'hello.exe')
        self.assertEqual(r['binary']['format'],'PE (Windows)')
        self.assertEqual(r['binary']['architecture'],'x86-64')
        self.assertEqual(r['binary']['entry_point'],0x140001000)
        self.assertTrue(r['binary']['sections'][0]['executable'])

    def test_pe_import_directory(self):
        b=bytearray(2048)
        b[:2]=b'MZ'; struct.pack_into('<I',b,0x3c,0x80)
        b[0x80:0x84]=b'PE\0\0'
        struct.pack_into('<HHIIIHH',b,0x84,0x8664,1,0,0,0,0xf0,0)
        opt=0x98
        struct.pack_into('<H',b,opt,0x20b)
        struct.pack_into('<I',b,opt+16,0x2000)
        struct.pack_into('<Q',b,opt+24,0x140000000)
        struct.pack_into('<II',b,opt+120,0x2000,0x100)
        sec=opt+0xf0
        b[sec:sec+8]=b'.idata\0\0'
        struct.pack_into('<IIII',b,sec+8,0x200,0x2000,0x200,0x400)
        struct.pack_into('<I',b,sec+36,0x40000040)
        struct.pack_into('<IIIII',b,0x400,0x2040,0,0,0x2080,0x2040)
        struct.pack_into('<Q',b,0x440,0x2090)
        b[0x480:0x480+13]=b'KERNEL32.dll\0'
        b[0x490:0x490+2+12]=b'\0\0CreateFileA\0'
        report=analyze_bytes(bytes(b),'import.exe')
        self.assertIn('KERNEL32.dll',report['binary']['imports'])
        self.assertIn('KERNEL32.dll!CreateFileA',report['binary']['imports'])

    def test_malformed_pe(self):
        meta=detect(b'MZ'+b'X'*128)
        self.assertEqual(meta['format'],'PE (Windows) — cabeçalho DOS')

    def test_n64_all_byte_orders_and_mips(self):
        rom=bytearray(0x1200)
        rom[:4]=b'\x80\x37\x12\x40'
        rom[8:12]=b'\x80\x00\x04\x00'
        rom[0x20:0x2a]=b'TEST GAME!'
        rom[0x1000:0x1008]=b'\x24\x02\x00\x0a\x03\xe0\x00\x08'
        versions={'z64':bytes(rom),
                  'v64':b''.join(rom[i:i+2][::-1] for i in range(0,len(rom),2)),
                  'n64':b''.join(rom[i:i+4][::-1] for i in range(0,len(rom),4))}
        for key,dat in versions.items():
            with self.subTest(key=key):
                r=analyze_bytes(dat,'test.'+key)
                b=r['binary']
                self.assertEqual(b['format'],'Nintendo 64 ROM')
                self.assertEqual(b['rom_byte_order'],key)
                self.assertEqual(b['entry_point'],0x80000400)
                self.assertEqual(b['title'],'TEST GAME!')
                self.assertIn('addiu',[i['mnemonic'] for i in r['disassembly']['instructions'][:2]])

    def test_strings_and_markdown(self):
        data=b'JUNK _ https://example.com/test ERRORS happen C:\\Windows\\system32\\abc.dll'+b'\0W\0I\0D\0E\0T\0E\0X\0T\0'
        report=analyze_bytes(data)
        categories={s['category'] for s in report['strings']}
        self.assertIn('URL',categories)
        self.assertIn('UTF-16LE',{s['encoding'] for s in report['strings']})
        text=markdown_report(report)
        self.assertIn('SHA-256',text)
        self.assertIn('nenhum',text.lower())

    @unittest.skipUnless(shutil.which('gcc'), 'gcc não disponível')
    def test_real_compiled_binary(self):
        source=Path(__file__).resolve().parents[1]/'examples'/'hello.c'
        with tempfile.TemporaryDirectory() as d:
            binary=Path(d)/'example'
            subprocess.run(['gcc','-O0','-g',str(source),'-o',str(binary)],check=True,timeout=15)
            r=analyze_bytes(binary.read_bytes(),'example')
            self.assertEqual(r['binary']['format'],'ELF')
            self.assertEqual(r['binary']['architecture'],'x86-64')
            self.assertGreater(len(r['binary']['sections']),5)
            self.assertIn('main',[v['name'] for v in r['binary']['functions']])
            self.assertTrue(r['disassembly']['instructions'])

    def test_malformed_headers_do_not_crash(self):
        for name,content in [('elf',b'\x7fELF'),('pe',b'MZ'+b'\0'*128),('rom',b'\x80\x37\x12\x40')]:
            with self.subTest(name=name):
                result=analyze_bytes(content)
                self.assertTrue(result['binary']['format'])


if __name__=='__main__':unittest.main()
