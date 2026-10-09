"""Static binary inspection engine. Untrusted files are never executed."""
from __future__ import annotations

import hashlib
import math
import re
import shutil
import struct
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_DISASSEMBLY_BYTES = 8192
MACHINE_ELF = {3: 'x86', 8: 'MIPS', 20: 'PowerPC', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V'}
MACHINE_PE = {0x14C: 'x86', 0x8664: 'x86-64', 0x1C0: 'ARM', 0xAA64: 'AArch64'}
MACHO_MAGIC = {b'\xfe\xed\xfa\xce': 'big', b'\xce\xfa\xed\xfe': 'little', b'\xfe\xed\xfa\xcf': 'big', b'\xcf\xfa\xed\xfe': 'little'}
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _u16(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'H', data, offset)[0] if len(data) >= offset + 2 else 0


def _u32(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'I', data, offset)[0] if len(data) >= offset + 4 else 0


def _u64(data: bytes, offset: int, endian: str = '<') -> int:
    return struct.unpack_from(endian + 'Q', data, offset)[0] if len(data) >= offset + 8 else 0


def _cstring(data: bytes, offset: int, max_len: int = 250) -> str:
    if offset < 0 or offset >= len(data):
        return ''
    chunk = data[offset:offset + max_len].split(b'\0', 1)[0]
    return chunk.decode('utf-8', 'replace')


def detect(data: bytes) -> dict[str, Any]:
    """Bounded parsers for basic ELF, PE, Mach-O and Nintendo 64 metadata."""
    meta: dict[str, Any] = dict(format='Desconhecido', architecture='Desconhecida', bits=None,
                                endian=None, entry_point=None, sections=[], imports=[], functions=[], notes=[])
    if data.startswith(b'\x7fELF'):
        _parse_elf(data, meta)
    elif len(data) > 0x40 and data[:2] == b'MZ':
        _parse_pe(data, meta)
    elif data[:4] in MACHO_MAGIC or data[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        meta['format'] = 'Mach-O'
        if data[:4] in MACHO_MAGIC:
            endian = '<' if MACHO_MAGIC[data[:4]] == 'little' else '>'
            meta['endian'] = 'little' if endian == '<' else 'big'
            meta['bits'] = 64 if data[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe') else 32
            cpu = _u32(data, 4, endian)
            meta['architecture'] = {7:'x86',0x01000007:'x86-64',12:'ARM',0x0100000c:'AArch64'}.get(cpu, f'CPU {cpu}')
        else:
            meta['format'] = 'Mach-O universal'
            meta['notes'].append('Binário universal: seleção de arquitetura ainda não implementada.')
        meta['notes'].append('Extração de seções Mach-O ainda não implementada.')
    elif data[:4] in (b'\x80\x37\x12\x40', b'\x37\x80\x40\x12', b'\x40\x12\x37\x80'):
        _parse_n64(data, meta)
    else:
        meta['notes'].append('Cabeçalho não reconhecido; somente análise genérica de bytes.')
    return meta


def _parse_elf(data: bytes, meta: dict[str, Any]) -> None:
    meta['format'] = 'ELF'
    cls, byteorder = (data[4] if len(data) > 4 else 0), (data[5] if len(data) > 5 else 0)
    if cls not in (1, 2) or byteorder not in (1, 2):
        meta['notes'].append('Cabeçalho ELF incompleto ou inválido.')
        return
    bits = 64 if cls == 2 else 32
    end = '<' if byteorder == 1 else '>'
    meta['bits'] = bits
    meta['endian'] = 'little' if end == '<' else 'big'
    meta['architecture'] = MACHINE_ELF.get(_u16(data, 18, end), 'Outra arquitetura')
    meta['entry_point'] = _u64(data, 24, end) if bits == 64 else _u32(data, 24, end)
    shoff = _u64(data, 40, end) if bits == 64 else _u32(data, 32, end)
    entsize = _u16(data, 58 if bits == 64 else 46, end)
    count = _u16(data, 60 if bits == 64 else 48, end)
    name_index = _u16(data, 62 if bits == 64 else 50, end)
    required = 64 if bits == 64 else 40
    if not shoff or entsize < required or count > 2048 or shoff + entsize * count > len(data):
        meta['notes'].append('Tabela de seções ausente, inválida ou fora dos limites.')
        return
    sections = []
    for i in range(count):
        off = shoff + i * entsize
        try:
            if bits == 64:
                name_id, typ, flags, addr, file_off, size, link, info, align, entry_size = struct.unpack_from(end+'IIQQQQIIQQ', data, off)
            else:
                name_id, typ, flags, addr, file_off, size, link, info, align, entry_size = struct.unpack_from(end+'IIIIIIIIII', data, off)
        except struct.error:
            break
        sections.append(dict(name_id=name_id, type=typ, flags=flags, address=addr,
                             offset=file_off, size=size, link=link, entry_size=entry_size,
                             executable=bool(flags & 4)))
    names = sections[name_index] if name_index < len(sections) else None
    for s in sections:
        index = names['offset'] + s['name_id'] if names and names['offset'] + names['size'] <= len(data) else -1
        s['name'] = _cstring(data, index, 100) or f"section_{len(meta['sections'])}"
        meta['sections'].append({k: s[k] for k in ('name','offset','size','address','executable')})
    strtables = {}
    for i,s in enumerate(sections):
        if s['type'] == 3 and s['offset'] + s['size'] <= len(data):
            strtables[i] = data[s['offset']:s['offset']+s['size']]
    for s in sections:
        if s['type'] not in (2, 11) or s['entry_size'] < (24 if bits == 64 else 16):
            continue
        if s['offset'] + s['size'] > len(data) or s['size'] > 6*1024*1024:
            continue
        strings = strtables.get(s['link'], b'')
        count_symbols = min(s['size'] // s['entry_size'], 18000)
        for j in range(count_symbols):
            off = s['offset'] + j * s['entry_size']
            if bits == 64:
                name_off, info, other, section_index, value, size = struct.unpack_from(end+'IBBHQQ', data, off)
            else:
                name_off, value, size, info, other, section_index = struct.unpack_from(end+'IIIBBH', data, off)
            name = _cstring(strings, name_off)
            if not name:
                continue
            if section_index == 0 and s['type'] == 11 and len(meta['imports']) < 160:
                meta['imports'].append(name)
            if info & 0xF == 2 and section_index != 0 and len(meta['functions']) < 160:
                meta['functions'].append({'name': name, 'address': hex(value), 'size': size, 'source': 'ELF symbol'})
    dynstr = next((s for s in sections if s['name'] == '.dynstr'), None)
    dynamic = next((s for s in sections if s['name'] == '.dynamic'), None)
    if dynstr and dynamic and dynstr['offset'] + dynstr['size'] <= len(data) and dynamic['offset'] + dynamic['size'] <= len(data):
        strings = data[dynstr['offset']:dynstr['offset']+dynstr['size']]
        step = 16 if bits == 64 else 8
        for off in range(dynamic['offset'], min(dynamic['offset'] + dynamic['size'], dynamic['offset'] + step*2000), step):
            if off + step > len(data):
                break
            typ = _u64(data, off, end) if bits == 64 else _u32(data, off, end)
            val = _u64(data, off + step//2, end) if bits == 64 else _u32(data, off + step//2, end)
            if typ == 1:
                lib = _cstring(strings, val)
                if lib and lib not in meta['imports'] and len(meta['imports']) < 160:
                    meta['imports'].append(lib)


def _parse_pe(data: bytes, meta: dict[str, Any]) -> None:
    meta['format'] = 'PE (Windows) — cabeçalho DOS'
    pe_off = _u32(data, 0x3c)
    if pe_off < 0x40 or pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b'PE\0\0':
        meta['notes'].append('Assinatura PE não encontrada ou inválida.')
        return
    meta['format'] = 'PE (Windows)'
    machine, nsec = struct.unpack_from('<HH', data, pe_off+4)
    optsize = _u16(data, pe_off+20)
    opt = pe_off+24
    magic = _u16(data, opt)
    meta['architecture'] = MACHINE_PE.get(machine, f'CPU 0x{machine:x}')
    if magic not in (0x10B, 0x20B) or opt + optsize > len(data):
        meta['notes'].append('Optional header ausente ou inválido.')
        return
    is64 = magic == 0x20B
    meta['bits'] = 64 if is64 else 32
    meta['endian'] = 'little'
    base = _u64(data, opt+24) if is64 else _u32(data, opt+28)
    meta['entry_point'] = base + _u32(data, opt+16)
    sections = []
    if nsec > 2048:
        meta['notes'].append('Número de seções excessivo.')
        return
    for i in range(nsec):
        s_off = opt + optsize + 40*i
        if s_off + 40 > len(data):
            break
        name = data[s_off:s_off+8].split(b'\0')[0].decode('ascii', 'replace')
        virt_size, va, raw_size, file_off = struct.unpack_from('<IIII', data, s_off+8)
        chars = _u32(data, s_off+36)
        sections.append(dict(name=name,offset=file_off,size=raw_size,address=base+va,
                             virtual_address=va,virtual_size=virt_size,executable=bool(chars&0x20000000)))
    meta['sections'] = [{k:s[k] for k in ('name','offset','size','address','executable')} for s in sections]

    def rva_to_file(rva: int) -> int | None:
        for s in sections:
            if s['virtual_address'] <= rva < s['virtual_address'] + max(s['virtual_size'], s['size']):
                p = s['offset'] + rva - s['virtual_address']
                if p < len(data) and p < s['offset'] + s['size']:
                    return p
        return None

    dirpos = opt + (112 if is64 else 96) + 8  # IMAGE_DIRECTORY_ENTRY_IMPORT
    if dirpos + 8 > opt+optsize:
        return
    imp_rva = _u32(data, dirpos)
    first_off = rva_to_file(imp_rva) if imp_rva else None
    if first_off is None:
        return
    for i in range(256):
        pos = first_off + 20*i
        if pos+20 > len(data):
            break
        orig, timestamp, fwd, name_rva, ft = struct.unpack_from('<IIIII', data, pos)
        if not any((orig,timestamp,fwd,name_rva,ft)):
            break
        name_off = rva_to_file(name_rva)
        dll = _cstring(data, name_off) if name_off is not None else ''
        if dll and len(meta['imports']) < 160:
            meta['imports'].append(dll)
        thunk_off = rva_to_file(orig or ft)
        step = 8 if is64 else 4
        if thunk_off is None:
            continue
        for j in range(150):
            tpos = thunk_off + step*j
            if tpos+step > len(data):
                break
            ptr = _u64(data,tpos) if is64 else _u32(data,tpos)
            if not ptr:
                break
            if ptr & (1 << (63 if is64 else 31)):
                continue
            func_off = rva_to_file(ptr)
            func = _cstring(data,func_off+2) if func_off is not None else ''
            if func and len(meta['imports']) < 160:
                meta['imports'].append(f'{dll}!{func}')


def _parse_n64(data: bytes, meta: dict[str, Any]) -> None:
    kind = {b'\x80\x37\x12\x40':'z64',b'\x37\x80\x40\x12':'v64',b'\x40\x12\x37\x80':'n64'}[data[:4]]
    meta.update(format='Nintendo 64 ROM', architecture='MIPS R4300i', bits=64,
                endian='big', rom_byte_order=kind)
    head = _normalize_n64(data[:0x40], kind)
    meta['entry_point'] = _u32(head, 8, '>')
    meta['title'] = head[0x20:0x34].decode('ascii','replace').strip('\0 ') if len(head)>=0x34 else ''
    meta['notes'].append('ROM reconhecida. O código de inicialização não identifica automaticamente todas as funções do jogo.')
    if len(data) >= 0x1004:
        meta['sections'].append({'name':'Trecho inicial da ROM (hipótese; não seção oficial)','offset':0x1000,
                                 'size':len(data)-0x1000,'address':0x1000,'executable':True})


def _normalize_n64(data: bytes, kind: str) -> bytes:
    if kind == 'z64':
        return data
    if kind == 'v64':
        return b''.join(data[i:i+2][::-1] for i in range(0,len(data)-len(data)%2,2))
    return b''.join(data[i:i+4][::-1] for i in range(0,len(data)-len(data)%4,4))


def _strings(data: bytes, limit: int = 110, minimum: int = 5) -> list[dict[str, Any]]:
    results = []
    for m in re.finditer(rb'[\x20-\x7e]{'+str(minimum).encode()+rb',}',data):
        val = m.group().decode('ascii')[:240]
        results.append({'offset':f'0x{m.start():x}', 'value':val,'encoding':'ASCII', 'category':_categorize(val)})
        if len(results) >= limit:
            break
    # UTF-16LE detection with bounded matching; avoid overlapping duplicates.
    if len(results) < limit:
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){'+str(minimum).encode()+rb',}',data):
            val = m.group().decode('utf-16le',errors='replace')[:240]
            results.append({'offset':f'0x{m.start():x}', 'value':val,'encoding':'UTF-16LE','category':_categorize(val)})
            if len(results) >= limit:
                break
    results.sort(key=lambda v:int(v['offset'],16))
    return results


def _categorize(value: str) -> str:
    v = value.lower()
    if URL_RE.search(value):
        return 'URL'
    if any(x in v for x in ('error','failed','exception','erro:','falha','debug','warning')):
        return 'Diagnóstico'
    if any(x in v for x in ('/usr/','/home/','\\windows\\','.dll','.so','.dylib')):
        return 'Caminho/biblioteca'
    if any(x in v for x in ('http','socket','connect','winsock','tls','ssl')):
        return 'Rede (indício)'
    return 'Geral'


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    return round(-sum((n/len(data))*math.log2(n/len(data)) for n in freq.values()), 3)


def _mips_instructions(chunk: bytes, address: int, limit: int = 140) -> list[dict[str,str]]:
    reg = ['$zero','$at','$v0','$v1','$a0','$a1','$a2','$a3','$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7',
           '$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7','$t8','$t9','$k0','$k1','$gp','$sp','$fp','$ra']
    out = []
    for i in range(0,min(len(chunk)//4,limit)*4,4):
        w = int.from_bytes(chunk[i:i+4],'big')
        op,rs,rt,rd,fun = (w>>26)&63,(w>>21)&31,(w>>16)&31,(w>>11)&31,w&63
        imm = w&0xffff
        simm = imm if imm < 32768 else imm - 65536
        name, args = '.word', f'0x{w:08x}'
        if w==0: name,args='nop',''
        elif op==0 and fun==8: name,args='jr',reg[rs]
        elif op==0 and fun==9: name,args='jalr',f'{reg[rd]}, {reg[rs]}'
        elif op==0 and fun in (0,2,3):
            name = {0:'sll',2:'srl',3:'sra'}[fun]; args=f'{reg[rd]}, {reg[rt]}, {(w>>6)&31}'
        elif op==0 and fun in (0x21,0x23,0x24,0x25,0x2a):
            name = {0x21:'addu',0x23:'subu',0x24:'and',0x25:'or',0x2a:'slt'}[fun]
            args = f'{reg[rd]}, {reg[rs]}, {reg[rt]}'
        elif op in (2,3):
            name = 'j' if op==2 else 'jal'
            args=f'0x{(((address+i+4)&0xf0000000)|((w&0x03ffffff)<<2)):x}'
        elif op in (4,5,6,7):
            name = {4:'beq',5:'bne',6:'blez',7:'bgtz'}[op]
            args = f'{reg[rs]}, {reg[rt]}, 0x{address+i+4+simm*4:x}'
        elif op in (9,10,11,12,13,14,15):
            name={9:'addiu',10:'slti',11:'sltiu',12:'andi',13:'ori',14:'xori',15:'lui'}[op]
            args = f'{reg[rt]}, 0x{imm:x}' if op == 15 else f'{reg[rt]}, {reg[rs]}, {simm if op in (9,10,11) else hex(imm)}'
        elif op in (0x20,0x21,0x23,0x24,0x25,0x28,0x29,0x2b):
            name = {0x20:'lb',0x21:'lh',0x23:'lw',0x24:'lbu',0x25:'lhu',0x28:'sb',0x29:'sh',0x2b:'sw'}[op]
            args = f'{reg[rt]}, {simm}({reg[rs]})'
        out.append({'address':f'0x{address+i:x}', 'bytes':chunk[i:i+4].hex(' '), 'mnemonic':name, 'operands':args})
    return out


def _disassemble(data: bytes, meta: dict[str,Any]) -> dict[str,Any]:
    sections = [s for s in meta['sections'] if s['executable'] and s['size'] and s['offset'] < len(data)]
    # Use .text for executable formats; for N64 use a clearly-labeled heuristic window.
    if sections:
        s=next((x for x in sections if x['name'] in ('.text','__text')),sections[0])
        offset, base = s['offset'], s['address']
    elif meta['format']=='Desconhecido':
        return {'backend':'Não disponível','instructions':[], 'note':'Formato desconhecido. Se for código bruto, informe uma arquitetura em versão futura.'}
    else:
        return {'backend':'Não disponível','instructions':[], 'note':'Sem seção de código reconhecida.'}
    chunk=data[offset: min(offset+MAX_DISASSEMBLY_BYTES, len(data),offset+s['size'])]
    arch=meta['architecture']
    if meta['format']=='Nintendo 64 ROM':
        chunk=_normalize_n64(chunk,meta['rom_byte_order'])
    # Optional multi-architecture backend, if installed.
    try:
        import capstone as cs
        modes = {'x86': (cs.CS_ARCH_X86,cs.CS_MODE_32), 'x86-64': (cs.CS_ARCH_X86,cs.CS_MODE_64),
                 'ARM':(cs.CS_ARCH_ARM,cs.CS_MODE_ARM),'AArch64':(cs.CS_ARCH_ARM64,cs.CS_MODE_ARM),
                 'MIPS':(cs.CS_ARCH_MIPS,cs.CS_MODE_MIPS32),'MIPS R4300i':(cs.CS_ARCH_MIPS,cs.CS_MODE_MIPS64)}
        if arch in modes:
            family,mode=modes[arch]
            mode |= cs.CS_MODE_BIG_ENDIAN if meta['endian']=='big' else cs.CS_MODE_LITTLE_ENDIAN
            engine=cs.Cs(family,mode)
            ins=[{'address':f'0x{i.address:x}','bytes':i.bytes.hex(' '),'mnemonic':i.mnemonic,'operands':i.op_str} for i in engine.disasm(chunk,base,count=140)]
            return {'backend':'Capstone','instructions':ins,'note':'Apenas janela inicial de código; não equivale à descoberta completa de funções.'}
    except (ImportError,AttributeError,ValueError) as e:
        pass
    if arch=='MIPS R4300i':
        return {'backend':'Decodificador MIPS básico (interno)','instructions':_mips_instructions(chunk,base),
                'note':'Decodificação parcial; endereços de ROM não são necessariamente endereços virtuais.'}
    objdump = shutil.which('objdump')
    arch_arg = {'x86-64':'i386:x86-64','x86':'i386'}.get(arch)
    if objdump and arch_arg:
        with tempfile.TemporaryDirectory(prefix='reverselab_') as d:
            p=Path(d)/'code.bin'
            p.write_bytes(chunk)
            try:
                result=subprocess.run([objdump,'-D','-b','binary','-m',arch_arg,'-M','intel',
                                       f'--adjust-vma={base}',str(p)],capture_output=True,text=True,
                                      encoding='utf-8',errors='replace',timeout=6,check=False)
            except (subprocess.SubprocessError,OSError) as ex:
                return {'backend':'objdump indisponível','instructions':[],'note':str(ex)[:200]}
        parsed=[]
        for line in result.stdout.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([^\s]+)?\s*(.*)$',line,re.I)
            if m:
                parsed.append(dict(address='0x'+m.group(1),bytes=m.group(2).strip(),mnemonic=m.group(3) or '',operands=m.group(4).strip()))
                if len(parsed)>=140:
                    break
        return {'backend':'GNU objdump','instructions':parsed,
                'note':'Desassemblagem linear de uma janela de bytes; pode interpretar dados como código.'}
    return {'backend':'Não disponível','instructions':[],
            'note':'Instale capstone (pip install capstone) para desassemblar esta arquitetura.'}


def _observations(meta:dict[str,Any], strings:list[dict[str,Any]], size:int, entropy:float) -> list[dict[str,str]]:
    observations=[]
    if entropy>7.6 and size>1024:
        observations.append({'label':'Entropia elevada','evidence':f'{entropy} bits/byte no arquivo',
                             'meaning':'Pode indicar compressão, dados multimídia ou conteúdo cifrado; isoladamente não indica malware.'})
    urls=[v['value'] for v in strings if v['category']=='URL'][:3]
    if urls:
        observations.append({'label':'URLs visíveis','evidence':'; '.join(urls),
                             'meaning':'Endereços aparecem como texto. Não comprova conexão de rede.'})
    if meta['imports']:
        observations.append({'label':'Dependências identificadas','evidence':', '.join(meta['imports'][:5]),
                             'meaning':'Importações ajudam a entender recursos usados; não comprovam ações em tempo de execução.'})
    if meta['format']=='Nintendo 64 ROM':
        observations.append({'label':'ROM Nintendo 64','evidence':f"ordem dos bytes {meta.get('rom_byte_order')}",
                             'meaning':'Possível candidata a análise MIPS. Portabilidade nativa exige runtime e validação.'})
    return observations


def analyze_bytes(data: bytes, filename: str = 'arquivo.bin') -> dict[str,Any]:
    if not isinstance(data,bytes):
        raise TypeError('Os dados devem ser bytes.')
    if not data:
        raise ValueError('Arquivo vazio.')
    if len(data)>MAX_FILE_SIZE:
        raise ValueError(f'Arquivo maior que o limite de {MAX_FILE_SIZE // 1024 // 1024} MiB.')
    safe_name = Path(filename.replace('\\','/')).name[:120] or 'arquivo.bin'
    meta=detect(data)
    string_values=_strings(data)
    ent=_entropy(data)
    assembly=_disassemble(data,meta)
    meta.pop('rom_byte_order',None) if meta.get('format') != 'Nintendo 64 ROM' else None
    return {
        'tool':'ReverseLab AI', 'version':'0.1.0', 'filename':safe_name,
        'size':len(data),'sha256':hashlib.sha256(data).hexdigest(), 'entropy':ent,
        'binary':meta, 'strings':string_values, 'disassembly':assembly,
        'observations':_observations(meta,string_values,len(data),ent),
        'disclaimer':'Análise estática inicial. Nenhum arquivo foi executado. Inferências não são veredictos.'
    }


def markdown_report(r: dict[str,Any]) -> str:
    b=r['binary']
    lines=[f"# ReverseLab AI — {r['filename'].replace(chr(10),' ')}",'',
           '## Identificação',f"- Formato: {b['format']}",f"- Arquitetura: {b['architecture']}",
           f"- Tamanho: {r['size']} bytes",f"- SHA-256: `{r['sha256']}`",
           f"- Entropia: {r['entropy']} bits/byte",f"- Entrada: {hex(b['entry_point']) if b['entry_point'] is not None else 'desconhecida'}",'',
           '## Observações']
    lines.extend(f"- **{o['label']}**: {o['meaning']} Evidência: `{o['evidence']}`" for o in r['observations'])
    if not r['observations']:
        lines.append('- Nenhuma observação heurística relevante.')
    lines.extend(['','## Seções'])
    lines.extend(f"- {s['name']} — offset 0x{s['offset']:x}, {s['size']} bytes, execução: {s['executable']}" for s in b['sections'][:80])
    lines.extend(['','## Importações'])
    lines.extend(f"- `{s}`" for s in b['imports'][:80])
    lines.extend(['','## Possíveis funções'])
    lines.extend(f"- `{f['name']}` em {f['address']} (símbolo)" for f in b['functions'][:80])
    deep = r.get('deep_analysis')
    if isinstance(deep, dict):
        lines.extend(['','## Funções (Ghidra Headless)'])
        for f in deep.get('functions', [])[:100]:
            lines.append(f"- `{f['name']}` em `{f['address']}` → {', '.join(f['calls']) or 'sem chamadas identificadas'}")
            if f.get('pseudocode'):
                lines.extend(['','```c',f['pseudocode'],'```'])
    lines.extend(['','## Strings (amostra)'])
    lines.extend(f"- {s['offset']} [{s['encoding']}] {s['value']!r}" for s in r['strings'][:75])
    lines.extend(['','## Desassemblagem (amostra)',f"Backend: {r['disassembly']['backend']}",'','```asm'])
    lines.extend(f"{i['address']}: {i['mnemonic']} {i['operands']}" for i in r['disassembly']['instructions'][:100])
    lines.extend(['```','',f"**Limitações:** {r['disassembly']['note']}",'',r['disclaimer'],''])
    return '\n'.join(lines)
