# ReverseLab AI — demo_n64_sintetica.z64

## Identificação
- Formato: Nintendo 64 ROM
- Arquitetura: MIPS R4300i
- Tamanho: 4608 bytes
- SHA-256: `3e49c3f84162cb393c1edacdcdce76eeb813c68c9b0c3814a5bc83c7812990ce`
- Entropia: 0.112 bits/byte
- Entrada: 0x80000400

## Observações
- **ROM Nintendo 64**: Possível candidata a análise MIPS. Portabilidade nativa exige runtime e validação. Evidência: `ordem dos bytes z64`

## Seções
- Trecho inicial da ROM (hipótese; não seção oficial) — offset 0x1000, 512 bytes, execução: True

## Importações

## Possíveis funções

## Strings (amostra)
- 0x20 [ASCII] 'REVERSELAB DEMO N64 '

## Desassemblagem (amostra)
Backend: Decodificador MIPS básico (interno)

```asm
0x1000: lui $t0, 0x1234
0x1004: ori $t0, $t0, 0x5678
0x1008: addiu $v0, $zero, 10
0x100c: jr $ra
0x1010: nop 
0x1014: nop 
0x1018: nop 
0x101c: nop 
0x1020: nop 
0x1024: nop 
0x1028: nop 
0x102c: nop 
0x1030: nop 
0x1034: nop 
0x1038: nop 
0x103c: nop 
0x1040: nop 
0x1044: nop 
0x1048: nop 
0x104c: nop 
0x1050: nop 
0x1054: nop 
0x1058: nop 
0x105c: nop 
0x1060: nop 
0x1064: nop 
0x1068: nop 
0x106c: nop 
0x1070: nop 
0x1074: nop 
0x1078: nop 
0x107c: nop 
0x1080: nop 
0x1084: nop 
0x1088: nop 
0x108c: nop 
0x1090: nop 
0x1094: nop 
0x1098: nop 
0x109c: nop 
0x10a0: nop 
0x10a4: nop 
0x10a8: nop 
0x10ac: nop 
0x10b0: nop 
0x10b4: nop 
0x10b8: nop 
0x10bc: nop 
0x10c0: nop 
0x10c4: nop 
0x10c8: nop 
0x10cc: nop 
0x10d0: nop 
0x10d4: nop 
0x10d8: nop 
0x10dc: nop 
0x10e0: nop 
0x10e4: nop 
0x10e8: nop 
0x10ec: nop 
0x10f0: nop 
0x10f4: nop 
0x10f8: nop 
0x10fc: nop 
0x1100: nop 
0x1104: nop 
0x1108: nop 
0x110c: nop 
0x1110: nop 
0x1114: nop 
0x1118: nop 
0x111c: nop 
0x1120: nop 
0x1124: nop 
0x1128: nop 
0x112c: nop 
0x1130: nop 
0x1134: nop 
0x1138: nop 
0x113c: nop 
0x1140: nop 
0x1144: nop 
0x1148: nop 
0x114c: nop 
0x1150: nop 
0x1154: nop 
0x1158: nop 
0x115c: nop 
0x1160: nop 
0x1164: nop 
0x1168: nop 
0x116c: nop 
0x1170: nop 
0x1174: nop 
0x1178: nop 
0x117c: nop 
0x1180: nop 
0x1184: nop 
0x1188: nop 
0x118c: nop 
```

**Limitações:** Decodificação parcial; endereços de ROM não são necessariamente endereços virtuais.

Análise estática inicial. Nenhum arquivo foi executado. Inferências não são veredictos.
