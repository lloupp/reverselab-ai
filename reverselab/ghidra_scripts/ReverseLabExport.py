#@category ReverseLab
# Ghidra Headless post-script, compatible with Jython 2.7.
# Only exports metadata/pseudocode to a new JSON file in a temporary workspace.
import json
from ghidra.app.decompiler import DecompInterface

args = getScriptArgs()
if len(args) != 1:
    raise ValueError('Expected output JSON path')
output_path = args[0]
manager = currentProgram.getFunctionManager()
iterator = manager.getFunctions(True)
functions = []
max_functions = 100
interface = DecompInterface()
interface.toggleSyntaxTree(False)
interface.setSimplificationStyle('decompile')
if not interface.openProgram(currentProgram):
    raise RuntimeError('Decompiler unavailable for this program')
try:
    while iterator.hasNext() and len(functions) < max_functions and not monitor.isCancelled():
        func = iterator.next()
        calls = []
        try:
            for callee in func.getCalledFunctions(monitor):
                calls.append('0x' + str(callee.getEntryPoint()))
                if len(calls) >= 48:
                    break
        except Exception:
            pass
        pseudocode = ''
        try:
            result = interface.decompileFunction(func, 5, monitor)
            if result is not None and result.decompileCompleted():
                decompiled = result.getDecompiledFunction()
                if decompiled is not None:
                    pseudocode = str(decompiled.getC())[:5000]
        except Exception:
            pass
        functions.append({
            'name': str(func.getName())[:180],
            'address': '0x' + str(func.getEntryPoint()),
            'size': int(func.getBody().getNumAddresses()),
            'calls': calls,
            'pseudocode': pseudocode,
            'source': 'Ghidra function manager',
        })
finally:
    interface.dispose()
payload = {'schema_version': 1, 'backend': 'Ghidra Headless',
           'program_name': str(currentProgram.getName())[:150],
           'language': str(currentProgram.getLanguageID()),
           'functions': functions, 'truncated': iterator.hasNext()}
with open(output_path, 'w') as destination:
    json.dump(payload, destination)
print('REVERSELAB_EXPORT_OK count=' + str(len(functions)))
