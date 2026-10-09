'use strict';
let current = null;
const $ = id => document.getElementById(id);
const escapeHTML = x => String(x ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => n < 1024 ? `${n} B` : n < 1024*1024 ? `${(n/1024).toFixed(1)} KiB` : `${(n/1048576).toFixed(2)} MiB`;
const empty = txt => `<div class="empty">${escapeHTML(txt)}</div>`;
function message(text, kind='') { $('message').textContent=text; $('message').className=`message ${kind}`; }
function route(id) {
  document.querySelectorAll('.screen').forEach(x=>x.hidden=x.id!==id);
  document.querySelectorAll('.nav').forEach(x=>x.classList.toggle('active',x.dataset.screen===id));
  $('crumb').textContent={overview:'Visão geral',sections:'Seções e símbolos',strings:'Strings',assembly:'Desassemblagem',ai:'Assistente IA'}[id];
}
document.querySelectorAll('.nav').forEach(btn=>btn.addEventListener('click',()=>route(btn.dataset.screen)));
const zone=$('dropzone');
$('pick').addEventListener('click',e=>{e.stopPropagation();$('file').click();});
zone.addEventListener('click',()=> $('file').click());
zone.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file').click();}});
$('file').addEventListener('change',e=>{if(e.target.files?.length) analyzeFile(e.target.files[0]);});
for(const event of ['dragenter','dragover']) zone.addEventListener(event,e=>{e.preventDefault();zone.classList.add('dragover');});
for(const event of ['dragleave','drop']) zone.addEventListener(event,e=>{e.preventDefault();zone.classList.remove('dragover');});
zone.addEventListener('drop',e=>{if(e.dataTransfer.files.length) analyzeFile(e.dataTransfer.files[0]);});
async function analyzeFile(file){
  if(file.size > 16*1024*1024){message('O arquivo excede o limite de 16 MiB.','error');return;}
  if(!file.size){message('Arquivo vazio.','error');return;}
  $('results').hidden=true;
  message(`Analisando ${file.name}...`);
  try {
    const res=await fetch('/api/analyze?filename='+encodeURIComponent(file.name),{
      method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file
    });
    const obj=await res.json();
    if(!res.ok) throw Error(obj.error || `HTTP ${res.status}`);
    current=obj;
    render(obj);
    $('results').hidden=false;
    route('overview');
    message('Análise concluída. Nenhum código do arquivo foi executado.','good');
    $('results').scrollIntoView({behavior:'smooth',block:'start'});
  }catch(e){message('Falha na análise: '+e.message,'error');}
}
function render(r){
  const b=r.binary;
  $('filename').textContent=r.filename;
  $('filehash').textContent='SHA-256  '+r.sha256;
  $('mformat').textContent=b.format;
  $('march').textContent=b.architecture;
  $('msize').textContent=fmt(r.size);
  $('mentropy').textContent=r.entropy.toFixed(2);
  const facts=[['Formato',b.format],['Arquitetura',b.architecture],['Largura',b.bits ? `${b.bits} bits`:'Não identificada'],
    ['Endian',b.endian ?? 'Não identificado'],['Ponto de entrada',b.entry_point==null ? '—' : '0x'+b.entry_point.toString(16)],
    ['Seções identificadas',b.sections.length],['Importações',b.imports.length],['Funções por símbolos',b.functions.length]];
  if(b.title) facts.push(['Título da ROM',b.title]);
  if(b.rom_byte_order) facts.push(['Ordem da ROM',b.rom_byte_order]);
  $('summary').innerHTML=facts.map(([k,v])=>`<div class="fact-row"><span>${escapeHTML(k)}</span><span>${escapeHTML(v)}</span></div>`).join('');
  $('observations').innerHTML=(r.observations.map(o=>`<div class="observation"><strong>${escapeHTML(o.label)}</strong><p>${escapeHTML(o.meaning)}</p><small>${escapeHTML(o.evidence)}</small></div>`).join('') || empty('Nenhuma observação heurística relevante.'));
  $('nsections').textContent=`${b.sections.length} seções`;
  $('sectionrows').innerHTML=b.sections.map(s=>`<tr><td class="code">${escapeHTML(s.name)}</td><td class="code">0x${s.offset.toString(16)}</td><td>${fmt(s.size)}</td><td>${s.executable?'Sim':'Não'}</td></tr>`).join('') || `<tr><td colspan="4">Sem seções conhecidas.</td></tr>`;
  $('nfunctions').textContent=`${b.functions.length} símbolos`;
  $('functionrows').innerHTML=b.functions.map(f=>`<div class="list-row"><span class="code">${escapeHTML(f.name)}</span><small>${escapeHTML(f.address)}</small></div>`).join('') || empty('Não foram identificadas funções por símbolos. Binários sem símbolos podem exigir Ghidra.');
  $('nimports').textContent=`${b.imports.length} entradas`;
  $('imports').innerHTML=b.imports.map(n=>`<span class="tag">${escapeHTML(n)}</span>`).join('') || empty('Nenhuma importação identificada.');
  $('stringfilter').value='';renderStrings();
  $('backend').textContent='BACKEND: '+r.disassembly.backend;
  $('asmlines').innerHTML=r.disassembly.instructions.map(i=>`<div class="asm-line"><span>${escapeHTML(i.address)}</span><span>${escapeHTML(i.bytes)}</span><span><strong>${escapeHTML(i.mnemonic)}</strong> ${escapeHTML(i.operands)}</span></div>`).join('') || empty('Nenhuma instrução decodificada.');
  $('asmnote').textContent=r.disassembly.note;
  $('airesponse').textContent='Aguardando pergunta. O modelo só será consultado após clicar no botão.';
}
function renderStrings(){
  if(!current)return;
  const q=$('stringfilter').value.toLowerCase();
  const filtered=current.strings.filter(s=>[s.value,s.category,s.offset].some(v=>String(v).toLowerCase().includes(q)));
  $('stringrows').innerHTML=filtered.map(s=>`<tr><td class="code">${escapeHTML(s.offset)}</td><td>${escapeHTML(s.encoding)}</td><td>${escapeHTML(s.category)}</td><td class="code">${escapeHTML(s.value)}</td></tr>`).join('') || `<tr><td colspan="4">Sem strings correspondentes.</td></tr>`;
}
$('stringfilter').addEventListener('input',renderStrings);
function download(name,content,type){const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function md(r){let b=r.binary;
  const line=[`# ReverseLab AI — ${r.filename}`,'',`Formato: ${b.format}`,`Arquitetura: ${b.architecture}`,`Tamanho: ${r.size} bytes`,`SHA-256: ${r.sha256}`,`Entropia: ${r.entropy} bits/byte`,'',
    '## Observações',...r.observations.map(o=>`- ${o.label}: ${o.meaning}\n  Evidência: ${o.evidence}`),'','## Seções',...b.sections.map(s=>`- ${s.name}: ${s.size} bytes @ 0x${s.offset.toString(16)}`),'',
    '## Importações',...b.imports.map(i=>`- ${i}`),'','## Símbolos',...b.functions.map(f=>`- ${f.name} @ ${f.address}`),'','## Strings',...r.strings.map(s=>`- ${s.offset}: ${JSON.stringify(s.value)}`),'',
    `## Instruções (${r.disassembly.backend})`,'```asm',...r.disassembly.instructions.map(i=>`${i.address}: ${i.mnemonic} ${i.operands}`),'```','',r.disassembly.note,'',r.disclaimer];
  return line.join('\n');
}
$('exportjson').addEventListener('click',()=>{if(current)download('reverselab-report.json',JSON.stringify(current,null,2),'application/json');});
$('exportmd').addEventListener('click',()=>{if(current)download('reverselab-report.md',md(current),'text/markdown');});
// Provider settings are intentionally volatile: never localStorage/sessionStorage/cookies.
const providerModelHint={
  local:['qwen3-coder-30b','Deixe vazio para usar REVERSELAB_MODEL (modelo local).'],
  openrouter:['openrouter/auto','Informe qualquer slug válido, ex.: anthropic/claude-sonnet-4.5. Deixe vazio para openrouter/auto.'],
  chatgpt:['(padrão do Codex)','Deixe vazio para utilizar o modelo padrão autorizado em sua conta Codex.']
};
function updateProvider(){
  const p=$('provider').value;
  $('openrouter-options').hidden=p!=='openrouter';
  $('chatgpt-options').hidden=p!=='chatgpt';
  $('model').value='';
  $('model').placeholder=providerModelHint[p][0];
  $('model-help').textContent=providerModelHint[p][1];
  $('ai-endpoint').textContent={local:'Somente servidor local',openrouter:'Envio para api.openrouter.ai após clicar',chatgpt:'Codex CLI autenticado no computador'}[p];
}
$('provider').addEventListener('change',updateProvider);
updateProvider();
async function checkCodex(){
  $('codex-status').textContent='Verificando...';
  try{
    const r=await fetch('/api/status'); const j=await r.json();
    $('codex-status').textContent=j.codex?.message || 'Status indisponível';
  }catch(e){$('codex-status').textContent='Não foi possível verificar o Codex.';}
}
$('check-codex').addEventListener('click',checkCodex);
$('fetch-models').addEventListener('click',async()=>{
  const btn=$('fetch-models');btn.disabled=true;$('models-status').textContent='Buscando catálogo…';
  try{
    const res=await fetch('/api/models');const obj=await res.json();
    if(!res.ok)throw Error(obj.error||'Falha HTTP '+res.status);
    const list=$('models-list');list.replaceChildren();
    for(const item of obj.models){
      const option=document.createElement('option');option.value=item.id;option.label=item.name;list.append(option);
    }
    $('models-status').textContent=`${obj.models.length} sugestões carregadas; também é possível digitar outros modelos.`;
  }catch(e){$('models-status').textContent=e.message;}
  finally{btn.disabled=false;}
});
$('ask').addEventListener('click',async()=>{
  if(!current)return;
  const provider=$('provider').value;
  const key=provider==='openrouter' ? $('openrouter-key').value : '';
  const model=$('model').value.trim();
  const btn=$('ask');btn.disabled=true;btn.textContent='Consultando modelo...';
  $('airesponse').textContent='Aguardando resposta do provedor escolhido.';
  try{
    const res=await fetch('/api/explain',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({report:current,question:$('question').value,provider,model,api_key:key})});
    const obj=await res.json();
    if(!res.ok)throw Error(obj.error||`HTTP ${res.status}`);
    $('airesponse').textContent=obj.explanation;
  }catch(e){$('airesponse').textContent='IA indisponível: '+e.message+'\n\nA análise estática continua disponível sem IA.';}
  finally{btn.disabled=false;btn.textContent='✦ Consultar IA';}
});
fetch('/api/status').then(r=>r.json()).then(d=>{ $('codex-status').textContent=d.codex?.message||'Não verificado'; }).catch(()=>{});
