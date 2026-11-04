(() => {
'use strict';
let activeRoot;
const $ = (s, root=activeRoot) => root.querySelector(s);
const $$ = (s, root=activeRoot) => [...root.querySelectorAll(s)];
const sections=['Overview','Theory','Procedure','Simulator','Comparison','Assessment','Quiz','References','Feedback'];
const icons=['▦','▤','☷','◇','⊞','◎','?','↗','✎'];
const keys=['packet','stateful','circuit','proxy','ngfw','waf'];
const names=['Packet Filtering','Stateful Inspection','Circuit-Level Gateway','Application-Level Gateway / Proxy','Next-Generation Firewall','Web Application Firewall'];
const storage={get(k,f){try{const v=JSON.parse(localStorage.getItem('group-exp-fw-'+k));return v??f;}catch{return f;}},set(k,v){try{localStorage.setItem('group-exp-fw-'+k,JSON.stringify(v));return true;}catch{toast('Browser storage unavailable; progress lasts for this session.');return false;}}};
const savedVisited=storage.get('visited',[]);
let visited=new Set((Array.isArray(savedVisited)?savedVisited:[]).filter(x=>sections.map(s=>s.toLowerCase()).includes(x)));
let quiz=storage.get('quiz',{answers:[],index:0});
if(!quiz||!Array.isArray(quiz.answers)||!Number.isInteger(quiz.index)||quiz.index<0||quiz.index>10)quiz={answers:[],index:0};
let logs=[], busy=false, simulationRun=0;
const defaults=()=>[{priority:10,action:'deny',protocol:'TCP',port:'22',source:'*',destination:'*',direction:'any'},{priority:20,action:'allow',protocol:'TCP',port:'80',source:'*',destination:'*',direction:'any'},{priority:30,action:'allow',protocol:'TCP',port:'443',source:'*',destination:'*',direction:'any'},{priority:40,action:'allow',protocol:'UDP',port:'53',source:'*',destination:'*',direction:'any'}];
let rules=defaults();
const base={source:'192.0.2.10',destination:'198.51.100.20',protocol:'TCP',port:443,direction:'outbound',state:'new',application:'HTTPS',path:'/',threat:'none',session:'valid'};
let packet={...base},firewall='packet';
const presets=[['Normal browsing',{}],['Blocked SSH',{port:22,application:'SSH'}],['DNS query',{protocol:'UDP',port:53,application:'DNS'}],['Suspicious payload',{threat:'malware'}],['Malicious HTTP request',{port:80,application:'HTTP',path:'/search?q=%27%20OR%201%3D1',threat:'sqli'}],['Established connection',{port:8443,state:'established'}]];
function toast(msg){$('#toast').textContent=msg;$('#toast').classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').classList.remove('show'),3000);}
const shield='<svg viewBox="0 0 40 40" aria-hidden="true"><path d="M20 4 33 9v11c0 9-13 16-13 16S7 29 7 20V9Z"/><path d="m14 20 4 4 9-10"/></svg>';
const monitor='<svg viewBox="0 0 40 40" aria-hidden="true"><rect x="5" y="6" width="30" height="23" rx="3"/><path d="M20 29v6m-8 0h16M6 24h28"/></svg>';
const server='<svg viewBox="0 0 40 40" aria-hidden="true"><rect x="9" y="4" width="22" height="32" rx="3"/><path d="M9 15h22M9 25h22m-16-15h2m-2 10h2m-2 10h2"/></svg>';
function topology(){return `<div class="topology" id="topology"><div class="node">${monitor}<strong>Client</strong><small>Traffic source</small></div><div class="wire"></div><div class="node firewall">${shield}<strong>Firewall</strong><small>Policy checkpoint</small></div><div class="wire"></div><div class="node">${server}<strong>Server</strong><small>Destination</small></div><span class="packet"></span></div>`;}
function intro(title,text){return `<div class="section-intro"><h2>${title}</h2><p>${text}</p></div>`;}
function options(items,selected){return items.map(x=>`<option value="${x}" ${x===selected?'selected':''}>${x}</option>`).join('');}
function headerRule(p,rs){return [...rs].sort((a,b)=>a.priority-b.priority).find(r=>(r.protocol==='any'||r.protocol===p.protocol)&&(r.port==='*'||(p.protocol!=='ICMP'&&Number(r.port)===Number(p.port)))&&(r.source==='*'||r.source===p.source)&&(r.destination==='*'||r.destination===p.destination)&&(r.direction==='any'||r.direction===p.direction));}
function evaluate(type,p,rs=rules){
 const steps=[];const done=(allowed,reason)=>({allowed,reason,steps});
 const http=['HTTP','HTTPS'].includes(p.application)&&p.protocol==='TCP';
 if(type==='waf'){
  steps.push('Check whether traffic is a modeled HTTP(S) request.');
  if(!http)return done(true,'Outside WAF scope: passed through uninspected. This is not a safety endorsement.');
  steps.push('Inspect the decoded HTTP path and simulated SQL injection / XSS indicators. HTTPS is assumed decrypted.');
  let path=p.path;try{path=decodeURIComponent(path);}catch{}
  if(['sqli','xss'].includes(p.threat)||/<script|\bunion\s+select\b|\bor\s+1\s*=\s*1/i.test(path))return done(false,'Web attack pattern detected by the WAF policy.');
  return done(true,'No modeled HTTP attack pattern matched. Network header rules do not apply to this standalone WAF.');
 }
 if(['stateful','ngfw'].includes(type)){
  steps.push('Consult the simulated connection table: state is supplied by the lab, not trusted packet metadata in a real firewall.');
  if(p.state==='invalid')return done(false,'Invalid connection state rejected.');
 }
 let established=['stateful','ngfw'].includes(type)&&p.state==='established';
 if(established)steps.push('Existing tracked connection accepted before new-connection header rules.');
 else{const r=headerRule(p,rs);steps.push('Match source, destination, protocol, destination port and direction; first priority match wins.');if(!r)return done(false,'No header rule matched. Default deny.');steps.push(`Priority ${r.priority}: ${r.action.toUpperCase()} matched.`);if(r.action==='deny')return done(false,`Denied by header rule at priority ${r.priority}.`);}
 if(type==='circuit'){steps.push('Validate a modeled TCP session negotiation; do not inspect application content.');if(p.protocol!=='TCP'||p.session!=='valid'||p.state==='invalid')return done(false,'A valid TCP session is required by this circuit-gateway model.');}
 if(type==='proxy'){steps.push('Terminate and relay supported HTTP(S) sessions; apply a URL policy. HTTPS is assumed decrypted.');if(!http)return done(false,'This proxy only supports HTTP(S) over TCP.');if(/^\/admin(?:[/?#]|$)/i.test(p.path))return done(false,'Proxy URL policy denies the /admin area.');}
 if(type==='ngfw'){steps.push('Check declared application identity, then simulated threat signatures. HTTPS inspection is assumed available.');if(!['HTTP','HTTPS','DNS'].includes(p.application))return done(false,'Application policy denies this application.');if(p.threat!=='none')return done(false,'Simulated threat signature detected.');}
 return done(true, type==='packet'?'Header policy permits traffic; payload and connection state were not inspected.':type==='stateful'?'Connection and header policy permit traffic; payload was not inspected.':type==='circuit'?'Session policy permits the circuit; payload was not inspected.':type==='proxy'?'Supported application and URL policy permit this request.':'Connection, application and threat policies permit this traffic.');
}
const theory=[
 ['Headers, not content','Matches network and transport header fields such as IP addresses, protocol and ports. A stateless filter evaluates each packet independently.','Fast and simple for basic network boundaries. It cannot infer whether an allowed web request carries an attack.','In this lab, ordered header rules apply and unmatched traffic is denied.'],
 ['Context across a connection','Tracks flows and uses their connection state when deciding whether traffic belongs to an accepted exchange. State is maintained by the device, not a flag a sender may freely assert.','Useful for return traffic and blocking invalid flows. Connection tracking does not inherently inspect application payloads.','The lab accepts established traffic before new-flow rules and rejects invalid state.'],
 ['A gate for sessions','A circuit gateway controls transport sessions, commonly using a SOCKS-style relay. It can validate session negotiation without understanding each application payload.','Useful for controlled session relay. It does not inherently identify SQL injection or malware in permitted content.','This simplified gateway requires valid TCP negotiation after header approval; UDP relay is not modeled.'],
 ['An application-aware intermediary','An application gateway terminates a connection and creates another on behalf of the client. It can enforce protocol-specific commands, destinations or content rules.','Fine-grained application control, with additional processing and configuration. Support depends on the proxy protocol.','This HTTP(S) proxy denies /admin paths. It is not a universal attack detector; HTTPS is assumed decrypted.'],
 ['Multiple inspection layers','NGFW products commonly combine stateful filtering with application identification and intrusion prevention. Features and policies vary by implementation.','Can identify disallowed applications and known attack signatures. Visibility into encrypted payloads requires appropriate inspection.','This lab combines connection state, a declared application allowlist and explicit simulated threat indicators.'],
 ['A specialist for web requests','A WAF applies application-layer rules to HTTP requests and responses to help protect web services, including checks for common injection patterns.','Complements network firewalls. It cannot replace network controls for arbitrary SSH, DNS or other non-HTTP traffic.','This WAF inspects HTTP(S) path patterns and SQL injection / XSS flags. Other traffic passes through outside its scope.']
];
function overview(){return `<div class="hero"><div class="hero-top"><span class="eyebrow">YOUR FIRST LINE OF DEFENSE</span><span class="tag">Hands-on learning</span></div><h2>One network.<br>Six ways to protect it.</h2><p>Meet the technologies that stand between trusted systems and untrusted traffic. Then put each one to the test.</p><div class="actions"><button class="primary" data-go="simulator">Launch simulator &nbsp; →</button><button data-go="theory">Explore the theory</button></div>${topology()}</div><div class="stats"><div class="stat"><b>06</b><span>Firewall<br>architectures</span></div><div class="stat"><b>06</b><span>Real-world<br>traffic presets</span></div><div class="stat"><b>10</b><span>Knowledge<br>check questions</span></div></div><div class="section-title"><h2>What you’ll take away</h2><small>LEARN BY DOING</small></div><div class="grid"><article class="card"><span class="card-number">01 / UNDERSTAND</span><h3>Know your defenses</h3><p>Aim: investigate how six firewall architectures evaluate traffic and where their visibility ends.</p><ul><li>Distinguish header, connection, session and application inspection.</li><li>Explain the role of a web application firewall.</li></ul></article><article class="card"><span class="card-number">02 / APPLY</span><h3>Turn policies into decisions</h3><p>Build a policy, predict the outcome and follow each inspection step.</p><ul><li>Configure ordered allow and deny rules.</li><li>Compare decisions and justify a defense for a scenario.</li></ul></article></div>`;}
function renderTheory(){return intro('Six architectures. Different perspectives.','Open a card to explore the trade-offs and the policy used in this lab.')+`<div class="grid">${theory.map((t,i)=>`<article class="card"><span class="card-number">0${i+1} / ${t[0].toUpperCase()}</span><h3>${names[i]}</h3><p>${t[1]}</p><details><summary>Capabilities & lab behavior</summary><p>${t[2]}</p><p>${t[3]}</p><button data-type="${keys[i]}">Try this firewall →</button></details></article>`).join('')}</div>`;}
function procedure(){return intro('Your experiment, step by step','Use the default rules first. Change one variable at a time to isolate its effect.')+[['Review the architectures','Read Theory and identify which fields each firewall can inspect.'],['Choose a baseline','Open Simulator, choose Packet Filtering and load Normal browsing. Predict ALLOWED.'],['Inspect and run','Review IPs, TCP port 443 and the allow rule. Run and read the inspection trace.'],['Change the policy','Change the port to 22. The priority 10 deny rule should block it. Edit priorities and see which matching rule wins.'],['Compare capabilities','Load Suspicious payload and compare all six firewalls. NGFW blocks the threat flag; header-only filtering does not.'],['Test state and web scope','Load Established connection, then compare Packet Filtering with Stateful Inspection. Try Malicious HTTP request with WAF. Non-HTTP traffic is outside WAF scope.'],['Check your understanding','Complete five practical predictions, then the ten-question quiz. Your quiz progress is saved locally.']].map((s,i)=>`<div class="card step"><span>${i+1}</span><div><h3>${s[0]}</h3><p>${s[1]}</p></div></div>`).join('')+'<button class="primary" data-go="simulator">Open the simulator →</button>';}
function field(label,id,values,value){return `<label>${label}${values?`<select id="${id}">${options(values,value)}</select>`:`<input id="${id}" required ${id==='port'?'type="number" min="1" max="65535"':id==='path'?'maxlength="500"':'maxlength="15"'}>`}</label>`;}
function simulator(){return intro('Simulation Controls','Choose a firewall, then click a scenario to watch it run automatically.')+`<div class="card"><div class="sim-top"><label>Firewall architecture<select id="firewall">${keys.map((k,i)=>`<option value="${k}" ${k===firewall?'selected':''}>${names[i]}</option>`).join('')}</select></label><span class="tag">SIMULATION ONLY</span></div><div class="mini-title">Choose a scenario · runs automatically</div><div class="presets">${presets.map((p,i)=>`<button data-preset="${i}">${p[0]}</button>`).join('')}</div>${topology()}<div class="journey" aria-label="Packet journey"><span data-stage="send">1 · Send</span><span data-stage="inspect">2 · Inspect</span><span data-stage="finish">3 · Outcome</span></div><p id="journey-status" role="status" class="journey-status">Choose a scenario to trace its journey.</p><p id="packet-summary" class="packet-summary"></p><div class="actions"><button type="button" class="primary" id="run">▷ Replay simulation</button><button type="button" id="compare">Compare firewalls</button><button type="button" id="reset">Reset workbench</button></div><div id="verdict" class="verdict" role="status">Choose a scenario above to begin.</div><div id="comparison-results"></div><details id="advanced"><summary>Advanced settings · packet details & firewall rules</summary><p>Optional: edit the traffic or policy, then select Apply & run. Scenarios use your current rules.</p><form id="packet-form" novalidate><fieldset id="packet-controls"><div class="fields">${field('Source IPv4','source')}${field('Destination IPv4','destination')}${field('Protocol','protocol',['TCP','UDP','ICMP'],packet.protocol)}${field('Destination port (ignored for ICMP)','port')}${field('Direction','direction',['outbound','inbound'],packet.direction)}${field('Tracked connection state','state',['new','established','invalid'],packet.state)}${field('Application identity (declared)','application',['HTTPS','HTTP','DNS','SSH','Other'],packet.application)}${field('HTTP path (decrypted model)','path')}${field('Simulated threat','threat',['none','malware','sqli','xss'],packet.threat)}${field('Session negotiation','session',['valid','failed'],packet.session)}</div><div class="mini-title">Network header rules</div><p style="font-size:11px">Lowest priority number first; ties use row order. * matches any IP or port. Default deny. WAF uses its own web policy. Tracked established flows bypass these rules in Stateful / NGFW.</p><div class="scroll"><div id="rules" class="rules-inner"></div></div><button type="button" id="add-rule">+ Add rule</button><button type="submit" class="primary apply-run">Apply & run</button></fieldset></form></details></div><div class="log-toolbar"><h3>Traffic log</h3><label>Show<select id="log-filter"><option>All</option><option>Allowed</option><option>Blocked</option></select></label><button id="clear-logs">Clear log</button></div><div id="logs"></div>`;}
function readPacket(){const f=$('#packet-form');if(!f.checkValidity()){$('#advanced').open=true;f.reportValidity();return null;}const p={};for(const k of Object.keys(base))p[k]=$('#'+k).value;p.port=Number(p.port);for(const k of ['source','destination'])if(!validIP(p[k])){$('#advanced').open=true;toast('Enter a valid IPv4 address for '+k+'.');$('#'+k).focus();return null;}if(!p.path.startsWith('/')){$('#advanced').open=true;toast('HTTP path must begin with /.');$('#path').focus();return null;}const rs=[];for(const row of $$('.rule')){const r={};for(const el of $$('[data-field]',row))r[el.dataset.field]=el.value;r.priority=Number(r.priority);if(!Number.isInteger(r.priority)||r.priority<0||!['source','destination'].every(k=>r[k]==='*'||validIP(r[k]))||!(r.port==='*'||(/^\d+$/.test(r.port)&&Number(r.port)>0&&Number(r.port)<=65535))){$('#advanced').open=true;toast('Check rule priority, IPv4 addresses and port (1–65535 or *).');return null;}rs.push(r);}rules=rs;packet=p;firewall=$('#firewall').value;return p;}
function validIP(ip){return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip)&&ip.split('.').every(n=>Number(n)<=255&&String(Number(n))===n);}
function renderRules(){const container=$('#rules');container.replaceChildren();rules.forEach((r,i)=>{const row=document.createElement('div');row.className='rule';for(const [key,values] of [['priority',null],['action',['allow','deny']],['protocol',['any','TCP','UDP','ICMP']],['port',null],['source',null],['destination',null],['direction',['any','inbound','outbound']]]){const label=document.createElement('label');label.textContent=key;const input=document.createElement(values?'select':'input');input.dataset.field=key;if(values)for(const v of values){const o=new Option(v,v);input.add(o);}else{input.required=true;if(key==='priority'){input.type='number';input.min=0;input.max=99999;}}input.value=r[key];label.append(input);row.append(label);}const remove=document.createElement('button');remove.type='button';remove.textContent='×';remove.title='Remove rule '+(i+1);remove.setAttribute('aria-label',remove.title);remove.onclick=()=>{if(!readPacket())return;rules.splice(i,1);renderRules();};row.append(remove);container.append(row);});}
function fillPacket(){for(const k of Object.keys(base))$('#'+k).value=packet[k];}
function renderLogs(){const box=$('#logs');box.replaceChildren();const filtered=logs.filter(l=>$('#log-filter').value==='All'||(l.result.allowed?'Allowed':'Blocked')===$('#log-filter').value);if(!filtered.length){box.innerHTML='<div class="empty">No matching traffic yet. Run a simulation to begin your observation log.</div>';return;}const table=document.createElement('table');const head=document.createElement('tr');for(const h of ['Time','Firewall','Traffic','Decision']){const th=document.createElement('th');th.textContent=h;head.append(th);}table.append(head);for(const l of filtered){const row=document.createElement('tr');for(const value of [l.time,names[keys.indexOf(l.type)],`${l.packet.protocol} / ${l.packet.port}`,l.result.allowed?'ALLOWED':'BLOCKED']){const td=document.createElement('td');td.textContent=value;row.append(td);}table.append(row);}const wrap=document.createElement('div');wrap.className='scroll';wrap.append(table);box.append(wrap);}
function updatePacketSummary(){
 if($('#prediction-feedback'))$('#prediction-feedback').textContent='';
 $('#packet-summary').textContent=`${packet.application} · ${packet.protocol} / ${packet.port} · ${packet.state} connection · Threat: ${packet.threat}`;
}
function positionPacket(graph){
 const nodes=$$('.node',graph),rect=graph.getBoundingClientRect();
 if(nodes.length!==3)return;
 const boxes=nodes.map(n=>n.getBoundingClientRect());
 // Local layout coordinates also work when the browser is zoomed.
 const scale=graph.offsetWidth/rect.width;
 const center=box=>(box.left+box.width/2-rect.left)*scale;
 graph.style.setProperty('--packet-start',center(boxes[0])+'px');
 graph.style.setProperty('--packet-gate',center(boxes[1])+'px');
 graph.style.setProperty('--packet-end',center(boxes[2])+'px');
 graph.style.setProperty('--packet-y',((boxes[0].top+boxes[0].height/2-rect.top)*scale)+'px');
}
function journeyStage(stage,message){
 $$('[data-stage]').forEach(el=>el.classList.toggle('active',el.dataset.stage===stage));
 $('#journey-status').textContent=message;
}
async function runSimulation(){
 if(busy)return;
 const p=readPacket();if(!p)return;
 const type=firewall,result=evaluate(type,p),runId=++simulationRun;
 const graph=$('#topology'),alive=()=>runId===simulationRun&&graph.isConnected;
 busy=true;updatePacketSummary();
 $('#comparison-results').replaceChildren();
 $('#run').disabled=true;$('#run').textContent='Following packet…';
 $('#packet-controls').disabled=true;
 $('#verdict').className='verdict';$('#verdict').textContent='Follow the packet through each inspection stage.';
 graph.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'center'});
 graph.classList.remove('sending','inspecting','delivering','rejected','delivered','running','blocked');
 positionPacket(graph);void graph.offsetWidth;
 graph.classList.add('sending');journeyStage('send','Sending '+p.application+' traffic from the client…');
 await new Promise(resolve=>setTimeout(resolve,700));if(!alive())return;
 graph.classList.replace('sending','inspecting');
 journeyStage('inspect',names[keys.indexOf(type)]+' is checking its policy…');
 $('#verdict').textContent=result.steps.join(' ');
 await new Promise(resolve=>setTimeout(resolve,1100));if(!alive())return;
 graph.classList.remove('inspecting');graph.classList.add(result.allowed?'delivering':'rejected');
 journeyStage('finish',result.allowed?'Policy permits this packet. Forwarding to the server…':'Packet stopped at the firewall. Nothing reaches the server.');
 await new Promise(resolve=>setTimeout(resolve,700));if(!alive())return;
 if(result.allowed){graph.classList.replace('delivering','delivered');journeyStage('finish','Packet arrived at the server.');}
 busy=false;$('#run').disabled=false;$('#run').textContent='▷ Replay simulation';$('#packet-controls').disabled=false;
 showVerdict(result);
 if(prediction!==null){$('#prediction-feedback').textContent=(prediction===result.allowed?'Your prediction was correct.':'Your prediction was different. Read the reason below to see why.');prediction=null;}
 if(result.allowed&&p.threat!=='none'){
  const note=document.createElement('p');note.className='scope-warning';
  note.textContent='Learning moment: allowed does not mean safe. This policy did not block the simulated threat. Compare firewalls to explore their different capabilities.';$('#verdict').append(note);
 }
 logs.unshift({time:new Date().toLocaleTimeString(),type,packet:{...p},result});logs=logs.slice(0,100);renderLogs();
}
function cancelSimulation(){
 simulationRun++;busy=false;
 const graph=$('#topology');if(graph)graph.classList.remove('sending','inspecting','delivering','rejected','delivered');
 if($('#journey-status'))journeyStage('','Choose a scenario or replay the current packet.');
 if($('#packet-controls'))$('#packet-controls').disabled=false;
 if($('#run')){$('#run').disabled=false;$('#run').textContent='▷ Replay simulation';}
}
function bindSimulator(){
 fillPacket();renderRules();renderLogs();updatePacketSummary();
 $('#packet-form').onsubmit=e=>{e.preventDefault();runSimulation();};
 $('#run').onclick=runSimulation;
 $$('[data-preset]').forEach(b=>b.onclick=()=>{
  cancelSimulation();packet={...base,...presets[Number(b.dataset.preset)][1]};fillPacket();$('#scenario-story').textContent=scenarioStories[Number(b.dataset.preset)];
  $$('[data-preset]').forEach(button=>button.setAttribute('aria-pressed',String(button===b)));
  runSimulation();
 });
 $('#firewall').onchange=()=>{cancelSimulation();firewall=$('#firewall').value;updateCapabilities();runSimulation();};
 $('#add-rule').onclick=()=>{if(!readPacket())return;rules.push({priority:50,action:'allow',protocol:'any',port:'*',source:'*',destination:'*',direction:'any'});renderRules();};
 $('#compare').onclick=()=>{cancelSimulation();$('#topology').classList.remove('running');compareResults();if($('#comparison-results').children.length)showVerdict(evaluate(firewall,packet));};
 $('#reset').onclick=()=>{cancelSimulation();packet={...base};rules=defaults();firewall='packet';render();toast('Default packet and rules restored.');};
 $('#log-filter').onchange=renderLogs;
 $('#clear-logs').onclick=()=>{logs=[];renderLogs();toast('Traffic log cleared.');};
 $('#packet-form').oninput=()=>{$$('[data-preset]').forEach(b=>b.setAttribute('aria-pressed','false'));};
}
function comparison(){return intro('Choose the right inspection depth','These capabilities overlap in real products. Select a focus to compare the six architectures.')+`<div class="card"><label>Focus<select id="comparison-focus"><option value="all">All architectures</option><option value="content">Application / content aware</option><option value="state">Connection / session aware</option></select></label><div class="scroll"><table><thead><tr><th>Architecture</th><th>Primary visibility</th><th>Strength</th><th>Important limit</th></tr></thead><tbody id="comparison-body"></tbody></table></div><p style="font-size:11px;margin-top:18px">Higher inspection depth is not automatically better for every deployment. Policy, performance, protocol support and encryption all matter.</p><button data-go="simulator">Compare a live scenario →</button></div>`;}
const compareData=[['Headers','Simple network policy','No payload or state analysis'],['Headers + flow state','Track permitted exchanges','Not inherently content aware'],['Session negotiation','Control session relay','No inherent payload analysis'],['Application protocol','Protocol and URL policies','Protocol support is limited'],['State + app + signatures','Layer multiple controls','Signatures and visibility have limits'],['HTTP application data','Protect web services','Non-HTTP traffic outside scope']];
function renderComparison(){const filter=$('#comparison-focus').value;$('#comparison-body').innerHTML=keys.map((k,i)=>({k,i})).filter(({k})=>filter==='all'||(filter==='content'?['proxy','ngfw','waf']:['stateful','circuit','ngfw']).includes(k)).map(({i})=>`<tr><td><strong>${names[i]}</strong></td>${compareData[i].map(t=>`<td>${t}</td>`).join('')}</tr>`).join('');}
const practicalBank=[
 ['A permitted web connection','packet',{}],
 ['An SSH attempt','stateful',{port:22,application:'SSH'}],
 ['A tracked return flow','stateful',{port:8443,state:'established'}],
 ['An allowed port, unsafe content','ngfw',{threat:'malware'}],
 ['A web attack','waf',{port:80,application:'HTTP',threat:'sqli'}],
 ['A DNS lookup','packet',{protocol:'UDP',port:53,application:'DNS'}],
 ['An unknown destination port','packet',{port:8080,application:'HTTP'}],
 ['State without state tracking','packet',{port:8443,state:'established'}],
 ['A suspicious connection state','stateful',{state:'invalid'}],
 ['Content beyond header inspection','packet',{threat:'malware'}],
 ['A failed session negotiation','circuit',{session:'failed'}],
 ['A valid web circuit','circuit',{}],
 ['UDP through a circuit gateway','circuit',{protocol:'UDP',port:53,application:'DNS'}],
 ['A restricted proxy path','proxy',{path:'/admin/settings'}],
 ['A public proxy path','proxy',{path:'/courses'}],
 ['DNS through a web proxy','proxy',{protocol:'UDP',port:53,application:'DNS'}],
 ['An unapproved application','ngfw',{application:'Other'}],
 ['A clean tracked application','ngfw',{port:8443,state:'established'}],
 ['A clean web request','waf',{path:'/courses'}],
 ['Traffic outside web inspection','waf',{port:22,application:'SSH'}],
 ['A script injection indicator','waf',{threat:'xss'}],
 ['An attack in an established flow','ngfw',{state:'established',threat:'sqli'}],
 ['A clean DNS application','ngfw',{protocol:'UDP',port:53,application:'DNS'}],
 ['A new connection with no matching rule','stateful',{port:9000}]
];
let practical=[];
let previousAssessment=storage.get('assessment-last',[]);
if(!Array.isArray(previousAssessment))previousAssessment=[];
function newAssessment(){
 const candidates=practicalBank.map((_,i)=>i).filter(i=>!previousAssessment.includes(i));
 for(let i=candidates.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[candidates[i],candidates[j]]=[candidates[j],candidates[i]];}
 const selected=candidates.slice(0,5);
 previousAssessment=selected;
 storage.set('assessment-last',selected);
 practical=selected.map(i=>{
  const [title,type,changes]=practicalBank[i],p={...base,...changes};
  const description=`${names[keys.indexOf(type)]} evaluates ${p.direction} ${p.protocol} traffic from ${p.source} to ${p.destination}, destination port ${p.port}. Tracked state: ${p.state}. Application: ${p.application}. Path: ${p.path}. Threat indicator: ${p.threat}. Session negotiation: ${p.session}.`;
  return [title,description,type,changes];
 });
 assessments={};
}
let assessments={};
function assessment(){newAssessment();return intro('Predict before you inspect','Five fresh scenarios from a bank of 24. None repeat from your previous set. Default policy applies, regardless of simulator edits.')+`<div id="assessment-score" class="verdict">0 of 5 scenarios evaluated</div><div class="grid" style="margin-top:18px">${practical.map((p,i)=>`<article class="card"><span class="card-number">SCENARIO 0${i+1}</span><h3>${p[0]}</h3><p>${p[1]}</p><div class="actions"><button data-predict="${i}" data-answer="true">Allowed</button><button data-predict="${i}" data-answer="false">Blocked</button></div><p id="assessment-${i}" class="feedback-message" role="status"></p></article>`).join('')}</div><button id="restart-assessment" style="margin-top:18px">New questions ↻</button>`;}
function gradeAssessment(i,answer){if(Object.hasOwn(assessments,i))return;const p=practical[i],r=evaluate(p[2],{...base,...p[3]},defaults());assessments[i]=answer===r.allowed;$('#assessment-'+i).textContent=(assessments[i]?'Correct. ':'Not quite. ')+r.reason;$$(`[data-predict="${i}"]`).forEach(b=>{b.disabled=true;});const n=Object.keys(assessments).length;if(n===5){storage.set('assessment-result',{score:Object.values(assessments).filter(Boolean).length,total:5,date:new Date().toISOString(),review:practical.filter((_,j)=>!assessments[j]).map(p=>p[0])});if($('#completion-report'))$('#completion-report').replaceWith(completionReport());}$('#assessment-score').textContent=`${n} of 5 evaluated · ${Object.values(assessments).filter(Boolean).length} correct${n===5?' · Assessment complete':''}`;}
const questions=[
 ['Which field can a basic packet filter directly match?',['Destination port','SQL query intent','User behavior','Decrypted web content'],0,'Packet filters match header fields, including addresses, protocol and ports.'],
 ['What distinguishes stateful inspection?',['It blocks every UDP packet','It tracks connections','It decrypts all traffic','It replaces authentication'],1,'Stateful inspection maintains context about flows and their state.'],
 ['Which control specializes in HTTP application attacks?',['Circuit gateway','Router alone','WAF','Basic packet filter'],2,'A WAF applies web application rules to HTTP traffic.'],
 ['Why might a packet filter allow a malicious HTTPS request?',['HTTPS cannot carry attacks','It only sees relevant headers','Port 443 is always safe','It identifies every payload'],1,'An allowed port does not establish that the application content is safe.'],
 ['What does a circuit gateway primarily control?',['SQL syntax','Image files','Transport sessions','Database permissions'],2,'A circuit gateway controls session establishment and relay without inherently inspecting payload content.'],
 ['What does an application proxy do?',['Terminates and relays application connections','Only changes IP addresses','Always permits unknown protocols','Removes the need for policies'],0,'A proxy acts as an intermediary and can enforce application-specific policies.'],
 ['Which combination is typical of an NGFW?',['Only port rules','Only web caching','Only session relay','Stateful filtering, app awareness and intrusion prevention'],3,'NGFWs combine multiple controls; exact features depend on the product.'],
 ['In this lab, which matching header rule wins?',['Last row','Lowest priority number, then row order','Always allow','Highest port'],1,'The lab evaluates ascending priority and uses the first matching rule, with stable row order for ties.'],
 ['How should non-HTTP traffic be interpreted when it passes this WAF model?',['Proven safe','Fully inspected','Outside its inspection scope','Automatically authenticated'],2,'Passing through outside scope is not a judgment that the traffic is safe.'],
 ['What is required to inspect encrypted HTTP content?',['A smaller IP address','A port 443 allow rule alone','A valid DNS record alone','Suitable decryption or TLS termination'],3,'Application inspection requires visibility into the content; this lab explicitly assumes decrypted HTTPS.']
];
function quizView(){if(quiz.index>=questions.length){const score=questions.reduce((n,q,i)=>n+(quiz.answers[i]===q[2]),0);return `<div class="card result"><div class="eyebrow">KNOWLEDGE CHECK COMPLETE</div><div class="score">${score}<span style="font-size:25px"> / 10</span></div><h2>${score>=8?'A strong line of defense.':'Keep building your understanding.'}</h2><p>Every explanation is an opportunity to strengthen your knowledge.</p><button id="restart-quiz" class="primary">Try again</button></div><div class="card" style="margin-top:16px">${questions.map((q,i)=>`<h3>${i+1}. ${q[0]}</h3><p>${quiz.answers[i]===q[2]?'✓ Correct':'Review'} · ${q[1][q[2]]}. ${q[3]}</p>`).join('')}</div>`;}const q=questions[quiz.index],answer=quiz.answers[quiz.index];return intro('Check your understanding','Ten questions. Thoughtful answers. Progress saved on this browser.')+`<div class="card"><div class="eyebrow">QUESTION ${quiz.index+1} OF 10</div><progress max="10" value="${quiz.index}"></progress><h3>${q[0]}</h3>${q[1].map((a,i)=>`<button class="quiz-option ${answer!==undefined?(i===q[2]?'correct':i===answer?'wrong':''):''}" data-choice="${i}" ${answer!==undefined?'disabled':''}>${String.fromCharCode(65+i)}. &nbsp; ${a}</button>`).join('')}<div role="status" class="feedback-message">${answer!==undefined?(answer===q[2]?'Correct. ':'Not quite. ')+q[3]:''}</div><div class="actions">${answer!==undefined?'<button class="primary" id="next-question">'+(quiz.index===9?'View results':'Next question →')+'</button>':''}<button id="restart-quiz">Restart quiz</button></div></div>`;}
function references(){return intro('Continue your learning','Authoritative background on firewall policy and web application protection. External references require internet access.')+`<div class="card"><h3>NIST · Guidelines on Firewalls and Firewall Policy</h3><p>Special Publication 800-41 Revision 1. Foundational guidance on firewall technologies, capabilities, policy and deployment. Published in 2009; use it as architectural background, not a current product comparison.</p><a href="https://csrc.nist.gov/pubs/sp/800/41/r1/final" target="_blank" rel="noopener noreferrer">Read NIST SP 800-41 Rev. 1 ↗</a><hr><h3>OWASP · Web Application Firewall</h3><p>An introduction to WAF scope, HTTP policies and web attack protection, with links to community projects.</p><a href="https://community.owasp.org/Web_Application_Firewall" target="_blank" rel="noopener noreferrer">Explore the OWASP reference ↗</a><hr><h3>Lab interpretation</h3><p>Architectures are teaching categories, not mutually exclusive product classes. Policies shown here are explicit examples, not universal behavior for every firewall of a given type.</p></div>`;}
const scenarioStories=[
 'A student opens a secure website. Can this connection reach the server?',
 'Someone tries to access the server remotely using SSH. Does the policy permit it?',
 'A computer asks DNS to translate a website name into an IP address. Will the query pass?',
 'A secure web connection carries a simulated malware indicator. Can this firewall detect it?',
 'A web request contains a simulated SQL injection attack. Does this firewall inspect web content?',
 'Traffic belongs to an already tracked connection on port 8443. Does this firewall remember it?'
];
const capabilityLabels=['IP & ports','Connection state','Session setup','Application','Web path','Threat signatures'];
const capabilities={packet:[0],stateful:[0,1],circuit:[0,2],proxy:[0,3,4],ngfw:[0,1,3,5],waf:[3,4,5]};
let prediction=null;
function element(tag,text,className){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;}
function updateCapabilities(){const box=$('#capabilities');if(!box)return;box.replaceChildren();capabilityLabels.forEach((label,i)=>{const active=capabilities[firewall].includes(i);const chip=element('span',(active?'✓ ':'— ')+label,active?'capability':'capability unavailable');chip.title=active?'Used by this lab model':'Not inspected by this lab model';box.append(chip);});}
function showVerdict(result){
 const box=$('#verdict');box.replaceChildren();box.className='verdict '+(result.allowed?'allowed':'blocked');
 const next=firewall==='packet'?'Switch to Next-Generation Firewall and replay the same traffic.':firewall==='waf'?'Try Blocked SSH to explore traffic outside WAF scope.':'Compare this result with Packet Filtering using the same traffic.';
 for(const [label,text] of [['What happened',result.allowed?'ALLOWED — the policy permitted this traffic.':'BLOCKED — the packet stopped at the firewall.'],['Why',result.reason],['Try next',next]]){const row=element('p');row.append(element('strong',label+': '),document.createTextNode(text));box.append(row);}
 const details=element('details'),summary=element('summary','See the inspection steps'),ol=element('ol');result.steps.forEach(step=>ol.append(element('li',step)));details.append(summary,ol);box.append(details);
}
function compareResults(){
 const p=readPacket();if(!p)return;const snapshot={...p},policy=rules.map(r=>({...r})),box=$('#comparison-results');box.replaceChildren();
 box.append(element('h3','Same traffic. Two perspectives.'),element('p','Both panels use the same packet and current rules. Change either firewall to compare its decision.'));
 const grid=element('div',undefined,'grid comparison-pair');
 [firewall,firewall==='ngfw'?'packet':'ngfw'].forEach((type,index)=>{
  const panel=element('article',undefined,'card'),label=element('label','Firewall '+(index+1)),select=element('select');
  keys.forEach((k,i)=>select.add(new Option(names[i],k)));select.value=type;label.append(select);const resultBox=element('div');
  const draw=()=>{const r=evaluate(select.value,snapshot,policy);resultBox.replaceChildren();resultBox.append(element('div',r.allowed?'Client → Firewall → Server':'Client → Firewall ⊘ Server','mini-route '+(r.allowed?'route-allow':'route-block')),element('strong',r.allowed?'ALLOWED':'BLOCKED'),element('p',r.reason));};
  select.onchange=draw;panel.append(label,resultBox);grid.append(panel);draw();
 });box.append(grid);
 const details=element('details'),summary=element('summary','View all six decisions');details.append(summary);
 keys.forEach(type=>{const r=evaluate(type,snapshot,policy);details.append(element('p',names[keys.indexOf(type)]+': '+(r.allowed?'ALLOWED':'BLOCKED')+' — '+r.reason));});box.append(details);
}
function learningGuide(){
 const guide=element('div',undefined,'learning-guide');guide.append(element('strong','Your learning path'));
 [['theory','1 · Learn'],['simulator','2 · Predict & experiment'],['assessment','3 · Practice'],['quiz','4 · Check & finish']].forEach(([hash,label])=>{const a=element('a',label);a.href='#'+hash;if(location.hash==='#'+hash)a.setAttribute('aria-current','step');guide.append(a);});return guide;
}
function completionReport(){
 const a=storage.get('assessment-result',null),complete=quiz.index===10&&quiz.answers.length===10;
 const score=complete?questions.reduce((sum,q,i)=>sum+(quiz.answers[i]===q[2]?1:0),0):null;
 const box=element('section',undefined,'card completion-report');box.id='completion-report';
 box.append(element('div','EXP-FW · DIFFERENT TYPES OF FIREWALLS','eyebrow'),element('h3',complete&&a?'Experiment complete':'Your experiment progress'));
 box.append(element('p',a?`Latest completed assessment: ${a.score} / 5 · ${new Date(a.date).toLocaleDateString()}`:'Practical assessment: not completed yet.'),element('p',complete?`Quiz: ${score} / 10`:'Quiz: complete all ten questions to receive a final score.'));
 if(a&&complete)box.append(element('strong',`Combined result: ${a.score+score} / 15`));
 const review=[];if(a&&Array.isArray(a.review))review.push(...a.review);if(complete)questions.forEach((q,i)=>{if(quiz.answers[i]!==q[2])review.push(q[0]+' '+q[3]);});
 if(review.length){box.append(element('h3','Topics to revisit'));const list=element('ul');review.forEach(text=>list.append(element('li',text)));box.append(list);}else if(a&&complete)box.append(element('p','All answers correct. Try new scenarios and custom rules to extend your learning.'));
 box.append(element('p','Scores reflect the latest completed practical assessment and the current quiz on this browser. This report is a learning record, not a certification.'));
 const actions=element('div',undefined,'actions');[['assessment','Open assessment'],['quiz','Open quiz']].forEach(([hash,text])=>{const link=element('a',text,'text-link');link.href='#'+hash;actions.append(link);});
 const print=element('button','Print / save report');print.onclick=()=>printReport(box);actions.append(print);box.append(actions);return box;
}

function sharedAim(){return `<div class="content-placeholder"><h2>Aim &amp; Objectives</h2><p><strong>Aim:</strong> Analyze how different types of firewalls inspect network traffic, enforce security policies, and protect systems against unauthorized access and simulated threats.</p><p><strong>Objectives:</strong></p><ul><li>Distinguish packet filtering, stateful inspection, circuit-level gateways, application proxies, next-generation firewalls and web application firewalls.</li><li>Configure traffic and firewall rules, observe packet decisions, and compare inspection capabilities.</li><li>Evaluate security limitations through practical scenarios and assessment questions.</li></ul></div>`;}
function sharedTheory(){return `<div class="content-placeholder"><h2>Theory</h2><p>A firewall applies a security policy to traffic crossing a network or application boundary. Different architectures inspect different information. An allowed connection is not proof that its content is safe; the decision depends on the configured policy and the firewall's visibility.</p>${theory.map((t,i)=>`<h3>${i+1}. ${names[i]}</h3><p>${t[1]}</p><p>${t[2]}</p><p><strong>In this experiment:</strong> ${t[3]}</p>`).join('')}</div>`;}
function sharedProcedure(){return `<div class="content-placeholder"><h2>Procedure</h2><ol><li>Read the theory and identify what each firewall architecture can inspect.</li><li>Open Simulation and select a firewall architecture.</li><li>Choose Normal browsing to automatically run a baseline packet. Observe the sending, inspection and outcome stages.</li><li>Choose Blocked SSH, DNS query, Suspicious payload, Malicious HTTP request or Established connection. Predict the outcome and inspect the explanation.</li><li>Select Compare firewalls to evaluate the same traffic against different architectures.</li><li>Open Advanced settings to change packet fields or ordered allow/deny rules. Select Apply &amp; run and inspect the traffic log.</li><li>Complete the practical assessment and ten-question quiz. Review missed topics and print the completion report if needed.</li></ol></div>`;}
function sharedReferences(){return `<div class="content-placeholder"><h2>References</h2><ul><li><a href="https://csrc.nist.gov/pubs/sp/800/41/r1/final" target="_blank" rel="noopener noreferrer">NIST SP 800-41 Revision 1: Guidelines on Firewalls and Firewall Policy</a> — architectural and policy background.</li><li><a href="https://community.owasp.org/Web_Application_Firewall" target="_blank" rel="noopener noreferrer">OWASP: Web Application Firewall</a> — HTTP inspection scope and web application protection.</li></ul><p>Firewall categories overlap in real products. This experiment uses explicit educational policies rather than a production security engine.</p></div>`;}

// Thin adapter: shared common.js owns the top-level tabs; this module owns only its content.
let currentView='overview';
const hostNames={overview:'aim',theory:'theory',procedure:'procedure',simulator:'simulation',comparison:'simulation',assessment:'quiz',quiz:'quiz',references:'references'};
const defaultViews={aim:'overview',theory:'theory',procedure:'procedure',simulation:'simulator',quiz:'assessment',references:'references'};
const hosts=[...document.querySelectorAll('[data-fw-host]')];
function go(view){
 const tab=hostNames[view];if(!tab)return;
 currentView=view;
 const button=document.querySelector('.tab-btn[data-tab="'+tab+'"]');
 button.click();
}
function render(){renderView(currentView);}
function renderView(view){
 if(activeRoot)cancelSimulation();prediction=null;currentView=view;
 activeRoot=document.querySelector('[data-fw-host="'+hostNames[view]+'"]');
 hosts.forEach(host=>{if(host!==activeRoot)host.replaceChildren();});
 const views={overview:sharedAim,theory:sharedTheory,procedure:sharedProcedure,simulator,comparison,assessment,quiz:quizView,references:sharedReferences};
 activeRoot.innerHTML=views[view]();
 const toastBox=element('div',undefined,'toast');toastBox.id='toast';toastBox.setAttribute('role','status');activeRoot.append(toastBox);
 
 $$('[data-go]').forEach(button=>button.onclick=()=>go(button.dataset.go));
 $$('[data-type]').forEach(button=>button.onclick=()=>{firewall=button.dataset.type;go('simulator');});
 if(view==='simulator'||view==='comparison')addSubnav([['simulator','Traffic workbench'],['comparison','Architecture comparison']]);
 if(view==='assessment'||view==='quiz')addSubnav([['assessment','Practical assessment'],['quiz','Knowledge quiz']]);
 if(view==='simulator'){bindSimulator();enhanceSimulator();}
 if(view==='comparison'){renderComparison();$('#comparison-focus').onchange=renderComparison;}
 if(view==='assessment'){
  $$('[data-predict]').forEach(button=>button.onclick=()=>gradeAssessment(Number(button.dataset.predict),button.dataset.answer==='true'));
  $('#restart-assessment').onclick=render;
 }
 if(view==='quiz'){
  $$('[data-choice]').forEach(button=>button.onclick=()=>{quiz.answers[quiz.index]=Number(button.dataset.choice);storage.set('quiz',quiz);render();});
  if($('#next-question'))$('#next-question').onclick=()=>{quiz.index++;storage.set('quiz',quiz);render();};
  $('#restart-quiz').onclick=()=>{quiz={answers:[],index:0};storage.set('quiz',quiz);render();};
 }
 if(view==='assessment'||view==='quiz')activeRoot.append(completionReport());
 // Route only our content links. Shared tab buttons, navigation and feedback stay untouched.
 activeRoot.onclick=event=>{
  const link=event.target.closest('a[href^="#"]');if(!link||!activeRoot.contains(link))return;
  const view=link.getAttribute('href').slice(1);if(hostNames[view]){event.preventDefault();go(view);}
 };
}
function addSubnav(items){
 const nav=element('div',undefined,'fw-subnav');nav.setAttribute('aria-label','Experiment activities');
 items.forEach(([view,label])=>{const button=element('button',label);button.type='button';button.setAttribute('aria-pressed',String(view===currentView));button.onclick=()=>go(view);nav.append(button);});
 activeRoot.prepend(nav);
}
function enhanceSimulator(){
 const top=$('.sim-top'),caps=element('div');caps.id='capabilities';caps.className='capabilities';top.after(caps);updateCapabilities();
 const story=element('p','Choose a scenario above. Predict the result, then follow the packet.','scenario-story');story.id='scenario-story';$('.presets').after(story);
 const predict=element('div',undefined,'prediction');predict.append(element('span','Optional: predict the next result'));
 [true,false].forEach(answer=>{const b=element('button',answer?'I predict Allowed':'I predict Blocked');b.type='button';b.onclick=()=>{prediction=answer;$$('button',predict).forEach(el=>el.setAttribute('aria-pressed',String(el===b)));$('#prediction-feedback').textContent='Prediction saved. Select a scenario or replay to test it.';};predict.append(b);});
 const feedback=element('p');feedback.id='prediction-feedback';feedback.setAttribute('role','status');predict.append(feedback);story.after(predict);
 const modeLabel=element('label','Learning mode'),mode=element('select');mode.add(new Option('Beginner — guided controls','beginner'));mode.add(new Option('Advanced — edit packets and rules','advanced'));mode.value=storage.get('mode','beginner');modeLabel.append(mode);top.append(modeLabel);$('#advanced').open=mode.value==='advanced';mode.onchange=()=>{$('#advanced').open=mode.value==='advanced';storage.set('mode',mode.value);};
 const glossary=element('details');glossary.className='glossary';glossary.append(element('summary','Quick help · what do these terms mean?'));
 [['Packet','A small unit of data traveling across a network.'],['Protocol','Rules for exchanging data; TCP and UDP are examples.'],['Port','A number identifying a destination service, such as 443 for HTTPS.'],['State','A new, established or invalid connection in this model.'],['Policy','Conditions deciding whether traffic may pass.'],['Threat indicator','A simulated marker, not a real malware scan.']].forEach(([word,meaning])=>{const row=element('p');row.append(element('strong',word+': '),document.createTextNode(meaning));glossary.append(row);});$('#advanced').after(glossary);
}
function printReport(box){
 const popup=window.open('','_blank','width=800,height=700');
 if(!popup){toast('Allow the report window to open, then try again.');return;}
 popup.opener=null;popup.document.title='Firewall experiment report';
 const report=box.cloneNode(true);report.querySelector('.actions')?.remove();
 popup.document.body.append(report);
 popup.print();
}
document.querySelectorAll('.tab-btn[data-tab]').forEach(button=>button.addEventListener('click',()=>{
 const tab=button.dataset.tab;
 if(!defaultViews[tab]){if(activeRoot)cancelSimulation();return;}
 renderView(hostNames[currentView]===tab?currentView:defaultViews[tab]);
}));
window.addEventListener('resize',()=>{const graph=activeRoot&&$('#topology');if(graph)positionPacket(graph);});
renderView('overview');
})();
