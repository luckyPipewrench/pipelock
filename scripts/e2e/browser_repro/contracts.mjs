// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Pure observations shared with contract tests; no browser/process side effects.
export function responseBlockReason(headers) {
  const entry=Object.entries(headers||{}).find(([name])=>name.toLowerCase()==='x-pipelock-block-reason');
  return entry?String(entry[1]):null;
}

export function checkAPIError(scenario, state, response) {
  if(state?.state!=='error')throw Error(`${scenario} did not reach an application error`);
  if(scenario==='error'){
    if(state.error!=='HTTP 503'||response?.status!==503)throw Error('error case did not observe intended HTTP 503');
  }else if(scenario==='incomplete'){
    // A truncated upstream body is rejected by Pipelock before delivery.
    // A generic 403 (allowlist/auth/etc.) is not evidence of this control.
    if(state.error!=='HTTP 403'||response?.status!==403||response.block_reason!=='parse_error')
      throw Error('incomplete case did not observe the attributed proxy parse-error refusal');
  }else throw Error(`unsupported error scenario: ${scenario}`);
}

export function isLoginRequired(state, expectedOrigin) {
  // Observe the form and its origin, not just a URL transition. A fixture can
  // serve its login state at /account or redirect the browser to /login.
  return typeof expectedOrigin==='string'&&state?.origin===expectedOrigin&&state.action_origin===expectedOrigin&&
    state.ready==='complete'&&['/account','/login'].includes(state.path)&&
    state.form==='fixture-login'&&state.method==='post'&&state.action==='/session'&&
    state.user===true&&state.code===true&&state.submit===true&&state.appReady===false;
}

export async function collectScenarios(names, observe) {
  const results=[];
  for(const name of names){
    try{results.push({name,...await observe(name)});}
    catch(error){results.push({name,status:'fail',failure:String(error.message||error).slice(0,512)});}
  }
  return results;
}

export function checkManagedIdentity(settings, identity, route) {
  if(!Number.isInteger(identity?.uid)||identity.uid<=0||identity.uid!==settings.expected_uid||
    !Number.isInteger(identity.gid)||identity.gid<=0||identity.gid!==settings.expected_gid)
    throw Error('managed runtime is not the expected nonroot identity');
  if(identity.exec_path!==settings.expected_node?.exec_path||identity.version!==settings.expected_node?.version||
    identity.release!=='node')throw Error('managed Node identity differs from prepared runtime');
  if(settings.proxy||route.upper!==settings.expected_proxy||route.lower!==route.upper)
    throw Error('managed proxy route differs from the installed runtime contract');
}

export const loginObservation=`(()=>{const form=document.getElementById('fixture-login');const action=form?new URL(form.action):null;return {
  ready:document.readyState,origin:location.origin,path:location.pathname,form:form?.id||null,
  method:form?.method||null,action:action?.pathname||null,action_origin:action?.origin||null,
  user:!!form?.querySelector('#user'),code:!!form?.querySelector('#code'),
  submit:!!form?.querySelector('#login'),appReady:window.fixture?.state==='ready'
}})()`;
