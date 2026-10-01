// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import {test} from 'node:test';
import {checkAPIError,checkManagedIdentity,collectScenarios,isLoginRequired,responseBlockReason} from './contracts.mjs';

test('truncated API requires the actual proxy parse-error refusal, not any 403',()=>{
  const state={state:'error',error:'HTTP 403'};
  assert.doesNotThrow(()=>checkAPIError('incomplete',state,{status:403,block_reason:'parse_error'}));
  for(const response of [undefined,{status:200},{status:502},{status:403},
    {status:403,block_reason:'dlp_match'},{status:403,block_reason:'prompt_injection'}])
    assert.throws(()=>checkAPIError('incomplete',state,response));
  for(const error of ['Failed to fetch','HTTP 502','HTTP 503'])
    assert.throws(()=>checkAPIError('incomplete',{state:'error',error},{status:403,block_reason:'parse_error'}));
  assert.throws(()=>checkAPIError('incomplete',{state:'ready'},{status:403,block_reason:'parse_error'}));
  assert.doesNotThrow(()=>checkAPIError('error',{state:'error',error:'HTTP 503'},{status:503}));
  assert.throws(()=>checkAPIError('error',state,{status:403,block_reason:'parse_error'}));
  assert.equal(responseBlockReason({'X-Pipelock-Block-Reason':'parse_error'}),'parse_error');
  assert.equal(responseBlockReason({}),null);
});

test('login readiness requires the exact form and origin, not just a path',()=>{
  const origin='http://browser.fixture.example';
  const form={ready:'complete',origin,action_origin:origin,path:'/account',form:'fixture-login',method:'post',
    action:'/session',user:true,code:true,submit:true,appReady:false};
  assert.equal(isLoginRequired(form,origin),true);
  assert.equal(isLoginRequired({...form,path:'/login'},origin),true);
  for(const delta of [{ready:'loading'},{path:'/session'},{form:null},{method:'get'},
    {action:'/other'},{origin:'http://other.fixture.example'},
    {action_origin:'http://other.fixture.example'},{user:false},{code:false},{submit:false},{appReady:true}])
    assert.equal(isLoginRequired({...form,...delta},origin),false);
  assert.equal(isLoginRequired({path:'/login'},origin),false);
  assert.equal(isLoginRequired(null,origin),false);
  assert.equal(isLoginRequired(form),false);
});

test('a failed independent scenario remains failed without hiding later observations',async()=>{
  const observed=[];
  const cases=await collectScenarios(['incomplete','pending','later'],async name=>{
    observed.push(name);
    if(name==='incomplete')checkAPIError(name,{state:'error',error:'HTTP 403'},
      {status:403,block_reason:'dlp_match'});
    return {status:name==='pending'?'expected_pending':'pass'};
  });
  assert.deepEqual(observed,['incomplete','pending','later']);
  assert.deepEqual(cases.map(({status})=>status),['fail','expected_pending','pass']);
  assert.equal(cases.some(({status})=>status==='fail'),true);
});

test('managed launch requires native nonroot identity and the exact installed route',()=>{
  const settings={expected_uid:1200,expected_gid:1200,expected_node:{exec_path:'/usr/bin/node',version:'24.0.0'},
    expected_proxy:'http://127.0.0.1:8888'};
  const identity={uid:1200,gid:1200,exec_path:'/usr/bin/node',version:'24.0.0',release:'node'};
  const route={upper:settings.expected_proxy,lower:settings.expected_proxy};
  assert.doesNotThrow(()=>checkManagedIdentity(settings,identity,route));
  for(const delta of [{uid:0},{gid:0},{uid:'1200'},{uid:1201},{gid:1201},
    {exec_path:'/usr/bin/mise'},{version:'22.0.0'},{release:'other'}])
    assert.throws(()=>checkManagedIdentity(settings,{...identity,...delta},route));
  for(const delta of [{upper:'http://other.fixture.example'},{lower:''},{lower:undefined}])
    assert.throws(()=>checkManagedIdentity(settings,identity,{...route,...delta}));
  assert.throws(()=>checkManagedIdentity({...settings,proxy:settings.expected_proxy},identity,route));
});
