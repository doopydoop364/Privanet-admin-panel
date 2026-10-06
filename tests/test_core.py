import base64
import json
import time
from pathlib import Path

import pytest

from agent.core import AdminBackend, Runner, redact


class FakeBroker:
    def __init__(self):
        self.calls=[]
        self.responses={}
    def set(self, action, response): self.responses[action]=response
    def call(self, action, params=None, session_key='session-default'):
        self.calls.append((action, params or {}, session_key))
        response=self.responses.get(action, {'ok':True})
        if isinstance(response, Exception): raise response
        return response


class FakeShell:
    def __init__(self):
        self.calls=[]
        self.response={'ok':True,'exitCode':0,'durationSeconds':0.01,'stdout':'ok\n','stderr':''}
    def run(self, command, timeout_seconds):
        self.calls.append((command,timeout_seconds))
        return dict(self.response)


class FakeRunner:
    def __init__(self): self.calls=[]
    def run(self, argv, **kwargs):
        self.calls.append((argv,kwargs))
        raise AssertionError('runner should not be used in this test')


def cfg(tmp_path: Path):
    updater=tmp_path/'privanet-update'; updater.write_text('#!/bin/sh\n'); updater.chmod(0o755)
    updater_config=tmp_path/'updater.json'; updater_config.write_text('{"version":1,"channel":"prerelease"}\n')
    return {
        'audit_db':str(tmp_path/'audit.sqlite3'),
        'command_home':str(tmp_path/'home'), 'command_cwd':str(tmp_path/'work'),
        'local_node_state_dir':'/var/lib/privanet-node',
        'command_path':'/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'managed_services':{'coordinator':'privanet-coordinator.service','node':'privanet-node.service','search':'privasearch.service','proxy':'privaproxy.service','updater':'privanet-update.service'},
        'executables':{'privanet_admin':'/usr/local/bin/privanet-admin','privanet_node':'/opt/privanet-node/current/bin/privanet-node','privanet_update':str(updater)},
        'broker':{'socket':'/run/privanet-chat-admin/broker.sock','timeout_seconds':1},
        'shell':{'socket':'/run/privanet-chat-shell/shell.sock','timeout_seconds':2},
        'privasearch':{'base_url':'http://127.0.0.1:4020','env_file':'/etc/privasearch/privasearch.env'},
        'updater':{'config_file':str(updater_config)},
        'diagnostic_paths':[str(tmp_path)],
        'limits':{'max_log_lines':50,'max_job_slots':16,'command_timeout_seconds':1,'max_command_timeout_seconds':60,'update_timeout_seconds':2},
    }


def backend(tmp_path, broker=None, shell=None):
    return AdminBackend(
        cfg(tmp_path), runner=FakeRunner(), broker=broker or FakeBroker(), shell=shell or FakeShell(),
        http_json=lambda *a,**k:{'ok':True,'http_status':200,'data':{'status':'ok','version':'0.5.1'},'error':None},
    )


def test_runner_default_path_contains_opt_node():
    assert '/opt/node/bin' in Runner().command_path.split(':')


def test_run_command_uses_separate_shell_identity(tmp_path):
    sh=FakeShell(); b=backend(tmp_path,shell=sh)
    out=b.run_command('uname -a',12)
    assert sh.calls==[('uname -a',12)]
    assert out['executedAs']=='privanet-shell'
    assert out['privilege']=='unprivileged'


def test_run_command_bounded_timeout_and_redacts(tmp_path):
    sh=FakeShell(); sh.response={'ok':True,'exitCode':0,'durationSeconds':1,'stdout':'token=abc\n','stderr':''}
    b=backend(tmp_path,shell=sh)
    out=b.run_command('echo hi',999)
    assert sh.calls[0][1]==60
    assert 'abc' not in out['stdout']


def test_command_environment_mentions_step_up_root(tmp_path):
    out=backend(tmp_path).command_environment()
    assert out['executedAs']=='privanet-shell'
    assert out['rootShellAvailable'] is False
    assert out['stepUpRootCommandAvailable'] is True


def test_service_allowlist_blocks_unmanaged_unit(tmp_path):
    with pytest.raises(ValueError): backend(tmp_path).service_status('sshd')


def test_service_status_uses_broker_read_path(tmp_path):
    br=FakeBroker(); br.set('service.status',{'ok':True,'unit':'privanet-node.service','output':'ActiveState=active\nSubState=running\n','error':None})
    out=backend(tmp_path,broker=br).service_status('node')
    assert out['state']['ActiveState']=='active'
    assert br.calls[-1][0]=='service.status'


def test_nodes_can_hide_revoked(tmp_path):
    br=FakeBroker(); br.set('admin.nodes.list',{'ok':True,'data':{'nodes':[{'nodeId':'a','status':'ONLINE'},{'nodeId':'b','status':'REVOKED'}]},'error':None})
    assert [n['nodeId'] for n in backend(tmp_path,broker=br).list_nodes(False)['nodes']]==['a']


def test_get_and_diagnose_node(tmp_path):
    br=FakeBroker(); br.set('admin.nodes.show',{'ok':True,'data':{'nodeId':'n','status':'OFFLINE','jobSlots':0,'currentJobs':0,'pressure':'ELEVATED'},'error':None})
    out=backend(tmp_path,broker=br).diagnose_node('node_12345678')
    assert {'OFFLINE','NO_SLOTS','RESOURCE_PRESSURE'} <= {x['code'] for x in out['diagnosis']}


def test_version_drift(tmp_path):
    br=FakeBroker(); br.set('admin.nodes.list',{'ok':True,'data':{'nodes':[{'status':'ONLINE','daemonVersion':'1.0','displayName':'a'},{'status':'ONLINE','daemonVersion':'1.1','displayName':'b'}]},'error':None})
    assert backend(tmp_path,broker=br).version_drift()['drift'] is True


def test_restart_calls_capability_broker_action(tmp_path):
    br=FakeBroker(); br.set('service.restart',{'ok':True,'state':'ActiveState=active\n','error':None})
    out=backend(tmp_path,broker=br).restart_service('node','req_'+'1'*32,'mcp_audit123')
    assert out['ok'] is True
    assert br.calls[-1]==('service.restart',{'service':'node','authorization_request_id':'req_'+'1'*32},'mcp_audit123')


def test_node_mutations_use_capability_ids(tmp_path):
    br=FakeBroker(); b=backend(tmp_path,broker=br); auth='req_'+'2'*32; conf='confirm_req_'+'3'*32
    b.approve_node('ABCD-EF12',['web.fetch.v1'],'crawler',auth,'mcp_audit123'); assert br.calls[-1][1]['authorization_request_id']==auth
    b.deny_node('ABCD-EF12',auth,'mcp_audit123'); assert br.calls[-1][1]['authorization_request_id']==auth
    b.rename_node('node_12345678','worker',False,auth,'mcp_audit123'); assert br.calls[-1][1]['authorization_request_id']==auth
    b.revoke_node('node_12345678',auth,conf,'mcp_audit123'); assert br.calls[-1][1]['confirmation_request_id']==conf


def test_node_reference_rejects_option_injection(tmp_path):
    with pytest.raises(ValueError): backend(tmp_path).get_node('--help')


def test_local_slots_are_bounded_and_brokered(tmp_path):
    br=FakeBroker(); b=backend(tmp_path,broker=br); auth='req_'+'4'*32
    b.set_local_node_slots(8,auth,'mcp_audit123')
    assert br.calls[-1][1]['authorization_request_id']==auth
    with pytest.raises(ValueError): b.set_local_node_slots(17,auth,'mcp_audit123')


def test_local_slots_show_is_read_only_broker_action(tmp_path):
    br=FakeBroker(); br.set('node.slots.show',{'ok':True,'data':{'slots':4},'error':None})
    assert backend(tmp_path,broker=br).local_node_slots()['slots']=={'slots':4}


def test_update_check_returns_fresh_per_app_events(tmp_path):
    br=FakeBroker(); br.set('update.check',{'ok':True,'output':'{"app":"core","code":"UP_TO_DATE","version":"0.4.0-alpha.4"}\n{"app":"proxy","code":"UPDATE_AVAILABLE","target":"v1.2.1"}\n','error':None})
    out=backend(tmp_path,broker=br).check_updates()
    assert len(out['apps'])==2 and out['apps'][1]['code']=='UPDATE_AVAILABLE'


def test_update_check_reports_missing_prerequisites(tmp_path):
    c=cfg(tmp_path); Path(c['executables']['privanet_update']).unlink()
    b=AdminBackend(c,runner=FakeRunner(),broker=FakeBroker(),shell=FakeShell())
    assert b.check_updates()['events'][0]['code']=='UPDATER_NOT_INSTALLED'


def test_privasearch_status_secret_stays_in_broker(tmp_path):
    br=FakeBroker(); br.set('search.status',{'ok':True,'http_status':200,'data':{'frontier':{'PENDING':12}},'error':None})
    out=backend(tmp_path,broker=br).privasearch_status()
    assert out['data']['frontier']['PENDING']==12 and br.calls[-1][0]=='search.status'


def test_privasearch_summary(tmp_path):
    br=FakeBroker(); br.set('search.status',{'ok':True,'http_status':200,'data':{'frontier':{'PENDING':12},'quality':{'duplicates':2},'throughput':{'perMinute':5},'warnings':[]},'error':None})
    out=backend(tmp_path,broker=br).privasearch_summary()
    assert out['queue']['PENDING']==12 and out['quality']['duplicates']==2


def test_authorization_round_trip_backend(tmp_path):
    rid='req_'+'5'*32
    br=FakeBroker(); br.set('auth.prepare',{'ok':True,'requestId':rid,'scope':'privanet.services'}); br.set('auth.grant',{'ok':True,'requestId':rid,'scope':'privanet.services','expiresAt':123}); br.set('auth.status',{'ok':True,'leases':[{'requestId':rid,'scope':'privanet.services','expiresAt':9999999999}]})
    b=backend(tmp_path,broker=br)
    p=b.prepare_authorization('privanet.services','restart node','mcp_audit123')
    g=b.grant_authorization(p['requestId'],'once','mcp_other456')
    st=b.authorization_status(rid,'mcp_third789')
    assert g['scope']=='privanet.services' and st['leases'][0]['requestId']==rid
    assert br.calls[-1][1]['request_id']==rid


def test_unknown_authorization_scope_rejected(tmp_path):
    with pytest.raises(ValueError): backend(tmp_path).prepare_authorization('root.shell','x','mcp_audit123')
    with pytest.raises(ValueError): backend(tmp_path).prepare_authorization('system.sudo','x','mcp_audit123')


def test_confirmation_backend_carries_authorization_id(tmp_path):
    auth='req_'+'6'*32; conf='confirm_req_'+'7'*32
    br=FakeBroker(); br.set('confirm.prepare',{'ok':True,'requestId':conf,'action':'package.install','target':'jq'})
    b=backend(tmp_path,broker=br)
    out=b.prepare_confirmation('package.install','jq','install jq',auth,'mcp_audit123')
    assert out['requestId']==conf
    assert br.calls[-1][1]['authorization_request_id']==auth


def test_install_package_validates_and_carries_both_capabilities(tmp_path):
    auth='req_'+'8'*32; conf='confirm_req_'+'9'*32
    br=FakeBroker(); br.set('package.install',{'ok':True,'package':'jq','output':'done','error':None})
    b=backend(tmp_path,broker=br)
    assert b.install_package('jq',auth,conf,'mcp_audit123')['ok']
    assert br.calls[-1][1]['authorization_request_id']==auth and br.calls[-1][1]['confirmation_request_id']==conf
    with pytest.raises(ValueError): b.install_package('-oBad=1',auth,conf,'mcp_audit123')


def test_sudo_backend_never_accepts_command_on_execution(tmp_path):
    rid='sudo_req_'+'a'*32
    br=FakeBroker(); br.set('root.run',{'ok':True,'executedAs':'root','exitCode':0,'stdout':'ok','stderr':'','commandSha256':'abc'})
    out=backend(tmp_path,broker=br).run_sudo_command(rid,'mcp_audit123')
    assert out['executedAs']=='root' and out['privilege']=='sudo-2fa'
    assert br.calls[-1]==('root.run',{'sudo_request_id':rid},'mcp_audit123')


def test_summary_flags_offline_service(tmp_path):
    br=FakeBroker()
    def call(action, params=None, session_key='session-default'):
        params=params or {}
        if action=='service.status':
            active='failed' if params.get('service')=='node' else 'active'
            return {'ok':True,'unit':'x.service','output':f'ActiveState={active}\nSubState=running\n','error':None}
        if action=='admin.nodes.list': return {'ok':True,'data':{'nodes':[]},'error':None}
        if action=='update.check': return {'ok':True,'output':'{"app":"core","code":"UP_TO_DATE"}\n','error':None}
        return {'ok':True}
    br.call=call
    out=backend(tmp_path,broker=br).privanet_summary()
    assert out['overall']=='ATTENTION' and any('node' in w for w in out['warnings'])


def test_system_health_bounded_paths(tmp_path):
    out=backend(tmp_path).system_health(); assert out['ok'] and str(tmp_path) in out['disks']


def test_redaction():
    clean=redact('Authorization: Bearer abc123 token=xyz password: hunter2')
    assert all(x not in clean for x in ['abc123','xyz','hunter2'])


def test_deploy_separates_shell_and_broker_identities():
    text=Path('deploy.sh').read_text()
    assert 'privanet-chat-broker' in text and 'privanet-chat-shell' in text and 'privanet-shell' in text
    assert 'SupplementaryGroups=$BROKER_GROUP $SHELL_GROUP' in text
    assert 'User=$SHELL_USER' in text


def test_shell_service_source_has_no_privileged_broker_socket():
    text=Path('agent/shell.py').read_text()
    assert 'privanet-chat-admin/broker.sock' not in text
    assert 'sudo' not in text


def test_broker_root_command_is_explicitly_2fa_gated():
    text=Path('agent/broker.py').read_text()
    assert 'root.run' in text and 'sudo.grant' in text and '_verify_totp' in text
    assert 'system.sudo' in text
    assert 'sudo ALL' not in text and 'NOPASSWD' not in text


def test_versions_are_032():
    assert 'VERSION = "0.3.3"' in Path('agent/core.py').read_text()
    assert 'VERSION=0.3.3' in Path('deploy.sh').read_text()
    assert json.loads(Path('plugin/plugin.json').read_text())['version']=='0.3.3'


def test_deploy_installs_2fa_helper_and_secret_path():
    text=Path('deploy.sh').read_text()
    assert 'privanet-chat-admin-2fa' in text
    assert 'PRIVANET_CHAT_ADMIN_TOTP_SECRET=$BROKER_STATE_DIR/totp.secret' in text
    assert 'install -d -o root -g root -m 0700 "$BROKER_STATE_DIR"' in text


def test_deploy_migrates_existing_audit_ownership():
    text=Path('deploy.sh').read_text()
    assert 'chown "$SERVICE_USER:$SERVICE_GROUP" "$STATE_DIR"/audit.sqlite3*' in text


def test_broker_authorization_once_is_capability_bound(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.services','reason':'restart'},'session_key':'mcp_sessionA'})
    broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'once'},'session_key':'mcp_sessionB'})
    assert broker._active_lease('privanet.services',prep['requestId'],consume=True) is not None
    assert broker._active_lease('privanet.services',prep['requestId'],consume=False) is None


def test_broker_capability_survives_transport_session_change(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    def fake_run(argv,timeout=60,env=None):
        stdout='ActiveState=active\nSubState=running\nMainPID=123\nExecMainStatus=0\nResult=success\n' if 'show' in argv else ''
        return {'ok':True,'code':0,'stdout':stdout,'stderr':''}
    monkeypatch.setattr(broker,'_run',fake_run)
    monkeypatch.setattr(broker,'_service_alias',lambda name:'privanet-node.service')
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.services','reason':'restart'},'session_key':'mcp_sessionA'})
    broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'15m'},'session_key':'mcp_sessionB'})
    out=broker.handle({'action':'service.restart','params':{'service':'node','authorization_request_id':prep['requestId']},'session_key':'mcp_sessionC'})
    assert out['ok'] is True


def test_broker_wrong_capability_scope_is_rejected(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.nodes','reason':'nodes'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'15m'},'session_key':'mcp_session_B'})
    with pytest.raises(broker.AuthorizationRequired):
        broker.handle({'action':'service.restart','params':{'service':'node','authorization_request_id':prep['requestId']},'session_key':'mcp_session_C'})


def test_broker_timed_lease_and_revoke_by_request(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.nodes','reason':'maintenance'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'15m'},'session_key':'mcp_session_B'})
    status=broker.handle({'action':'auth.status','params':{'request_id':prep['requestId']},'session_key':'mcp_session_C'})
    assert status['leases'][0]['requestId']==prep['requestId']
    revoked=broker.handle({'action':'auth.revoke_all','params':{'request_id':prep['requestId']},'session_key':'mcp_session_D'})
    assert revoked['revoked']==1


def test_broker_denies_privileged_action_without_capability(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    with pytest.raises(broker.AuthorizationRequired):
        broker.handle({'action':'service.restart','params':{'service':'node'},'session_key':'mcp_12345678'})


def test_broker_rejects_replayed_authorization_request(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.updates','reason':'updates'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'once'},'session_key':'mcp_session_B'})
    with pytest.raises(PermissionError):
        broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'once'},'session_key':'mcp_session_C'})


def test_broker_denial_consumes_auth_request_across_sessions(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    prep=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.services','reason':'restart'},'session_key':'mcp_session_A'})
    assert broker.handle({'action':'auth.deny','params':{'request_id':prep['requestId']},'session_key':'mcp_session_B'})['denied'] is True
    with pytest.raises(PermissionError):
        broker.handle({'action':'auth.grant','params':{'request_id':prep['requestId'],'duration':'15m'},'session_key':'mcp_session_C'})


def test_confirmation_requires_corresponding_capability(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    with pytest.raises(broker.AuthorizationRequired):
        broker.handle({'action':'confirm.prepare','params':{'action':'package.install','target':'jq','reason':'install','authorization_request_id':'req_'+'1'*32},'session_key':'mcp_session_A'})


def test_confirmation_survives_session_change_and_is_single_use(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    auth=broker.handle({'action':'auth.prepare','params':{'scope':'system.packages','reason':'packages'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':auth['requestId'],'duration':'15m'},'session_key':'mcp_session_B'})
    prep=broker.handle({'action':'confirm.prepare','params':{'action':'package.install','target':'jq','reason':'install jq','authorization_request_id':auth['requestId']},'session_key':'mcp_session_C'})
    granted=broker.handle({'action':'confirm.grant','params':{'request_id':prep['requestId']},'session_key':'mcp_session_D'})
    assert granted['usesRemaining']==1
    with pytest.raises(PermissionError):
        broker.handle({'action':'confirm.grant','params':{'request_id':prep['requestId']},'session_key':'mcp_session_E'})


def test_destructive_revoke_preserves_once_capability_until_confirmed(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    node_id='node_1234567890abcdef'
    def fake_admin(args, timeout=60):
        if args[:2]==['nodes','show']: return {'ok':True,'code':0,'stdout':json.dumps({'nodeId':node_id,'status':'ONLINE'}),'stderr':''}
        if args[:2]==['nodes','revoke']: return {'ok':True,'code':0,'stdout':'revoked','stderr':''}
        raise AssertionError(args)
    monkeypatch.setattr(broker,'_admin',fake_admin)
    auth=broker.handle({'action':'auth.prepare','params':{'scope':'privanet.nodes','reason':'revoke'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':auth['requestId'],'duration':'once'},'session_key':'mcp_session_B'})
    with pytest.raises(broker.ConfirmationRequired):
        broker.handle({'action':'admin.node.revoke','params':{'node_reference':node_id,'authorization_request_id':auth['requestId']},'session_key':'mcp_session_C'})
    assert broker._active_lease('privanet.nodes',auth['requestId'],consume=False) is not None
    conf=broker.handle({'action':'confirm.prepare','params':{'action':'admin.node.revoke','target':node_id,'reason':'confirmed revoke','authorization_request_id':auth['requestId']},'session_key':'mcp_session_D'})
    broker.handle({'action':'confirm.grant','params':{'request_id':conf['requestId']},'session_key':'mcp_session_E'})
    out=broker.handle({'action':'admin.node.revoke','params':{'node_reference':node_id,'authorization_request_id':auth['requestId'],'confirmation_request_id':conf['requestId']},'session_key':'mcp_session_F'})
    assert out['ok'] is True
    assert broker._active_lease('privanet.nodes',auth['requestId'],consume=False) is None
    assert broker._active_confirmation('admin.node.revoke',node_id,conf['requestId'],consume=False) is None


def test_confirmation_target_must_match_exactly(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    auth=broker.handle({'action':'auth.prepare','params':{'scope':'system.packages','reason':'packages'},'session_key':'mcp_session_A'})
    broker.handle({'action':'auth.grant','params':{'request_id':auth['requestId'],'duration':'15m'},'session_key':'mcp_session_B'})
    conf=broker.handle({'action':'confirm.prepare','params':{'action':'package.install','target':'jq','reason':'install jq','authorization_request_id':auth['requestId']},'session_key':'mcp_session_C'})
    broker.handle({'action':'confirm.grant','params':{'request_id':conf['requestId']},'session_key':'mcp_session_D'})
    assert broker._active_confirmation('package.install','curl',conf['requestId'],consume=False) is None
    assert broker._active_confirmation('package.install','jq',conf['requestId'],consume=False) is not None


def _configure_totp(broker, tmp_path, monkeypatch):
    secret=base64.b32encode(b'01234567890123456789').decode().rstrip('=')
    path=tmp_path/'totp.secret'; path.write_text(secret+'\n')
    monkeypatch.setattr(broker,'TOTP_SECRET_PATH',str(path))
    return secret


def test_sudo_requires_2fa_configuration(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    monkeypatch.setattr(broker,'TOTP_SECRET_PATH',str(tmp_path/'missing.secret'))
    with pytest.raises(PermissionError):
        broker.handle({'action':'sudo.prepare','params':{'command':'id','reason':'test'},'session_key':'mcp_session_A'})


def test_sudo_2fa_status_never_returns_secret(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    secret=_configure_totp(broker,tmp_path,monkeypatch)
    out=broker.handle({'action':'sudo.2fa_status','params':{},'session_key':'mcp_session_A'})
    assert out['configured'] is True and secret not in json.dumps(out)


def test_sudo_exact_command_is_bound_and_one_use(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    secret=_configure_totp(broker,tmp_path,monkeypatch)
    observed=[]
    monkeypatch.setattr(broker,'_run_root_command',lambda command,timeout_seconds:(observed.append((command,timeout_seconds)) or {'ok':True,'code':0,'stdout':'root\n','stderr':''}))
    prep=broker.handle({'action':'sudo.prepare','params':{'command':'id -u','reason':'verify root','timeout_seconds':17},'session_key':'mcp_session_A'})
    code=broker._totp_at(secret,int(time.time())//30)
    grant=broker.handle({'action':'sudo.grant','params':{'request_id':prep['requestId'],'totp_code':code},'session_key':'mcp_session_B'})
    assert grant['usesRemaining']==1
    out=broker.handle({'action':'root.run','params':{'sudo_request_id':prep['requestId'],'command':'echo hacked'},'session_key':'mcp_session_C'})
    assert out['ok'] is True and observed==[('id -u',17)]
    with pytest.raises(broker.AuthorizationRequired):
        broker.handle({'action':'root.run','params':{'sudo_request_id':prep['requestId']},'session_key':'mcp_session_D'})


def test_sudo_totp_replay_is_rejected(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    secret=_configure_totp(broker,tmp_path,monkeypatch)
    code=broker._totp_at(secret,int(time.time())//30)
    a=broker.handle({'action':'sudo.prepare','params':{'command':'id','reason':'one'},'session_key':'mcp_session_A'})
    b=broker.handle({'action':'sudo.prepare','params':{'command':'whoami','reason':'two'},'session_key':'mcp_session_B'})
    broker.handle({'action':'sudo.grant','params':{'request_id':a['requestId'],'totp_code':code},'session_key':'mcp_session_C'})
    with pytest.raises(PermissionError):
        broker.handle({'action':'sudo.grant','params':{'request_id':b['requestId'],'totp_code':code},'session_key':'mcp_session_D'})


def test_sudo_wrong_code_is_rejected(tmp_path, monkeypatch):
    import agent.broker as broker
    monkeypatch.setattr(broker,'STATE_DB',str(tmp_path/'broker.sqlite3'))
    secret=_configure_totp(broker,tmp_path,monkeypatch)
    correct=broker._totp_at(secret,int(time.time())//30)
    wrong='000000' if correct!='000000' else '000001'
    req=broker.handle({'action':'sudo.prepare','params':{'command':'id','reason':'test'},'session_key':'mcp_session_A'})
    with pytest.raises(PermissionError):
        broker.handle({'action':'sudo.grant','params':{'request_id':req['requestId'],'totp_code':wrong},'session_key':'mcp_session_B'})


def test_server_mcp_app_is_fullscreen_capable_and_no_elicitation():
    text=Path('agent/server.py').read_text()
    assert 'Apps()' in text
    assert 'ui://privanet-admin/approval-v3.html' in text
    assert 'availableDisplayModes": ["inline", "fullscreen"]' in text
    assert 'requestDisplayMode' in text
    assert 'Open fullscreen' in text
    assert 'ChatGPT kept this approval inline' in text
    assert \"terminalState=['approved','denied','expired']\" in text
    assert 'request_admin_access' in text and 'request_action_confirmation' in text and 'request_sudo_command' in text
    assert 'grant_sudo_command' in text and 'visibility=["app"]' in text
    assert 'context.elicit' not in text and '.elicit(' not in text



def test_sudo_card_warns_output_returns_to_chatgpt():
    text=Path('agent/server.py').read_text()
    assert 'Command output is returned to ChatGPT' in text
    assert 'does not expose secrets you do not want in chat' in text

def test_server_sudo_flow_never_sends_totp_to_model_followup():
    text=Path('agent/server.py').read_text()
    assert 'totp_code: str' in text
    assert 'sudo_request_id=${payload.requestId}' in text
    assert 'totp_code=${' not in text


def test_skill_requires_capability_ids_and_sudo_2fa():
    text=Path('plugin/skills/privanet-admin/SKILL.md').read_text()
    assert 'authorization_request_id' in text
    assert 'confirmation_request_id' in text
    assert 'request_sudo_command' in text and 'run_sudo_command' in text
    assert 'privanet-chat-admin-2fa setup' in text
    assert 'Never ask them to paste' in text


def test_twofactor_helper_has_local_enrollment_and_no_network_calls():
    text=Path('twofactor.py').read_text()
    assert 'otpauth://totp/' in text
    assert 'privanet-chat-admin-2fa verify' in text
    assert 'requests.' not in text and 'urllib.request' not in text


def test_security_scan_no_shell_true_or_os_system():
    for fn in ['agent/broker.py','agent/core.py','agent/server.py','agent/shell.py','authorize.py','twofactor.py']:
        text=Path(fn).read_text()
        assert 'shell=True' not in text
        assert 'os.system(' not in text
