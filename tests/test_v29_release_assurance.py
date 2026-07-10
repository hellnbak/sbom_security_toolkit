from datetime import datetime, timedelta, timezone
from sbomops.assurance import evaluate, normalize_findings, vex_index

POLICY={'metadata':{'name':'test'},'spec':{'deny':[{'id':'kev','kev':True},{'id':'critical','severity':'critical','fixAvailable':True}],'requireApproval':[{'id':'aged-high','severity':'high','ageDays':{'greaterThan':30}}],'warn':[{'id':'medium','severity':'medium'}]}}

def test_blocks_kev():
 r=evaluate(POLICY,normalize_findings([{'id':'CVE-1','severity':'high','kev':True}]),{},[],{}, {})
 assert r['decision']=='BLOCK' and r['exit_code']==4

def test_vex_not_affected_suppresses():
 vx=vex_index({'statements':[{'vulnerability':'CVE-1','product':'pkg:pypi/a@1','status':'not_affected'}]})
 r=evaluate(POLICY,normalize_findings([{'id':'CVE-1','purl':'pkg:pypi/a@1','severity':'critical','fix_available':True}]),vx,[],{}, {})
 assert r['decision']=='PASS'

def test_approved_active_exception_warns_instead_of_blocks():
 exp=(datetime.now(timezone.utc)+timedelta(days=2)).isoformat()
 exc=[{'metadata':{'id':'RISK-1'},'spec':{'status':'approved','rule':'kev','vulnerability':'CVE-1','expires':exp}}]
 r=evaluate(POLICY,normalize_findings([{'id':'CVE-1','severity':'high','kev':True}]),{},exc,{}, {})
 assert r['decision']=='PASS_WITH_WARNINGS'
 assert r['warnings'][0]['exception']=='RISK-1'

def test_required_provenance_is_incomplete():
 p={'metadata':{'name':'signed'},'spec':{'requireEvidence':{'provenance':True,'builderIdentity':True}}}
 r=evaluate(p,[],{},[],{}, {})
 assert r['decision']=='INCOMPLETE_EVIDENCE'
