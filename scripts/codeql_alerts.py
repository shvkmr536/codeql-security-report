#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,logging,os,tempfile
from pathlib import Path
from typing import Any,Optional,Iterable
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
API_VERSION=os.getenv("GITHUB_API_VERSION","2026-03-10"); PER_PAGE=100; TIMEOUT=60
LOG=logging.getLogger("codeql-export")
COLS=["Repository","Alert ID","Tool","Tool Version","Language","Rule ID","Rule Name","Rule Description","Severity","Security Severity","File","Start Line","End Line","Start Column","End Column","State","Status","Assignee / Owner","Dismissed By","Dismissed At","Dismissal Reason","Triage Comment","Created At","Fixed At","Commit SHA","Branch / Ref","Alert URL"]
def session(token):
 s=requests.Session(); r=Retry(total=5,connect=5,read=5,status=5,backoff_factor=1.5,status_forcelist=(429,500,502,503,504),allowed_methods=frozenset({'GET'}),respect_retry_after_header=True,raise_on_status=False); a=HTTPAdapter(max_retries=r,pool_connections=10,pool_maxsize=10); s.mount('https://',a); s.mount('http://',a); s.headers.update({'Accept':'application/vnd.github+json','Authorization':f'Bearer {token}','X-GitHub-Api-Version':API_VERSION,'User-Agent':'codeql-security-report/1.0'}); return s
def msg(r):
 try:return str(r.json().get('message',r.json()))
 except:return r.text[:500]
def get(s,url,params=None):
 r=s.get(url,params=params,timeout=TIMEOUT)
 if r.status_code==401: raise RuntimeError('GitHub authentication failed (401).')
 if r.status_code==403: raise RuntimeError(f'GitHub API 403: {msg(r)}')
 if r.status_code==404: raise RuntimeError(f'GitHub resource not found: {url}')
 if r.status_code>=400: raise RuntimeError(f'GitHub API {r.status_code}: {msg(r)}')
 return r.json()
def pages(s,url,params):
 p=1
 while True:
  q=dict(params,page=p,per_page=PER_PAGE); data=get(s,url,q)
  if not isinstance(data,list): raise RuntimeError('Expected list from Code Scanning API')
  if not data:return
  yield from data
  if len(data)<PER_PAGE:return
  p+=1
def language(rule):
 r=rule.lower()
 if r.startswith('cpp/'):return 'C/C++'
 if r.startswith('java/'):return 'Java'
 if r.startswith(('js/','javascript/')):return 'JavaScript'
 if r.startswith(('py/','python/')):return 'Python'
 if r.startswith('go/'):return 'Go'
 if r.startswith(('cs/','csharp/')):return 'C#'
 if r.startswith(('rb/','ruby/')):return 'Ruby'
 if r.startswith('swift/'):return 'Swift'
 return 'Unknown'
def assignees(a):
 raw=a.get('assignees') or []; out=[]
 if isinstance(raw,list):
  for x in raw:
   if isinstance(x,str):out.append(x)
   elif isinstance(x,dict) and x.get('login'):out.append(str(x['login']))
 return ', '.join(sorted(set(out))) if out else 'Unassigned'
def status(a):
 st=str(a.get('state') or '').lower(); reason=str(a.get('dismissed_reason') or '').strip()
 if st=='open':return 'Open'
 if st=='fixed':return 'Fixed'
 if st=='dismissed':return f'Mitigated ({reason})' if reason=='mitigated' else (f'Dismissed ({reason})' if reason else 'Dismissed')
 return st.title() if st else 'Unknown'
def enrich_assignees(s, a):
    if 'assignees' in a:
        return a
    url = a.get('url')
    if not url:
        return a
    try:
        detail = get(s, url)
        if isinstance(detail, dict) and 'assignees' in detail:
            a['assignees'] = detail.get('assignees') or []
    except Exception as exc:
        LOG.warning('Could not enrich assignees for alert %s: %s', a.get('number'), exc)
    return a

def row(a):
 rule=a.get('rule') or {}; tool=a.get('tool') or {}; inst=a.get('most_recent_instance') or {}; loc=inst.get('location') or {}; db=a.get('dismissed_by') or {}; repo=a.get('repository') or {}; rid=str(rule.get('id') or 'N/A')
 return {'Repository':repo.get('full_name') or 'Unknown','Alert ID':a.get('number') or 'N/A','Tool':tool.get('name') or 'N/A','Tool Version':tool.get('version') or 'N/A','Language':language(rid),'Rule ID':rid,'Rule Name':rule.get('name') or rid,'Rule Description':rule.get('description') or 'N/A','Severity':rule.get('severity') or 'N/A','Security Severity':rule.get('security_severity_level') or 'N/A','File':loc.get('path') or 'N/A','Start Line':loc.get('start_line') or 'N/A','End Line':loc.get('end_line') or 'N/A','Start Column':loc.get('start_column') or 'N/A','End Column':loc.get('end_column') or 'N/A','State':a.get('state') or 'N/A','Status':status(a),'Assignee / Owner':assignees(a),'Dismissed By':db.get('login') or 'N/A','Dismissed At':a.get('dismissed_at') or 'N/A','Dismissal Reason':a.get('dismissed_reason') or 'N/A','Triage Comment':a.get('dismissed_comment') or 'N/A','Created At':a.get('created_at') or 'N/A','Fixed At':a.get('fixed_at') or 'N/A','Commit SHA':inst.get('commit_sha') or 'N/A','Branch / Ref':inst.get('ref') or 'N/A','Alert URL':a.get('html_url') or 'N/A'}
def export(args):
 base=args.api_base.rstrip('/'); url=f'{base}/orgs/{args.org}/code-scanning/alerts' if args.org else f'{base}/repos/{args.owner}/{args.repo}/code-scanning/alerts'; params={'tool_name':'CodeQL','sort':'updated','direction':'desc'}; out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix='._codeql_',dir=out.parent); os.close(fd); tmp=Path(tmp); received=written=0
 try:
  with tmp.open('w',newline='',encoding='utf-8-sig') as f:
   w=csv.DictWriter(f,fieldnames=COLS); w.writeheader()
   for a in pages(args.session,url,params):
    received+=1; tool=str((a.get('tool') or {}).get('name','')).lower(); rid=str((a.get('rule') or {}).get('id','')).lower()
    if tool!='codeql' or not rid.startswith(tuple(x.lower() for x in args.prefixes)):continue
    a=enrich_assignees(args.session, a); w.writerow(row(a)); written+=1
  tmp.replace(out)
 except Exception: tmp.unlink(missing_ok=True); raise
 LOG.info('API alerts: %d; exported: %d; output: %s',received,written,out); return written
def main():
# p=argparse.ArgumentParser(); p.add_argument('--api-base',default=os.getenv('GITHUB_API_BASE','https://api.github.com')); g=p.add_mutually_exclusive_group(required=True); g.add_argument('--org'); g.add_argument('--owner'); p.add_argument('--repo'); p.add_argument('--rule-prefix',action='append',dest='prefixes',default=['cpp/']); p.add_argument('--output',required=True); p.add_argument('--verbose',action='store_true'); a=p.parse_args();
 p=argparse.ArgumentParser(); p.add_argument('--api-base',default=os.getenv('GITHUB_API_BASE','https://api.github.com')); g=p.add_mutually_exclusive_group(required=True); g.add_argument('--org'); g.add_argument('--owner'); p.add_argument('--repo'); p.add_argument('--rule-prefix',action='append',dest='prefixes',default=[]); p.add_argument('--output',required=True); p.add_argument('--verbose',action='store_true'); a=p.parse_args();
 if a.owner and not a.repo:p.error('--repo is required with --owner')
 token=os.getenv('GITHUB_TOKEN')
 if not token:LOG.error('GITHUB_TOKEN is not set'); return 2
 a.session=session(token); logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,format='%(asctime)s | %(levelname)s | %(message)s')
 try:
  n=export(a)
  if n==0:LOG.warning('No matching CodeQL alerts exported')
  return 0
 except Exception as e:LOG.error('Export failed: %s',e); return 1
if __name__=='__main__':raise SystemExit(main())
