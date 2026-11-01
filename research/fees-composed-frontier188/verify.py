"""Recheck composed source, compiler outputs, callee/data evidence and saved runs."""
from pathlib import Path
import gzip,hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):
 raw=path.read_bytes();return json.loads(gzip.decompress(raw)if path.suffix=='.gz'else raw)
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def sources():
 parent=module('composed_sources',ROOT/'research/fees-math-pack-source-proposal/verify.py');parent.manifest();base=parent.sources()['combined'];source=dict(base)
 def replace(name,replacements):
  text=source[name].decode()
  for a,b in replacements:assert text.count(a)==1,(name,a);text=text.replace(a,b)
  source[name]=text.encode()
 replace('programs/pump-fees/src/instructions/fee_sharing/create_fee_sharing_config.rs',[("pub event_authority:UncheckedAccount<'info>","pub event_authority:AccountInfo<'info>"),("pub pump_event_authority:UncheckedAccount<'info>","pub pump_event_authority:AccountInfo<'info>"),("pub global:Box<Account<'info,pump_global::Global>>","pub global:Account<'info,pump_global::Global>")])
 replace('programs/pump-fees/src/sharing_admin.rs',[("pub global:Account<'info,pump_global::Global>","pub global:Box<Account<'info,pump_global::Global>>"),("pub sharing_config:Account<'info,SharingConfig>","pub sharing_config:Box<Account<'info,SharingConfig>>"),("#[account(address=ID)]pub program:UncheckedAccount<'info>","pub program:Program<'info,crate::program::PumpFeesCandidate>")])
 name='programs/pump-fees/src/social.rs';text=source[name].decode();start=text.index(' pub fn create_social(');end=text.index(' pub fn claim(',start);removed=text[start:end];source[name]=(text[:start]+'\n'*removed.count('\n')+text[end:]).encode()
 name='programs/pump-fees/src/instructions/fee_sharing/create_social_fee_pda.rs';lines=source[name].decode().splitlines(True);assert not lines[3].strip();lines[3]='use crate::FeeError;\n';assert len(lines)<63;lines.extend(['\n']*(63-len(lines)))
 body=(ROOT/'research/fees-social-creation-body/create_social_fee_pda.rs').read_text().splitlines(True)[63:];assert body[0].startswith(' pub fn create_social(');source[name]=''.join(lines+body).encode()
 meta=load(HERE/'sources.json');assert meta['parent']=='research/fees-math-pack-source-proposal'and meta['variant']=='combined'
 changes={n for n in source if source[n]!=base[n]};assert changes==set(meta['overrides'])
 assert all((HERE/'overrides'/n).read_bytes()==source[n]for n in changes)
 return {'baseline':base,'origins':source}

def verify():
 manifest=load(HERE/'manifest.json');assert set(manifest)=={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and'__pycache__'not in p.parts}
 for name,digest in manifest.items():
  p=HERE/name;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==digest,name
 for name,digest in load(HERE/'parents.json').items():assert sha((ROOT/name).read_bytes())==digest,name
 exp=load(HERE/'experiment.json');source=sources()
 for label,files in source.items():
  launch=load(HERE/f'builds/{label}/launch.json');result=load(HERE/f'builds/{label}/result.json');log=(HERE/f'builds/{label}/build.log').read_bytes();inputs={n:sha(b)for n,b in files.items()}
  assert len(inputs)==42 and launch['inputs']==exp['variants'][label]['inputs']==inputs
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'
  assert result['exit_code']==0 and result['compiled_root']and result['source_unchanged']and log.count(b'--crate-name pump_fees_candidate ')==1 and sha(log)==result['log_sha256']
  assert all(x in launch['command']for x in ['--locked','--offline','sbpf-solana-solana'])
  for kind in ['candidate','symbols']:assert result[kind+'_sha256']==exp['variants'][label]['files'][kind]['sha256']
 expected=load(ROOT/'research/fees-math-pack-source-proposal/expected.json')['reports']['combined']
 for key in ['candidate_sha256','symbols_sha256']:assert exp['variants']['baseline']['files'][key.removesuffix('_sha256')]['sha256']==expected[key]
 measured=module('composed_analysis',HERE/'analyze.py').analyze();assert measured==load(HERE/'analysis.json.gz')
 assert len(measured['variants']['origins']['unique_pairs'])==404 and len(measured['variants']['origins']['unmatched_original'])==34
 assert len(measured['details']['origins']['normalized'])==551 and len(measured['details']['origins']['raw'])==118
 full=load(HERE/'runtime/full.json.gz');social=load(HERE/'runtime/social.json.gz');candidate=exp['variants']['origins']['files']['candidate']['sha256'];original='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
 assert full['candidate_sha256']==candidate and full['original_sha256']==original and full['case_count']==17331 and len(full['suites'])==18 and not full['mismatches']
 for suite in full['suites'].values():assert suite['candidate_sha256']==candidate and suite['original_sha256']==original and not suite.get('mismatches',suite.get('failures',[]))
 assert social['candidate_sha256']==candidate and social['original_sha256']==original and len(social['cases'])==157 and not social['mismatches']
 assert all(row['match']and row['original']==row['candidate']for row in social['cases'])
 print('PASS: exact 545-window baseline; 551 composed windows; 404 unique pairs; 163 matching Location uses; 17,331 suite and 157 strict saved comparisons; no whole identity')

if __name__=='__main__':verify()
