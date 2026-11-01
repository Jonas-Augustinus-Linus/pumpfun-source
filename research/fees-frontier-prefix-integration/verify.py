"""Verify exact source composition, actual outputs and finite saved runtime evidence."""
from pathlib import Path
import gzip,hashlib,importlib.util,json,difflib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p):return json.loads(gzip.decompress(p.read_bytes())if p.suffix=='.gz'else p.read_bytes())
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def strict(r):
 assert len(r['cases'])==157 and not r['mismatches']
 assert all(x['match']and x['original']==x['candidate']for x in r['cases'])
def source_change(before,after):
 left='''        Self::try_deserialize_unchecked(buf)
    }
    fn try_deserialize_unchecked(buf: &mut &[u8]) -> Result<Self> {
        if buf.len() < 2504 { return Err(ProgramError::InvalidAccountData.into()); }
        if buf.len() < 4065 { return Self::read_legacy(buf); }
        if buf.len() < 4089 { return Self::read_stable(buf); }
        Self::read_full(buf)
'''
 right='''        decode_fee_config_payload(buf)
    }
    fn try_deserialize_unchecked(buf: &mut &[u8]) -> Result<Self> {
        if buf.len() < 8 { return Err(ProgramError::InvalidAccountData.into()); }
        *buf = &buf[8..];
        decode_fee_config_payload(buf)

'''
 helper='''
#[inline(never)]
fn decode_fee_config_payload(buf: &mut &[u8]) -> Result<FeeConfig> {
    if buf.len() < 2504 { return Err(ProgramError::InvalidAccountData.into()); }
    if buf.len() < 4065 { return FeeConfig::read_legacy(buf); }
    if buf.len() < 4089 { return FeeConfig::read_stable(buf); }
    FeeConfig::read_full(buf)
}
'''
 assert before.count(left)==1 and after==before.replace(left,right)+helper
def main():
 manifest=load(HERE/'manifest.json');actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and '__pycache__'not in p.parts};assert set(manifest)==actual
 for n,h in manifest.items():
  p=HERE/n;assert not p.is_symlink()and p.resolve().is_relative_to(HERE)and sha(p.read_bytes())==h,n
 e=load(HERE/'experiment.json');parentraw=(HERE/'parent-experiment.json').read_bytes();assert sha(parentraw)==e['parent_experiment_sha256'];parent=json.loads(parentraw)['variants']['origins'];base=e['variants']['control'];v=e['variants']['origins'];assert parent['inputs']==base['input_sha256']and e['control_runtime_reused']
 assert all(parent['files'][k][field]==base['files'][k][field]for k in ['candidate','symbols']for field in ['sha256','bytes'])
 name='programs/pump-fees/src/types.rs';assert base['input_sha256'].keys()==v['input_sha256'].keys()and {n for n,h in base['input_sha256'].items()if v['input_sha256'][n]!=h}=={name}
 before,after=[(HERE/e['variants'][k]['source_paths'][name]).read_text()for k in ['control','origins']];source_change(before,after);patch=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+name,tofile='b/'+name,n=0));assert patch==(HERE/'decoder.patch').read_text()
 for label,row in e['variants'].items():
  assert len(row['input_sha256'])==42 and set(row['source_paths'])==set(row['input_sha256'])
  for n,h in row['input_sha256'].items():assert sha((HERE/row['source_paths'][n]).read_bytes())==h,n
  for kind,d in row['files'].items():
   raw=gzip.decompress((HERE/d['path']).read_bytes());assert len(raw)==d['bytes']and sha(raw)==d['sha256']
  launch=load(HERE/f'builds/{label}-launch.json');result=load(HERE/f'builds/{label}-result.json');log=(HERE/f'builds/{label}-build.log').read_bytes()
  assert launch['input_sha256']==result['input_sha256']==row['input_sha256']and result['exit_code']==result['strip_exit_code']==0 and result['source_unchanged']
  assert log.count(b'--crate-name pump_fees_candidate ')==1 and b'-Zremap-cwd-prefix='in log and b'Finished `release` profile'in log
  assert launch['rustc_sha256']=='c8807b7ebede8578ac5a257ea333780f9d89bd356064fd8184af7e996cb71a97'and 'sbpf-solana-solana'in launch['command']and sum(x.startswith('--remap-path-prefix=')for x in launch['command'])==3
  assert row['strip_replay']['exit_code']==0 and row['strip_replay']['sha256']==row['files']['candidate']['sha256']
 harness=load(HERE/'harness-sha256.json');assert len(harness)==187 and set(harness)=={str(p.relative_to(ROOT))for p in(ROOT/'scripts').glob('*.py')}
 for n,h in harness.items():assert sha((ROOT/n).read_bytes())==h
 a=module('prefix_analysis',HERE/'analyze.py').analyze();assert a==load(HERE/'analysis.json.gz')and a['delta']==dict(added=[18384],lost=[])and a['raw_delta']==dict(added=[],lost=[])
 for label,count,normalized,left in [('control',404,551,34),('origins',405,552,33)]:
  r=a['variants'][label];assert len(r['unique_pairs'])==count and len(r['normalized'])==normalized and len(r['unmatched_original'])==left and r['candidate_windows']==591 and r['unique_raw_pairs']==64 and len(r['raw'])==118 and not r['equals_original_capture']and not r['equals_original_elf_extent']
 assert a['preserved_edges']==dict(control=3238,origins=3249,newly_equal=[[302032,6040]])
 for key,count in [('18384',11),('302032',17),('257264',13),('36072',12),('408640',98),('381352',51),('445160',87),('464168',37),('190104',21)]:assert len(a['direct_calls'][key])==count and all(x['equal']for x in a['direct_calls'][key])
 assert [(x['offset'],x['original']['target'])for x in a['direct_calls']['639104']if not x['equal']]==[(440,177720)]
 assert [(x['offset'],x['original']['target'])for x in a['direct_calls']['642848']if not x['equal']]==[(1176,127776)]
 assert a['decoder']['message']=='failed to fill whole buffer'and len(a['slice_contract']['locations'])==4 and a['relay']['address_error']==3007
 assert a['social_strings']==['social_fee_pda already exists','CreateSocialFeePda is currently disabled','programs/pump-fees/src/instructions/fee_sharing/create_social_fee_pda.rs']
 original='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
 for label in ['control','origins']:
  candidate=e['variants'][label]['files']['candidate']['sha256'];f=load(HERE/f'receipts/{label}-full.json.gz');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==17331 and len(f['suites'])==18 and not f['mismatches'];assert all(s['candidate_sha256']==candidate and s['original_sha256']==original and not s.get('mismatches',s.get('failures',[]))for s in f['suites'].values())
  f=load(HERE/f'receipts/{label}-strict.json.gz');assert f['candidate_sha256']==candidate and f['original_sha256']==original;strict(f)
 for name,d in e['reused_receipts'].items():assert sha((HERE/f'receipts/control-{name}.json.gz').read_bytes())==d['compressed_sha256']
 candidate=v['files']['candidate']['sha256'];f=load(HERE/'receipts/origins-flags.json.gz');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==1542 and not f['failures']and not f['compute_differences']and all(x['original']==x['candidate']for x in f['cases'])
 assert {(x['cap'],x['pool'],x['flag_hex'])for x in f['cases']}=={(cap,pool,flag)for cap in(0,1000,2**128-1)for pool in(0,1)for flag in ['']+[bytes([b]).hex()for b in range(256)]}
 for name,count in [('precedence',24),('optional',32),('seeds',20),('logs',8),('mint',30),('relay',16)]:
  f=load(HERE/f'receipts/origins-{name}.json.gz');assert f['candidate_sha256']==candidate and f['original_sha256']==original and f['case_count']==len(f['cases'])==count and not f['mismatches']and all(x['match']and all(x['original'][k]==x['candidate'][k]for k in f['fields'])for x in f['cases'])
 raw=module('prefix_raw',HERE/'raw_compare.py').compare();assert raw==load(HERE/'raw-comparisons.json')and all(not x['capture_equal']and not x['elf_extent_equal']for x in raw.values())
 print('PASS: exact upstream control; decoder-only composition;405unique/552normalized/33unmatched;callee/data checks;fresh17331+1542+targeted matrices;whole0/4')
if __name__=='__main__':main()
