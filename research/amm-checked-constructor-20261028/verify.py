#!/usr/bin/env python3
"""Verify the checked-constructor source overlay, real repeat and runtime proofs."""
from pathlib import Path
import argparse,base64,difflib,functools,gzip,hashlib,importlib.util,io,json,struct,subprocess,sys,tarfile,tempfile
P=Path(__file__).resolve().parent
ROOT=P.parents[1]
BASE='repro/pump_amm/canonical-frontier-20261028'
BASE_MANIFEST='d05b92a344e1e095e6f68276eb50ddc64a36a0792ac20cb0e7c31c6f6f384489'
CONTROL='15aadc37c6a4fb2148895eafa22a969f7ad28a363c8972a8fe526a015fa85d21'
CANDIDATE='b6f62738ea983e3acde0dfe1d24027af1355199807745d733c75c88a044e4d73'
SYMBOLS='fd78dd8a0238985c2b32a79e6733a6adb415b757d95c6d97aa275c2256043629'
FILE='programs/pump-amm/src/instructions/swap/sell.rs'
OLD=b'Account::<UserVolumeAccumulator>::try_from_unchecked(user_volume_accumulator)?'
NEW=b'Account::<UserVolumeAccumulator>::try_from(user_volume_accumulator)?'
AMM='pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA'

def require(ok,message):
 if not ok:raise RuntimeError(message)
def H(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
 raw=Path(path).read_bytes();return gzip.decompress(raw)if str(path).endswith('.gz')else raw
def J(path):return json.loads(read(path))
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def archive(path):
 result={}
 with tarfile.open(fileobj=io.BytesIO(read(path)))as source:
  for item in source:
   require(item.isfile()and not item.name.startswith('/')and '..'not in Path(item.name).parts and item.name not in result,'unsafe or duplicate archive entry')
   result[item.name]=source.extractfile(item).read()
 return result
def manifest(packet,expected=None):
 raw=(packet/'MANIFEST.json').read_bytes()
 if expected:require(H(raw)==expected,'base manifest identity')
 values=json.loads(raw);actual={str(path.relative_to(packet))for path in packet.rglob('*')if path.is_file()and path.relative_to(packet).parts[0]not in['work','__pycache__']and '__pycache__'not in path.parts and path.name!='MANIFEST.json'}
 require(actual==set(values),'packet membership differs')
 for name,digest in values.items():require(not(packet/name).is_symlink()and H((packet/name).read_bytes())==digest,'packet hash differs: '+name)

def focused(base,signatures):
 report=J(P/'runtime/focused.json.gz');observed=J(P/'runtime/focused-transactions.json.gz');audit=module('focused_base_audit',base/'audit_runtime.py')
 require(report['candidate_sha256']==CANDIDATE and report['control_sha256']==CONTROL and report['original_sha256']==audit.ORIGINAL,'focused program identities')
 require(report['case_count']==len(report['cases'])==21 and report['signature_fields']==63 and not report['mismatches'],'focused totals')
 require(report['script_sha256']==observed['script_sha256']==H((P/'runtime/probe_focused.py').read_bytes()),'focused producer binding')
 require(observed['observer_sha256']==H(archive(base/'results/runtime/inputs.tar.gz')['repro/pump_amm/owner6048-v144/runtime/observe_suite.py']),'focused observer binding')
 require(observed['transaction_count']==len(observed['transactions'])==observed['signature_count']==63,'focused observer totals')
 fields=verified=witnesses=0
 names=['original','r31_control','checked_candidate'];hashes=[audit.ORIGINAL,CONTROL,CANDIDATE]
 for index,row in enumerate(report['cases']):
  require(all(audit.clean(value)==audit.clean(row['results']['original'])for value in row['results'].values()),'focused complete observations differ')
  require(row['strict_observations_equal']is True,'focused comparison flag')
  pair=observed['transactions'][3*index:3*index+3]
  require(len({item['transaction_base64']for item in pair})==1,'focused signed inputs differ')
  for name,digest,item in zip(names,hashes,pair):
   result=row['results'][name];raw=base64.b64decode(item['transaction_base64'],validate=True);count,at=audit.compact(raw,0)
   require(item['transaction_base64']==result['transaction_base64']and H(raw)==item['transaction_sha256'],'focused transaction binding')
   require(count==item['signature_count']and count>0 and item['all_signatures_verified']is True,'focused signature observation')
   fields+=count
   require(item['amm_program_sha256']==item['loaded_programs'][AMM]['sha256']==digest,'focused actual code load')
   require(item['logs_sha256']==H(json.dumps(result['logs'],separators=(',',':')).encode())and item['error']==result['error'],'focused outcome binding')
   if signatures:
    from solders.transaction import Transaction
    checks=Transaction.from_bytes(raw).verify_with_results();require(len(checks)==count and all(checks),'focused signature invalid');verified+=count
  # Last matching meter line is the outer sell. Earlier same-program lines
  # belong to the existing event CPI; no logs or execution are instrumented.
  import re
  meters={name:[int(match.group(1))for line in row['results'][name]['logs']if(match:=re.fullmatch(r'Program '+AMM+r' consumed (\d+) of \d+ compute units',line))][-1]for name in names}
  require(meters==row['amm_compute_units'],'focused meter binding')
  delta=meters['checked_candidate']-meters['r31_control'];require(delta==row['checked_minus_control_units'],'focused meter delta')
  early=row['case']in['bad-discriminator-early','correct-header-length-7']
  require(delta==(0 if early else 11),'constructor execution witness delta')
  require(row['constructor_call_execution_witness']is(not early),'constructor execution witness flag')
  if early:require('6060'in row['results']['original']['error'],'early explicit discriminator guard')
  else:
   witnesses+=1;require(row['case']=='valid-new'or(row['initial_accumulator']['program_owned']and row['initial_accumulator']['has_expected_discriminator']),'constructor preconditions')
 require(fields==63 and witnesses==19,'focused signed/witness totals')
 return {'triple_cases':21,'signature_fields':fields,'cryptographically_verified_signature_fields':verified if signatures else None,'constructor_execution_witnesses':19,'early_guard_controls':2,'strict_mismatches':0,'execution_witness_scope':'Sole source-built CALL-immediate difference plus deterministic compute delta; no PC trace'}

def constructors(repo,symbols,base):
 result=subprocess.run([sys.executable,'-I','-B',str(P/'tools/cfg_attribution.py'),str(symbols),'0x4c750','sell8cashback',str(repo)],capture_output=True,text=True,check=True)
 graph=json.loads(result.stdout);require(graph['original_blocks']==graph['candidate_blocks']==graph['mapped_blocks']==77 and not graph['differences'],'sell instruction CFG differs beyond layout')
 require(graph['direct_calls_checked']==80 and not graph['direct_callee_body_mismatches'],'sell direct callee bodies differ')
 elf=module('checked_elf_reader',base/'tools/elf_reader.py');left=elf.Elf(repo/'evidence/original/pump_amm/deployed.so');right=elf.Elf(symbols)
 @functools.lru_cache(None)
 def identity(side,start,depth):
  value=left if side==0 else right;end=next(point for point in value.entries+[value.hi]if point>start)
  out={'bytes':end-start,'normalized_sha256':H(value.normalized[start:end]),'relocations':value.pattern(start,end-start)}
  if depth:out['calls']=[{'offset':at-start,'identity':identity(side,target,depth-1)}for at,target in sorted(value.calls.items())if start<=at<end]
  return out
 control_checked=False
 saved=J(P/'constructor/r51-depth2-audit.json.gz');require(saved['direct_sites']==80 and saved['mismatches']==[],'retained constructor depth totals')
 by_site={row['original_site']:row for row in saved['all_sites']};require(len(by_site)==80,'retained constructor depth membership')
 for row in graph['all_actual_direct_calls']:
  first,second=int(row['original_target'],16),int(row['candidate_target'],16)
  require(identity(0,first,2)==identity(1,second,2),'actual sell callee depth-two identity differs')
  retained=by_site[row['original_site']]
  require(retained['candidate_site']==row['candidate_site']and retained['candidate_target']==row['candidate_target']and retained['equal_depths_0_1_2']==[True,True,True],'retained depth record differs')
  require(retained['original_identity']==identity(0,first,2)and retained['candidate_identity']==identity(1,second,2),'retained depth identity differs')
  if first==0x6528:
   control_checked=True;require(any('8try_from'in name for name in row['candidate_names']),'constructor is not checked')
 require(control_checked,'constructor site absent')
 return {'paired_register_exact_cfg_blocks':77,'actual_callee_depth2_sites':80,'actual_callee_depth2_mismatches':0,'original_constructor':'0x6528','diagnostic_scope':'Branch inversion/forwarder canonicalization locates layout only; does not award a window'}

def verify(repo=ROOT,runtime=None,signatures=False,source_root=None,require_current=True):
 repo=Path(repo).resolve();manifest(P);base=repo/BASE;manifest(base,BASE_MANIFEST)
 baseline=module('checked_base_gate',base/'verify.py').verify(repo,current_source=False)
 require(baseline['candidate_sha256']==CONTROL and baseline['normalized']==784 and baseline['raw']==394,'base qualification differs')
 recipe=module('checked_source_recipe',base/'workspace_recipe.py');old=archive(base/'results/build-a/canonical-source.tar.gz');new=archive(P/'sources/canonical-source.tar.gz')
 require(set(old)==set(new)and len(new)==68,'canonical overlay membership')
 require([name for name in sorted(new)if new[name]!=old[name]]==[FILE]and old[FILE].count(OLD)==1 and new[FILE]==old[FILE].replace(OLD,NEW),'overlay is not the exact checked-constructor correction')
 patch=''.join(difflib.unified_diff(old[FILE].decode().splitlines(keepends=True),new[FILE].decode().splitlines(keepends=True),fromfile='a/'+FILE,tofile='b/'+FILE));require(patch==(P/'source.patch').read_text(),'source patch differs')
 checked_source=Path(source_root or repo).resolve()
 if require_current:require(recipe.source_inputs(checked_source)==new,'selected/current source differs from checked-constructor proposal')
 with tempfile.TemporaryDirectory()as temporary:
  temporary=Path(temporary);canonical=temporary/'canonical';canonical.mkdir()
  for name,raw in new.items():
   target=canonical/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  _,workspace=recipe.expected_workspace(canonical);digests={name:H(raw)for name,raw in workspace.items()}
  require(archive(P/'builds/initial/source.tar.gz')==workspace and J(P/'builds/initial/source-sha256.json')==digests,'initial source workspace binding')
  record=J(P/'builds/repeat/build-record.json');require(record['returncode']==0 and record['source_unchanged']is True and record['source_sha256']==record['source_after_sha256']==digests,'repeat source binding')
  require(record['canonical_sha256']=={name:H(raw)for name,raw in new.items()}and archive(P/'builds/repeat/canonical-source.tar.gz')==new,'repeat canonical source binding')
  require(record['harness_sha256']==record['harness_after_sha256']=={name:H((base/name).read_bytes())for name in ['build.py','workspace_recipe.py']},'repeat executed builder binding')
  require(all(H((P/'builds/repeat/harness'/name).read_bytes())==digest for name,digest in record['harness_sha256'].items()),'repeat controller snapshots differ')
  inventory=J(P/'builds/repeat/dependencies.json.gz');module('checked_base_dependencies',base/'verify.py').dependencies(workspace['Cargo.lock'],inventory,archive(base/'results/registry-archives.tar.gz'))
  require(J(P/'builds/repeat/sdk-sha256.json')==J(base/'results/build-a/sdk-sha256.json'),'repeat SDK differs')
  blobs={}
  for name,expected in [('candidate.so',CANDIDATE),('symbols.so',SYMBOLS)]:
   first=read(P/'builds/initial'/(name+'.gz'));second=read(P/'builds/repeat'/(name+'.gz'));require(first==second and H(first)==expected,'independent full ELF repeat differs');blobs[name]=first
  require(record['candidate_sha256']==CANDIDATE and record['symbols_sha256']==SYMBOLS,'repeat output binding')
  log=read(P/'builds/repeat/build.log.gz').decode();require('--crate-name pump_amm_recovered'in log and 'Running `'in log,'repeat compiler was not executed')
  candidate=temporary/'candidate.so';symbols=temporary/'symbols.so';candidate.write_bytes(blobs['candidate.so']);symbols.write_bytes(blobs['symbols.so'])
  control=(base/'results/build-a/candidate.so').read_bytes();different=[index for index,(a,b)in enumerate(zip(control,blobs['candidate.so']))if a!=b]
  require(len(control)==len(blobs['candidate.so'])==1268504 and different==[0x4dc84,0x4dc85],'ELFs do not differ solely in the constructor CALL operand')
  require(control[0x4dc80:0x4dc82]==blobs['candidate.so'][0x4dc80:0x4dc82]==bytes.fromhex('8510'),'changed instruction is not a direct CALL')
  old_target=0x4dc88+struct.unpack_from('<i',control,0x4dc84)[0]*8;new_target=0x4dc88+struct.unpack_from('<i',blobs['candidate.so'],0x4dc84)[0]*8
  require((old_target,new_target)==(0x3a10,0x6178),'constructor targets differ')
  measure=module('checked_census',base/'tools/measure.py');rows=measure.measure(repo/'evidence/original/pump_amm/deployed.so',symbols);prior=J(base/'results/windows.json')
  membership=lambda values,key:{row['original']for row in values if row[key]};require(all(membership(rows,key)==membership(prior,key)for key in ['match','raw']),'official window membership changed')
  require((sum(bool(row['match'])for row in rows),sum(row['raw']for row in rows))==(784,394),'census differs')
  depths=constructors(repo,symbols,base)
 inputs=J(P/'runtime/full/inputs.json');old_inputs=J(base/'results/runtime/corpus/inputs.json');require(inputs['harness_sha256']==old_inputs['harness_sha256']and inputs['observer_sha256']==old_inputs['observer_sha256'],'full corpus producers changed')
 corpus=module('checked_full_runtime',base/'audit_runtime.py').audit(Path(runtime)if runtime else P/'runtime/full',CANDIDATE,signatures)
 narrow=focused(base,signatures)
 return {'status':'PASS','candidate_sha256':CANDIDATE,'symbols_sha256':SYMBOLS,'base_manifest_sha256':BASE_MANIFEST,'checked_source_root':str(checked_source)if require_current else None,'current_source_verified':bool(require_current and checked_source==repo),'proposed_source_verified':require_current,'independent_source_forced_repeat_identical':True,'canonical_inputs':68,'workspace_inputs':69,'normalized':784,'raw':394,'new_window_gains':0,'whole_elf_identical':False,'sole_changed_call_target':{'site':'0x4dc80','old':'0x3a10','new':'0x6178','different_bytes':2},'constructor':depths,'focused':narrow,'full_corpus':corpus,'scope':'One-line checked-constructor provenance recovery; sell basic-block ordering and whole-ELF equality remain open'}

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=Path,default=ROOT);parser.add_argument('--source-root',type=Path);parser.add_argument('--runtime',type=Path);parser.add_argument('--signatures',action='store_true');parser.add_argument('--saved-only',action='store_true');args=parser.parse_args();print(json.dumps(verify(args.repo,args.runtime,args.signatures,args.source_root,not args.saved_only),indent=2))
