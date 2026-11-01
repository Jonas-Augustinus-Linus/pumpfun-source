"""Replay retained static evidence using only Python's standard library."""
from pathlib import Path, PurePosixPath
import gzip,hashlib,io,json,re,tarfile,tempfile,types
P=Path(__file__).resolve().parent
def check(ok,msg):
 if not ok:raise ValueError(msg)
def digest(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def raw(p):return gzip.decompress(p.read_bytes()) if p.suffix=='.gz' else p.read_bytes()
def read(p):return json.loads(raw(p))
def module(p):
 m=types.ModuleType(p.stem);m.__file__=str(p);exec(compile(p.read_bytes(),str(p),'exec'),m.__dict__);return m
def commands(log):return [l.strip()[8:-1] for l in log.splitlines() if l.strip().startswith('Running `') and ' --crate-name ' in l]
def verify(root=P):
 root=Path(root);manifest=read(root/'manifest.json');files={}
 for p in root.rglob('*'):
  check(not p.is_symlink() and (p.is_file() or p.is_dir()),'special file')
  if p.is_file() and p!=root/'manifest.json':files[p.relative_to(root).as_posix()]=digest(p.read_bytes())
 check(files==manifest,'packet membership/hash mismatch')
 binding=read(root/'source-binding.json');source=raw(root/'source.tar.gz')
 # The binding describes the compressed Git blob.
 compressed=(root/'source.tar.gz').read_bytes();check(blob(compressed)==binding['git_blob']=='b32b0f08de2c956e1b33df189455500dbd4a0c4c' and digest(compressed)==binding['sha256'],'source binding')
 members={}
 with tarfile.open(fileobj=io.BytesIO(source),mode='r:') as t:
  for m in t.getmembers():
   p=PurePosixPath(m.name);check(m.isfile() and not p.is_absolute() and '..' not in p.parts and ':' not in m.name and '\\' not in m.name and m.name not in members,'source member')
   members[m.name]=t.extractfile(m).read()
 check({k:digest(v) for k,v in members.items()}==binding['files'] and len(members)==62,'source member hashes')
 import tomllib
 locked={x['name']+'-'+x['version']:x['checksum'] for x in tomllib.loads(members['Cargo.lock'].decode())['package'] if 'checksum' in x}
 vendor=read(root/'vendor-acquisition.json');check({x['name']:x['sha256'] for x in vendor}==locked and len(vendor)==257,'registry lock binding')
 for r in read(root/'upstream-inputs.json')['files']:
  p=root/'upstream'/r['path'].split('research/claude-amm-union6-20261028/',1)[1];b=p.read_bytes();check(digest(b)==r['sha256'] and blob(b)==r['git_blob'],'upstream input binding')
 original=raw(root/'original.so.gz');r=next(x for x in read(root/'original-acquisition.json') if x['local']=='original.so')
 check(digest(original)==r['sha256']=='6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7' and blob(original)==r['git_blob'],'original binding')
 check(read(root/'scope.json')==dict(source_changes=0,binary_patching=False,original_derived_layout=False,target_executions=0,whole_elf_identity=False,allocation_identity=False,historical_provenance_proven=False,runtime_qualification=False,maintained_promotion=False),'unsupported scope')
 cases=read(root/'cases.json');check(set(cases)=={'01-official','02-linux-sysroot','03-linux-explicit','04-linux-repeat','05-windows-explicit','06-controller'},'case membership')
 outputs={};launches={};total=0
 for label,claim in cases.items():
  b=root/'builds'/label;launch=read(b/'launch.json.gz');result=read(b/'result.json.gz');launches[label]=launch
  check(launch['source_inputs']==binding['files'] and launch['target_directory_initially_absent'] is True and result['source_unchanged'] is True and launch['target_executions']==result['target_executions']==0,'build source/freshness scope')
  log=raw(b/'stderr.log.gz').decode();cs=commands(log);target=sum(' --target sbpf-solana-solana ' in x for x in cs)
  check((len(cs),target,len(cs)-target)==(claim['compiler_commands'],claim['target_commands'],claim['host_commands']),'compiler command inventory')
  check(len(re.findall(r'^ +Fresh ',log,re.M))==claim['fresh_lines']==0,'reused Cargo artifacts')
  for n in ['stdout.log','stderr.log']:check(digest(raw(b/(n+'.gz')))==result['logs'][n],'build log binding')
  check(result['returncode']==claim['returncode'],'build outcome')
  command=launch['command'];check(command[1:4]==['build','--release','--target'] and '--offline' in command and '--locked' in command and '--verbose' in command,'build command')
  env=launch['environment'];check(env['CARGO_NET_OFFLINE']=='true' and not any(k in env for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER']),'compiler environment')
  expected='-Zremap-cwd-prefix='
  if label in ['02-linux-sysroot','03-linux-explicit','04-linux-repeat','06-controller']:
   check(env['CARGO_TARGET_SBPF_SOLANA_SOLANA_RUSTFLAGS'].startswith(expected+' --sysroot='),'Linux target libraries')
  else:check(env['CARGO_TARGET_SBPF_SOLANA_SOLANA_RUSTFLAGS']==expected,'Windows target flags')
  if label=='02-linux-sysroot':
   check(result['returncode']==101 and 'linker `rust-lld` not found' in log and not (b/'symbols.so.gz').exists(),'failed linker control');continue
  check(result['returncode']==0 and len(cs)==215 and target==124 and sum('--crate-name pump_amm_recovered ' in x for x in cs)==1,'complete fresh build')
  check('admin_update_token_incentives' in log and 'overwrites values in the frame' in log,'retained frame diagnostic')
  full=raw(b/'symbols.so.gz');stripped=raw(b/'stripped.so.gz');check(digest(full)==claim['symbols_sha256']==result['symbols_sha256'] and digest(stripped)==claim['stripped_sha256'],'output binding')
  strip=read(b/'strip-result.json.gz');check(strip['returncode']==0 and strip['command'][1]=='--strip-all','ordinary strip command')
  artifacts=read(b/'artifacts.json.gz');check(artifacts['sbpf-solana-solana/release/pump_amm_recovered.so']==digest(full),'target artifact binding')
  if label=='06-controller':check(launch['controller_sha256']==digest((root/'build.py').read_bytes()),'tested controller binding')
  outputs[label]=(full,stripped);total+=len(cs)
 check(outputs['01-official']==outputs['05-windows-explicit'],'explicit linker control changed output')
 check(outputs['03-linux-explicit']==outputs['04-linux-repeat']==outputs['06-controller'],'fresh Linux-library repeats differ')
 measure=module(root/'measure.py');Elf=module(root/'elf_reader.py').Elf
 with tempfile.TemporaryDirectory() as td:
  td=Path(td);op=td/'original.so';op.write_bytes(original);o=Elf(op);rows={};elfs={}
  all_outputs=dict(outputs,upstream=(raw(root/'upstream/builds/a/symbols.so.gz'),raw(root/'upstream/builds/a/candidate.so.gz')))
  for label,(full,stripped) in all_outputs.items():
   p=td/(label+'.so');p.write_bytes(full);rows[label]=measure.measure(op,p);elfs[label]=Elf(p)
   sp=td/(label+'-stripped.so');sp.write_bytes(stripped);s=Elf(sp);e=elfs[label]
   for name,sec in e.secs.items():
    if sec[2]&2:
     check(name in s.secs,'stripped allocated section missing');other=s.secs[name];check(sec[3]==other[3] and e.b[sec[4]:sec[4]+sec[5]]==s.b[other[4]:other[4]+other[5]],'allocated section altered by stripping')
  norm=lambda label:{r['original'] for r in rows[label] if r['match']}
  raws=lambda label:{r['original'] for r in rows[label] if r['raw']}
  check(len(rows['upstream'])==785 and len(norm('upstream'))==779 and len(raws('upstream'))==220,'archived measurement')
  for label in outputs:
   n,r=(774,211) if label in ['01-official','05-windows-explicit'] else (779,221)
   check((len(norm(label)),len(raws(label)))==(n,r),'fresh measurement')
  check(norm('03-linux-explicit')==norm('upstream'),'normalized set changed')
  check(raws('03-linux-explicit')-raws('upstream')=={'0xcaa8'} and not raws('upstream')-raws('03-linux-explicit'),'raw gains/losses')
  check(norm('03-linux-explicit')-norm('01-official')=={'0xa9b0','0xf8ca0','0x1016a8','0x10efd8','0x111b38'} and not norm('01-official')-norm('03-linux-explicit'),'sysroot five-window control')
  e=elfs['03-linux-explicit'];a=elfs['upstream'];gain=read(root/'raw-gain.json');begin=int(gain['candidate'],16);old=int(gain['archived_candidate'],16);base=0xcaa8;size=1424
  check(begin==0xc940 and o.b[base:base+size]==e.b[begin:begin+size] and digest(o.b[base:base+size])==gain['sha256'],'complete raw gain')
  differences=[dict(offset=i,original=o.b[base+i:base+i+8].hex(),archived=a.b[old+i:old+i+8].hex()) for i in range(0,size,8) if o.b[base+i:base+i+8]!=a.b[old+i:old+i+8]]
  check(differences==gain['archived_different_instructions'] and [x['offset'] for x in differences]==[72,256,432,608,792,968,1144,1304],'eight call distances')
  oc=o.callsites(base,size);cc=e.callsites(begin,size);check(len(oc)==len(cc)==len(gain['calls'])==8 and e.pattern(begin,size)==gain['relocations']==[],'gain call/relocation inventory')
  for x,y,receipt in zip(oc,cc,gain['calls']):
   check(x['offset']==y['offset']==receipt['offset'] and x['target']==0xb760 and y['target']==0xb5f8,'actual call target')
   n=328;ob=o.b[x['target']:x['target']+n];cb=e.b[y['target']:y['target']+n]
   check(digest(ob)==receipt['original']['sha256'] and digest(cb)==receipt['candidate']['sha256'] and ob!=cb and receipt['raw_body_equal'] is False,'callee is not raw-identical')
   check(o.normalized[x['target']:x['target']+n]==e.normalized[y['target']:y['target']+n] and o.pattern(x['target'],n)==e.pattern(y['target'],n) and receipt['normalized_body_equal'] is True,'immediate callee normalized body')
  check(all(next(r for r in rows[label] if r['original']=='0xf28b8')['raw'] for label in outputs),'scanner preserved')
 return dict(status='PASS',successful_fresh_builds=5,successful_compiler_commands=total,retained_failed_compiler_commands=189,normalized=779,raw=221,new_raw_window='0xcaa8',whole_elf_identity=False,runtime_qualification=False)
if __name__=='__main__':print(json.dumps(verify(),indent=2))
