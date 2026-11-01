#!/usr/bin/env python3
"""Verify/materialize ordinary Fees source only; local ELF comparison is opt-in."""
import argparse, difflib, hashlib, importlib.util, json, subprocess, tomllib
from pathlib import Path, PurePosixPath
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'.git').exists())
def sha(data): return hashlib.sha256(data).hexdigest()
def read(path): return json.loads(path.read_bytes())
def safe_name(name):
 p=PurePosixPath(name)
 assert name and not p.is_absolute() and '..' not in p.parts and str(p)==name
 return p
def safe_file(root,name):
 p=root
 for part in safe_name(name).parts:
  p=p/part; assert not p.is_symlink(),p
 assert p.resolve().is_relative_to(root.resolve())
 return p
def public_blob(revision,name):
 safe_name(name);assert len(revision)==40 and all(c in '0123456789abcdef'for c in revision)
 return subprocess.check_output(['git','--no-optional-locks','show',revision+':'+name],cwd=ROOT)
def check_manifest():
 assert not(HERE/'manifest.json').is_symlink()
 assert all(not p.is_symlink()for p in HERE.rglob('*'))
 expected=read(HERE/'manifest.json')
 actual={str(p.relative_to(HERE))for p in HERE.rglob('*')if p.is_file()and p.name!='manifest.json'and'__pycache__'not in p.parts}
 assert actual==set(expected)
 for name,digest in expected.items():assert sha(safe_file(HERE,name).read_bytes())==digest,name
def patch_text(before,after):
 result=''
 for name in sorted(set(before)|set(after)):
  a=before.get(name,b'').decode();b=after.get(name,b'').decode()
  if a!=b:result+=''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+name,tofile='b/'+name))
 return result
def validate_sources(before,after):
 expected=read(HERE/'source-inputs.json');assert len(before)==36 and len(after)==41
 for label,source in [('baseline',before),('recovered',after)]:
  for name in source:safe_name(name)
  assert {name:sha(data)for name,data in source.items()}==expected[label]
 changed=sorted(n for n in after if after[n]!=before.get(n));assert len(changed)==18
 assert patch_text(before,after).encode()==(HERE/'source.patch').read_bytes()
 # The locked dependency change is exactly the authentic published version/checksum.
 a=tomllib.loads(before['Cargo.lock'].decode());b=tomllib.loads(after['Cargo.lock'].decode())
 old=next(x for x in a['package']if x['name']=='solana-program-entrypoint')
 new=next(x for x in b['package']if x['name']=='solana-program-entrypoint')
 assert old['version']=='2.3.0' and new['version']=='2.2.1'
 assert new['checksum']=='473ffe73c68d93e9f2aa726ad2985fe52760052709aaab188100a42c618060ec'
 changed_package=dict(old,version=new['version'],checksum=new['checksum']);assert changed_package==new
 a['package'][a['package'].index(old)]=changed_package;assert a==b
 return changed
def sources():
 spec=read(HERE/'baseline-sources.json');before={}
 assert len(spec['files'])==36
 for name,row in spec['files'].items():
  safe_name(name);data=public_blob(spec['revision'],row['path']);assert sha(data)==row['sha256'],name;before[name]=data
 after=dict(before)
 for p in (HERE/'source').rglob('*'):
  if p.is_file():
   name=str(p.relative_to(HERE/'source'));after[name]=safe_file(HERE/'source',name).read_bytes()
 validate_sources(before,after);return before,after
def materialize(destination,source):
 assert not destination.exists() and not destination.is_symlink()
 assert all(not p.is_symlink()for p in destination.parents)
 destination.mkdir(parents=True)
 for name,data in source.items():
  p=safe_file(destination,name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 assert {str(p.relative_to(destination)):sha(p.read_bytes())for p in destination.rglob('*')if p.is_file()}=={n:sha(b)for n,b in source.items()}
def static_result(before,after):
 return {'source_verified':True,'baseline_files':len(before),'recovered_files':len(after),'changed_or_added_files':validate_sources(before,after),'compiler_executed':False,'runtime_verified':False,'elf_comparison':'not requested'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--materialize',type=Path);p.add_argument('--baseline',action='store_true',help='Materialize the public36-input baseline instead');p.add_argument('--candidate',type=Path);p.add_argument('--symbols',type=Path);args=p.parse_args()
 assert (args.candidate is None)==(args.symbols is None),'Supply both local ELF paths'
 check_manifest();before,after=sources()
 if args.materialize:materialize(args.materialize,before if args.baseline else after)
 result=static_result(before,after)
 if args.candidate:
  spec=importlib.util.spec_from_file_location('fees_optional_local_compare',HERE/'compare.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  result['elf_comparison']=m.compare(args.candidate,args.symbols)
 print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
