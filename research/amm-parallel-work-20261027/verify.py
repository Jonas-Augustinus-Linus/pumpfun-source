from pathlib import Path,PurePosixPath
import hashlib,json,tarfile
D=Path(__file__).resolve().parent
H=lambda b:hashlib.sha256(b).hexdigest()
m=json.loads((D/'manifest.json').read_bytes());actual={str(p.relative_to(D))for p in D.rglob('*')if p.is_file()};assert actual==set(m)|{'manifest.json'}
for name,digest in m.items():assert H((D/name).read_bytes())==digest,name
counts=[]
for row in json.loads((D/'archives.json').read_bytes()):
 p=D/row['archive'];assert H(p.read_bytes())==row['sha256']
 with tarfile.open(p,'r:gz')as t:
  members={}
  for x in t.getmembers():
   q=PurePosixPath(x.name);assert not q.is_absolute()and '..'not in q.parts and x.isfile();assert x.name not in members;members[x.name]=x
  target=next(n for n in members if n.count('/')==1 and n.endswith('/manifest.json'));prefix=target.rsplit('/',1)[0];raw=t.extractfile(members[target]).read();assert H(raw)==row['manifest_sha256'];inner=json.loads(raw)['files'];assert set(members)=={prefix+'/'+n for n in inner}|{target}
  for name,entry in inner.items():
   raw=t.extractfile(members[prefix+'/'+name]).read();assert len(raw)==entry['bytes']and H(raw)==entry['sha256'],name
  counts.append({'archive':row['archive'],'files':len(members)})
print(json.dumps({'verified':True,'published_files':len(m),'archives':counts,'executes_archived_code':False}))
