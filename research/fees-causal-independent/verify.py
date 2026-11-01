"""Independent compiler/IR/call and signed-state checks; no target execution."""
if not __debug__:
    raise SystemExit('Assertions are required; do not run with -O')
from pathlib import Path
from collections import Counter
from functools import lru_cache
import base64,gzip,hashlib,importlib.util,io,json,lzma,re,tarfile,tempfile

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
ORIGINAL='4f2955d0f6b40cc9ff7daa18ccad7d19119ba1249759f4e7e3bb691beee6b35e'
HASHES={
 'before':('a6c604519704b04ddac659104aaca3fa438f5a27ba584c7531707172041e004a','d8d7905097fa4fde8ac3e55762d0f024bb226581f2902eda789861a62af999c9'),
 'after':('7f12e1313a5c6f028f9d124563109a02a6ac630f52d83203f65764c640ab3025','aa039a96a1dcbbce069c2b11446566daa8cf04051474e062ac580e29963bbb7a')}
FROM_ERROR='a77a340c56e0ce7faaf098a22acc6e7b9a0b952a71858a9e6ab74fe064c5b035'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):return json.loads(p.read_bytes())
@lru_cache(maxsize=1)
def fees_id():return load(ROOT/'evidence/upstream/pump_fees.json')['address']
def unpack(p):return gzip.decompress(p.read_bytes())
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def bindings():
    expected=load(HERE/'manifest.json')
    files={p.relative_to(HERE).as_posix()for p in HERE.rglob('*')if p.is_file()and '__pycache__'not in p.parts and p.name!='manifest.json'}
    assert files==set(expected),'packet membership'
    for name,digest in expected.items():assert sha((HERE/name).read_bytes())==digest,('packet hash',name)
    for name,digest in load(HERE/'references.json').items():assert sha((ROOT/name).read_bytes())==digest,('external hash',name)

def source_stages():
    with tempfile.TemporaryDirectory(prefix='fees-public-source-')as directory:
        p=Path(directory);prefix='research/fees-causal582-source/'
        with tarfile.open(HERE/'public302.tar.xz')as archive:
            seen=set()
            for member in archive:
                if member.isdir():continue
                assert member.isfile()and member.name.startswith(prefix)and member.name not in seen
                seen.add(member.name);name=member.name[len(prefix):]
                assert not Path(name).is_absolute()and '..'not in Path(name).parts
                f=p/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(archive.extractfile(member).read())
        source=module('fees_public_source302',p/'source_tools.py')
        metadata,before,after=source.stages(p)
        assert len(seen)==55 and len(before)==len(after)==48
        assert sum(before[n]!=after[n]for n in before)==2
        return metadata

def builds(metadata):
    images={}
    for label,stage in [('before','before'),('after','after'),('portable','after')]:
        d=HERE/'builds'/label;launch,result=load(d/'launch.json'),load(d/'result.json')
        c,s=unpack(d/'candidate.so.gz'),unpack(d/'symbols.so.gz')
        assert (sha(c),sha(s))==HASHES[stage]
        assert all(result[k]for k in ['source_unchanged','registry_unchanged','tools_unchanged'])
        assert result['returncode']==0 and result['root_invocations']==1
        assert launch['source_inputs']==metadata[stage]and launch['empty_target']is True and launch['originals_mounted']is False
        assert launch['command'][:7]==['docker','run','--rm','--platform','linux/amd64','--network','none']
        assert '--locked'in launch['command']and '--offline'in launch['command']
        controller=HERE/('reproduce.py'if label=='portable'else'controllers/build.py')
        assert sha(controller.read_bytes())==launch['controller_sha256']
        assert result['artifacts']=={'candidate.so':{'sha256':sha(c),'bytes':len(c)},'symbols.so':{'sha256':sha(s),'bytes':len(s)}}
        assert sha(unpack(d/'build.log.gz'))==result['log_sha256']
        images[label]=(c,s)
    assert images['after']==images['portable']
    return images

def copy24(rows,offset):
    """Verify three actual frame loads/stores feeding r2 at a direct conversion call."""
    at={r['offset']:r for r in rows};sequence=[at[offset-80+i*8]for i in range(10)]
    source=[];dest=[]
    for a,b in zip(sequence[:6:2],sequence[1:6:2]):
        assert a['opcode']==0x79 and a['source']==10
        assert b['opcode']==0x7b and b['destination']==10 and b['source']==a['destination']
        source.append(a['displacement']);dest.append(b['displacement'])
    assert source==[source[-1]+16,source[-1]+8,source[-1]]
    assert dest==[dest[-1]+16,dest[-1]+8,dest[-1]]
    a,b=sequence[-2:]
    assert (a['opcode'],a['destination'],a['source'])==(0xbf,2,10)
    assert (b['opcode'],b['destination'],b['immediate'])==(7,2,dest[-1])
    return {'source_frame_offset':source[-1],'destination_frame_offset':dest[-1],'copied_bytes':24,'copy_instructions':6,'call_offset':offset}

def crank_ir(body,extra):
    copies=re.findall(r'@llvm.memcpy[^\n]*i64 (\d+), i1 false',body)
    assert Counter(copies)==Counter({'32':29,'24':4 if extra else 3,'120':2,'36':2,'5':2})
    if extra:
        start=body.index('dereferenceable(24) %_272,')
        region=body[start:body.index('\n\nbb1.i.i.i154:',start)]
        assert region.index('dereferenceable(24) %_73,')<region.index('ProgramError')<region.index('%a.sroa.8.0.copyload')
        assert 'dereferenceable(24) %_272) #25'in region,'conversion must use copied error'
    return dict(Counter(copies))

def static(images):
    w=module('fees_independent_windows',ROOT/'research/fees-composed-frontier188/window_map.py')
    h=module('fees_independent_contracts',ROOT/'research/fees-frontier-prefix-integration/frontier_contract.py')
    original=(ROOT/'evidence/original/pump_fees/deployed.so').read_bytes();assert sha(original)==ORIGINAL
    ow=w.windows(original);oi={f['address']:f for f in ow};reports={};previous=None
    def allocated(a,b):
        for sec in w.m.elf_layout(a)['sections']:
            if sec['flags']&2 and sec['type']!=8:
                other=next(s for s in w.m.elf_layout(b)['sections']if s['name']==sec['name'])
                assert sec['address']==other['address']and w.m.section_data(a,sec['name'])==w.m.section_data(b,sec['name'])
    for stage in ['before','after']:
        c,s=images[stage];allocated(c,s);cw=w.windows(s);ci={f['address']:f for f in cw}
        pairs=w.compare(ow,cw)['unique_pairs'];mapping={p['original']['address']:p['candidate']['address']for p in pairs}
        normalized=[f['address']for f in ow if f['signature']in {r['signature']for r in cw}]
        raw=[f['address']for f in ow if f['raw_sha256']in {r['raw_sha256']for r in cw}]
        loc=h.cohort(w,original,c,pairs);edges=h.direct_edges(w,original,c,ow,cw,pairs)
        positives={(r[0],r[1]):r[2:]for r in edges if r[2]==r[3]}
        assert len(normalized)==582 and len(raw)==143 and len(loc)==185 and all(x==y for x,y in loc.values())
        assert len(edges)==4101 and len(positives)==4098
        cohort=(normalized,raw,loc,positives)
        if previous is not None:assert cohort==previous,'prior matched obligations changed'
        previous=cohort;targets={}
        ir=unpack(HERE/'ir'/stage/'root.ll.gz').decode()
        irsymbols=unpack(HERE/'ir'/stage/'symbols.so.gz');allocated(s,irsymbols)
        qualification=load(HERE/'ir'/stage/'qualification.json')
        assert qualification['ir_sha256']==sha(ir.encode())and qualification['ir_link_symbols_sha256']==sha(irsymbols)
        assert qualification['stripped_candidate_sha256']==sha(c)and qualification['stripped_candidate_equal']is True
        assert unpack(HERE/'ir'/stage/'candidate.so.gz')==c and s!=irsymbols
        for kind,wrapper,call_offset,original_body,expected_size in [('crank',656832,464,147944,15688 if stage=='before' else 15736),('create',655904,424,163920,13888 if stage=='before' else 13864)]:
            own=mapping[wrapper]
            call=next(r for r in w.m.instructions(s,own,ci[own]['bytes'])if r['offset']==call_offset)
            assert dict(w.m.relocations(s)).get(own+call_offset,0)&0xffffffff!=10
            body=ci[call['call_target']];assert body['bytes']==expected_size and body['signature']!=oi[original_body]['signature']
            rows=w.m.instructions(s,body['address'],body['bytes'])
            start=re.search(r'^define .*@'+re.escape(body['name'])+r'\(',ir,re.M).start();end=ir.index('\n}',start)+2;function=ir[start:end]
            item=dict(wrapper_original=wrapper,wrapper_candidate=own,call_offset=call_offset,original_body=original_body,original_bytes=oi[original_body]['bytes'],candidate_body=body['address'],candidate_bytes=expected_size,complete_body_equal=False,ir_function_sha256=sha(function.encode()))
            if kind=='crank':
                rel=dict(w.m.relocations(s));calls=[r for r in rows if 'call_target'in r and rel.get(body['address']+r['offset'],0)&0xffffffff!=10 and ci[r['call_target']]['signature']==FROM_ERROR]
                assert len(calls)==9
                item['ir_memcpy_counts']=crank_ir(function,stage=='after')
                if stage=='after':
                    item['copy24']=copy24(rows,calls[7]['offset'])
                    orows=w.m.instructions(original,original_body,oi[original_body]['bytes']);orel=dict(w.m.relocations(original))
                    ocalls=[r for r in orows if 'call_target'in r and orel.get(original_body+r['offset'],0)&0xffffffff!=10 and oi[r['call_target']]['signature']==FROM_ERROR]
                    assert len(ocalls)==9;item['original_copy24']=copy24(orows,ocalls[7]['offset'])
                else:
                    try:copy24(rows,calls[7]['offset'])
                    except AssertionError:pass
                    else:raise AssertionError('before unexpectedly has the restored copy')
            else:
                item['ir_memcpy_counts']=dict(Counter(re.findall(r'@llvm.memcpy[^\n]*i64 (\d+), i1 false',function)))
                assert item['ir_memcpy_counts']['32']==(48 if stage=='before' else 47)
            targets[kind]=item
        reports[stage]=dict(normalized=582,raw=143,locations=185,retained_equal_direct_calls=4098,open_direct_calls=3,bodies=targets,whole_elf_equal=c==original[:w.m.elf_layout(original)['elf_extent']])
        assert reports[stage]['whole_elf_equal']is False
    return reports

def validate_pair(o,c,original_digest,candidate_digest,known):
    from solders.transaction import Transaction
    signatures=0
    for row,digest in [(o,original_digest),(c,candidate_digest)]:
        assert row['fees_sha256']==digest,'loaded Fees artifact'
        assert all(h in known for h in row['loaded_programs'].values()),'loaded dependency'
        assert row['loaded_programs'][fees_id()]==digest
        tx=Transaction.from_bytes(base64.b64decode(row['transaction_base64'],validate=True))
        checks=tx.verify_with_results();assert checks and all(checks),'cryptographic signature'
        assert len(checks)==row['signature_fields'];signatures+=len(checks)
    for key in ['transaction_base64','error','before','after','inner','return_data']:assert o[key]==c[key],('execution field',key)
    log=lambda row:[s for s in row['logs']if s.startswith(('Program log:','Program data:','Program return:'))]
    assert log(o)==log(c),'program logs'
    return signatures,o['logs']!=c['logs']

def runtime(stage):
    folder=HERE/'runtime'/stage;result=[]
    headers=sorted(folder.glob('*-observed.json'))
    assert len(headers)==(18 if stage=='after' else 2)
    for file in headers:
        name=file.name[:-len('-observed.json')];header=load(file)
        assert header['observer_sha256']==sha((HERE/'controllers/observer.py').read_bytes())
        assert header['script_sha256']==sha((ROOT/header['script']).read_bytes())
        for n,h in header['input_reads'].items():assert sha((ROOT/n).read_bytes())==h,('producer read',n)
        known={v['sha256']for v in header['loaded_files'].values()}
        for record in header['loaded_files'].values():
            if record['sha256']in HASHES[stage]:continue
            assert record['sha256']in load(HERE/'references.json').values()
        canonical=json.loads(unpack(folder/(name+'.json.gz')))
        width=4 if name=='sharing_update' else 2
        cases=signatures=raw_logs=transactions=bootstrap_pairs=0
        with gzip.open(folder/(name+'-observed.jsonl.gz'),'rt')as stream:
            while True:
                first=stream.readline()
                if not first:break
                group=[json.loads(first)]+[json.loads(next(stream))for _ in range(width-1)]
                assert [r['sequence']for r in group]==list(range(transactions,transactions+width))
                if width==4:
                    b1,o,b2,c=group
                    sig,diff=validate_pair(b1,b2,ORIGINAL,ORIGINAL,known)
                    assert not diff,'identical-original bootstraps differ'
                    signatures+=sig;bootstrap_pairs+=1
                    case=canonical['cases'][cases]
                    assert case['original']['bootstrap_transaction_base64']==b1['transaction_base64']
                    assert case['candidate']['bootstrap_transaction_base64']==b2['transaction_base64']
                    assert case['original']['transaction_base64']==o['transaction_base64']
                    assert case['candidate']['transaction_base64']==c['transaction_base64']
                else:o,c=group
                sig,diff=validate_pair(o,c,ORIGINAL,HASHES[stage][0],known)
                signatures+=sig;raw_logs+=diff;cases+=1;transactions+=width
        assert transactions==header['transactions']and signatures==header['signature_fields']
        assert canonical['original_sha256']==ORIGINAL and canonical['candidate_sha256']==HASHES[stage][0]
        assert canonical.get('case_count',len(canonical['cases']))==cases
        assert not canonical.get('mismatches',canonical.get('failures',[]))
        result.append(dict(suite=name,cases=cases,transactions=transactions,signature_fields=signatures,original_bootstrap_pairs=bootstrap_pairs,extended_differences=0,raw_log_differences=raw_logs))
    assert sum(r['cases']for r in result)==(17331 if stage=='after' else 713)
    return result

def main():
    bindings();metadata=source_stages();images=builds(metadata)
    report=dict(static=static(images),runtime={s:runtime(s)for s in ['before','after']})
    assert report==load(HERE/'summary.json'),'recomputed results differ'
    print('PASS: exact48-input before/after builds; 582/143 retained; compiler-bound Crank copy; 17331 after cases and713 before subset; all signatures/state/program logs agree')

if __name__=='__main__':main()
