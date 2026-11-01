#!/usr/bin/env python3
"""irnorm.py <a.ll> <b.ll>: diff execute's body with local value/block names canonicalised by first occurrence."""
import sys,re,difflib
def body(p):
    t=open(p).read()
    m=re.search(r'^define [^\n]*admin_cto7execute17',t,re.M)
    if m is None: raise SystemExit('irnorm: no definition of admin_cto::execute in '+p)
    i=m.start(); j=t.index('\n}\n',i)
    L=t[i:j].split('\n'); m={}; out=[]
    tok=re.compile(r'%("[^"]+"|[-\w.$]+)')
    for l in L:
        def f(x):
            k=x.group(0)
            if k not in m: m[k]='%%v%d'%len(m)
            return m[k]
        l=re.sub(r'!\d+','!M',l); out.append(tok.sub(f,l))
    return out
a=body(sys.argv[1]); b=body(sys.argv[2])
for l in difflib.unified_diff(a,b,lineterm='',n=1): print(l[:200])
