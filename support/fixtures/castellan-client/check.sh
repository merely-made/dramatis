#!/usr/bin/env bash
set -euo pipefail
# castellan-client's two tiers: the types alone, and the clients
# (djinn-slimming S3). Neither may reach Djinn, Armillary's serving crates,
# castellan or a product crate.
cd "$(dirname "$0")"
metadata_dir="${CASTELLAN_CLIENT_METADATA_DIR:-${TMPDIR:-/tmp}/castellan-client-fixture-metadata}"
mkdir -p "$metadata_dir"
for fixture in types client; do
  echo "Fixture: $fixture"
  crate=castellan-client
  name="castellan-client-$fixture"
  cargo test --offline --locked --manifest-path "$fixture/Cargo.toml" --lib
  cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu --manifest-path "$fixture/Cargo.toml" > "$metadata_dir/$name.json"
  python3 - "$metadata_dir/$name.json" "$metadata_dir/$name-cone.json" "$crate" <<'PYCODE'
import json,sys
m=json.load(open(sys.argv[1])); packages={p['id']:p for p in m['packages']}; nodes={n['id']:n for n in m['resolve']['nodes']}; seen=set(); pending=[m['resolve']['root']]
while pending:
    ident=pending.pop()
    if ident in seen: continue
    seen.add(ident)
    for d in nodes[ident]['deps']:
        if any(k['kind'] in (None,'build') for k in d['dep_kinds']): pending.append(d['pkg'])
forbidden=('mere','knot','graphshell','sceno','distillery','hest','chirograph')
forbidden+=('djinn','peer-facts','apparatus')
bad=sorted({packages[i]['name'] for i in seen if any(x in packages[i]['name'].lower() for x in forbidden) or packages[i]['name'] in ('castellan','armillary')})
root=nodes[m['resolve']['root']]
crate=sys.argv[3]
supplier=next(d['pkg'] for d in root['deps'] if packages[d['pkg']]['name']==crate)
direct=[]
for dep in nodes[supplier]['deps']:
    kinds=sorted({k['kind'] or 'normal' for k in dep['dep_kinds'] if k['kind'] in (None,'build')})
    if kinds: direct.append({'name':packages[dep['pkg']]['name'],'kinds':kinds,'features':nodes[dep['pkg']]['features']})
report={'normal_build_packages':sorted({packages[i]['name'] for i in seen}), 'forbidden':bad, 'root_features':root['features'], 'supplier':crate, 'supplier_features':nodes[supplier]['features'], 'supplier_direct_edges':sorted(direct,key=lambda e:e['name'])}
with open(sys.argv[2],'w') as out: json.dump(report,out,indent=2);out.write('\n')
print('normal/build packages:',len(seen),'forbidden:',bad,crate,'features:',report['supplier_features'])
assert not bad
PYCODE
  if [[ -f "$fixture/examples/forbidden.rs" ]]; then
    logfile="$metadata_dir/$name-forbidden.log"
    case "$fixture" in
      types) symbol=custody_client ;;
      *) echo "Unknown forbidden fixture: $fixture"; exit 1 ;;
    esac
    if cargo check --offline --locked --manifest-path "$fixture/Cargo.toml" --example forbidden > "$logfile" 2>&1; then cat "$logfile"; exit 1; fi
    if ! grep -q 'error\[E0432\]' "$logfile" || ! grep -Fq "no \`$symbol\` in" "$logfile"; then cat "$logfile"; exit 1; fi
    echo "forbidden import: expected E0432 for $symbol"
  fi
done
