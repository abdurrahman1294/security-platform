"""V74 Passive OSINT intelligence planner.
Builds source plans and normalized search pivots for lawful public-source research.
Avoids private-account access, credential collection, doxxing, or sensitive targeting.
"""
import json, re
from pathlib import Path

SOURCE_CATEGORIES={
 "web":"search engines, public websites, archived public pages",
 "technical":"DNS/WHOIS/CT logs, public code repositories, package registries",
 "organizations":"official company pages, registries, public filings",
 "media":"public news, interviews, press releases",
 "documents":"public PDFs, advisories, standards, conference material",
 "social":"public professional/social profiles; respect platform rules",
}

def _seed_type(seed):
    s=seed.strip()
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}",s): return "domain"
    if re.fullmatch(r"https?://.+",s): return "url"
    if re.fullmatch(r"[0-9a-fA-F:]{7,}",s): return "technical_identifier"
    return "entity"

def build(outdir, seed, objective="general", locations=None):
    outdir=Path(outdir); (outdir/"evidence").mkdir(parents=True,exist_ok=True); (outdir/"reports").mkdir(parents=True,exist_ok=True)
    st=_seed_type(seed); safe=seed.strip().replace('"','')
    pivots=[f'"{safe}"',f'"{safe}" filetype:pdf',f'"{safe}" security',f'"{safe}" technology',f'"{safe}" incident',f'"{safe}" contact']
    if st=="domain": pivots += [f'site:{safe}',f'site:{safe} login',f'site:{safe} api',f'site:{safe} github']
    data={"version":"V74","seed":safe,"seed_type":st,"objective":objective,"locations":locations or [],"source_categories":SOURCE_CATEGORIES,"search_pivots":pivots,"collection_mode":"passive-public-sources","restrictions":["no credential harvesting","no private-account access","no doxxing","no unauthorized active probing","respect source terms and law"]}
    p=outdir/"evidence"/"osint-plan-v74.json"; p.write_text(json.dumps(data,indent=2))
    (outdir/"reports"/"osint-plan-v74.md").write_text("# OSINT Intelligence Plan\n\nSeed: `%s`\nObjective: %s\n\n## Source plan\n%s\n\n## Search pivots\n%s\n"%(safe,objective,"\n".join(f"- **{k}**: {v}" for k,v in SOURCE_CATEGORIES.items()),"\n".join(f"- `{q}`" for q in pivots)))
    return p
