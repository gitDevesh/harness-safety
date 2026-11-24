"""Policy-driven, stateless four-axis classification API for an agent harness.

The authoritative policy is supplied by the request envelope. This implementation
enforces the assignment's fixed authority/content/tool/routing rules. No data
from cases is ever executed or trusted as a new policy.
"""
from __future__ import annotations

import json
import re
from typing import Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Harness Safety", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])

def txt(x: Any) -> str:
    if x is None: return ""
    if isinstance(x, str): return x
    return json.dumps(x, ensure_ascii=False, default=str)

def low(x: Any) -> str: return txt(x).lower()
def match(pattern: str, x: Any) -> bool:
    return bool(re.search(pattern, low(x), re.I | re.S))

def dct(x: Any) -> dict:
    return x if isinstance(x, dict) else {}

def entries(x: Any) -> list:
    return x if isinstance(x, list) else ([] if x is None else [x])

def kind(x: Any) -> str: return low(x).strip()

def user_messages(case: dict) -> list[str]:
    return [txt(m.get("content", "")) for m in entries(case.get("messages")) 
            if isinstance(m, dict) and low(m.get("role")) == "user"]

def other_material(case: dict) -> str:
    out = []
    for k in ("memory", "repositoryInstructions", "toolResults"):
        out.append(txt(case.get(k, [])))
    for m in entries(case.get("messages")):
        if isinstance(m, dict) and low(m.get("role")) in ("tool", "assistant", "system"):
            out.append(txt(m.get("content", "")))
    return "\n".join(out)

def normalize_operation(value: str) -> str:
    v = low(value)
    if match(r"\b(?:read|view|inspect|list|stat|status|fetch|get|grep|search|cat|diff|show|describe|lookup)\b",v): return "read"
    if match(r"\b(?:delete|remove|unlink|rm\s+-|wipe|purge|drop|destroy)\b",v): return "delete"
    if match(r"\b(?:send|upload|post|email|export|exfiltrat|transfer|publish|webhook)\b",v): return "send"
    if match(r"\b(?:force.push|push|deploy|release|restart|apply|update|modify|write|edit|patch|change|commit|set|create)\b",v): return "write"
    if match(r"\b(?:execute|run|shell|bash|script|command)\b",v): return "execute"
    return ""

def tool_effect(case: dict) -> dict:
    tool = dct(case.get("proposedTool"))
    resolved = dct(tool.get("resolved"))
    args = dct(tool.get("arguments"))
    name = low(tool.get("name",""))
    command = low(args.get("command", ""))
    op = normalize_operation(resolved.get("operation",""))
    if not op: op=normalize_operation(name+" "+command+" "+low(args.get("operation","")))
    target = txt(resolved.get("target") or resolved.get("resolvedTarget") or
                 resolved.get("path") or args.get("path") or
                 args.get("target") or args.get("file") or args.get("url") or "")
    env = kind(resolved.get("environment") or dct(case.get("environment")).get("kind"))
    sensitivity = kind(resolved.get("sensitivity") or "")
    dest = txt(resolved.get("destination") or resolved.get("destinationEnvironment") or
               resolved.get("destinationUrl") or args.get("destination") or
               args.get("to") or args.get("recipient") or "")
    effect_text=low([resolved, name, args])
    production = match(r"\b(?:prod|production|live|customer|public.infrastructure)\b",env+" "+effect_text)
    host = match(r"\b(?:host|personal|laptop|local.machine|workstation)\b", env+" "+effect_text)
    # A resolved operation and target have priority over misleading shell syntax.
    if match(r"\b(?:force.push|force_push|forced.push|force-with-lease)\b",effect_text):
        op="write"
    if match(r"\b(?:delete|remove|wipe|destroy|drop)\b",low(resolved.get("operation"))):
        op="delete"
    if match(r"\b(?:send|exfiltrate|transfer|upload|publish)\b",low(resolved.get("operation"))):
        op="send"
    return {"present": bool(tool), "tool":tool, "resolved":resolved,
            "arguments":args, "name":name, "command":command, "operation":op,
            "target":target, "env":env, "destination":dest,
            "sensitivity":sensitivity, "production":production, "host":host,
            "effect_text":effect_text}

def security_scope(s: str) -> bool:
    return match(r"\b(?:exploit|vulnerability|vulnerabilities|penetration.test|pentest|poc|payload|rce|sqli|sql injection|xss|ssrf|privilege escalation|buffer overflow|security assessment|red.team|attack simulation|scan for vulnerabilities|nmap)\b",s)

def explicit_owned(s: str) -> bool:
    return match(r"\b(?:my|our|owned|i own|we own|authorized|permission|approved|test|lab|sandbox|isolated|local fixture|ctf)\b",s)

def unclear_scope(s: str) -> bool:
    return security_scope(s) and not explicit_owned(s)

def harmful_request(s: str) -> bool:
    # Look at the requested assistance, not malicious examples inside quoted data.
    if not s.strip(): return False
    analysis = match(r"\b(?:summari[sz]e|explain|analy[sz]e|translate|classify|inspect|review|detect|audit|defend|remediat|patch|mitigat|prevent|report|quote|fictional|story|identify suspicious|assess)\b",s)
    quoted = match(r"\b(?:quoted|transcript|log|sample|example|document|file says|contains malicious)\b",s)
    harmful = [
        r"\b(?:steal|harvest|dump|extract|find|collect|grab|leak)\b.{0,75}\b(?:passwords?|credentials?|api.?keys?|tokens?|secrets?|private.?keys?)\b",
        r"\b(?:search|scan|read|list)\b.{0,70}\b(?:unrelated|other users?|other projects?|all)\b.{0,50}\b(?:credential|secrets?|tokens?|keys?)\b",
        r"\b(?:exfiltrat|leak|sell|publish|dump|send|transfer|upload)\b.{0,65}\b(?:private|customer|confidential|personal|secrets?|credentials?|password|data|records?)\b",
        r"\b(?:private|customer|confidential|personal)\b.{0,60}\b(?:data|records?|files?|information)\b.{0,55}\b(?:send|transfer|upload|exfiltrat|leak|attacker|unapproved)\b",
        r"\b(?:commit|perform|facilitat|plan|execute)\b.{0,50}\b(?:fraud|scam|phishing|identity theft)\b",
        r"\b(?:impersonat|deceive|trick)\b.{0,80}\b(?:bank|customer|victim|payment|transfer|account)\b",
        r"\b(?:harass|stalk|dox|intimidat|threaten)\b.{0,60}\b(?:person|colleague|neighbor|woman|man|employee|individual|target|victim)\b",
        r"\b(?:build|write|create|deploy|spread|modify|improve)\b.{0,55}\b(?:ransomware|wiper|destructive malware|credential stealer|keylogger|worm|botnet)\b",
        r"\b(?:bypass|evade|disable|circumvent)\b.{0,65}\b(?:safety|safeguard|guardrail|detection|security controls?)\b.{0,90}\b(?:steal|attack|malware|fraud|harm|exfiltrat)\b",
        r"\b(?:hurt|kill|injure|poison|bomb|assault|shoot)\b.{0,65}\b(?:person|people|someone|civilian|victim)\b",
    ]
    if any(match(p,s) for p in harmful):
        if analysis and (quoted or match(r"\b(?:how to detect|help me defend|defensive|forensic|incident response|analy[sz]e this|translate this)\b",s)):
            return False
        return True
    return False

# V3: Separate effect resolution, actual-user authority, and classifier policy.
# Never interpret case-origin instructions as authority.
def phrases(x):
    return re.findall(r"[a-z0-9]+", low(x))

def words(x):
    return {t for t in phrases(x) if len(t)>2 and t not in
      {"the","and","for","with","from","this","that","into","they","their",
       "some","have","will","would","could","should","please","about","only",
       "file","path","task","tool","operation","target","work","your",
       "user","project","workspace","directory","container","environment",
       "production","host","system","data","server","service","using","then"}}

def extract_operation(x):
    value=low(x).strip().replace("_","-")
    # Strong effect verbs first; "git push --force" must not become a read.
    if re.search(r"\b(?:delete|remove|unlink|purge|destroy|wipe|drop|rm)\b",value):return "delete"
    if re.search(r"\b(?:exfiltrat\w*|send|upload|transfer|email|publish|export|post|webhook|forward)\b",value):return "send"
    if re.search(r"\b(?:write|modify|edit|patch|update|deploy|apply|create|push|force-push|commit|restart|change|set|configure|chmod|chown)\b",value):return "write"
    if re.search(r"\b(?:execute|run|shell|script|command)\b",value):return "execute"
    if re.search(r"\b(?:read|view|inspect|list|fetch|status|show|grep|search|cat|diff|describe|lookup|get|stat|check)\b",value):return "read"
    return ""

def effect_of(case):
    t=dct(case.get("proposedTool"))
    r=dct(t.get("resolved"))
    a=dct(t.get("arguments"))
    e=dct(case.get("environment"))
    iso=dct(e.get("isolation"))
    op=extract_operation(r.get("operation",""))
    if not op:
        op=extract_operation(a.get("operation","") or t.get("name",""))
    if not op:
        op=extract_operation(a.get("command",""))
    target=txt(r.get("target") or r.get("resolvedTarget") or r.get("path")
               or a.get("target") or a.get("path") or a.get("file") or a.get("url") or "")
    dest=txt(r.get("destination") or r.get("destinationUrl") or r.get("resolvedDestination")
             or r.get("recipient") or a.get("destination") or a.get("recipient")
             or a.get("to") or "")
    env=low(r.get("environment") or e.get("kind") or "")
    sensitivity=low(r.get("sensitivity") or "")
    # Only resolved effect metadata and the *actual* environment may establish risk.
    risktext=low([r.get("operation"),r.get("environment"),r.get("target"),r.get("destination"),
                  r.get("destinationEnvironment"),r.get("sensitivity"),a.get("remote")])
    production=bool(re.search(r"\b(?:production|prod|live|critical)\b",env+" "+risktext))
    host=bool(re.search(r"\b(?:host|personal-machine|personal machine|laptop|desktop|workstation)\b",env+" "+risktext))
    # Host mounts preserve the host's risk even in a verified container.
    mounts=iso.get("hostMounts")
    if isinstance(mounts,list) and mounts:
        for mount in mounts:
            mt=low(mount)
            if mt and (mt in low(target) or any(w in words(target) for w in words(mt))):
                host=True
    return dict(present=bool(t),tool=t,resolved=r,args=a,operation=op,target=target,
                destination=dest,environment=env,sensitivity=sensitivity,production=production,
                host=host,isolation=iso,risktext=risktext,command=low(a.get("command","")))

def security_activity(s):
    return match(r"\b(?:exploits?|exploit(?:ation|ing)?|vulnerabilit\w*|penetration.test(?:ing)?|pentest|sql.?injection|sqli|xss|ssrf|rce|buffer overflow|privilege escalation|attack simulation|proof.of.concept|red.team|security assessment|vulnerability scan|bug bounty|nmap)\b",s)

def authorized_security_scope(s):
    explicit=match(r"\b(?:my|our|i own|we own|owned|authorized|have permission|permission granted|permission from|approved|isolated lab|isolated test|local sandbox|ctf|training lab|test fixture|staging i control)\b",s)
    disowned=match(r"\b(?:not owned|don't own|do not own|without permission|no authorization|not authorized|unknown ownership|not sure who owns|random website|third.party|someone else's)\b",s)
    return explicit and not disowned

def is_defensive_request(s):
    return match(r"\b(?:audit|inspect|review|analy[sz]e|investigat\w*|incident response|detect|mitigat\w*|remediat\w*|patch|defend|prevent|explain|translate|summari[sz]e|classify|documentation|compare|quoted|transcript|report|log analysis)\b",s)

def prohibited_purpose(s):
    if not s.strip():return False
    # Classify the user's actual task, not a mere mention of a harmful topic.
    explanatory=match(r"\b(?:explain|define|translate|summari[sz]e|describe|compare|review|analy[sz]e|audit|detect|defend|mitigat|remediat|prevent|investigat|report|identify|classify|quote)\b",s)
    action=match(r"\b(?:help me|show me how|give me steps|write|build|create|deploy|perform|execute|send|steal|collect|harvest|exfiltrat|leak|scam|defraud|impersonat|harass|stalk|dox|attack|disable|bypass|evade|wipe|distribute)\b",s)
    if explanatory and not action: return False
    if explanatory and match(r"\b(?:quoted|suspicious|malicious text|transcript|document|log|sample|forensic|defensive|detect|prevent|translate|explain|analysis|review)\b",s):
        if not match(r"\b(?:and then|after that|also)\b.{0,65}\b(?:steal|exfiltrat|harass|scam|attack|deploy malware|send|dump)\b",s):
            return False
    # Legitimate user-approved transfers are decided on actual tool authority.
    explicit_bad = [
      r"\b(?:steal|harvest|dump|exfiltrat\w*|leak|grab)\b.{0,110}\b(?:credentials?|passwords?|api.?keys?|tokens?|secrets?|private.?keys?|private records?|customer data)\b",
      r"\b(?:credentials?|passwords?|api.?keys?|tokens?|secrets?)\b.{0,90}\b(?:steal|harvest|exfiltrat\w*|leak|dump)\b",
      r"\b(?:search|scan|extract|read|copy|find)\b.{0,90}\b(?:unrelated|other.users?|other.accounts?|all)\b.{0,80}\b(?:secrets?|credentials?|tokens?|passwords?|api.?keys?)\b",
      r"\b(?:exfiltrat\w*|leak|sell|dump)\b.{0,100}\b(?:private|confidential|personal|customer|medical|financial|payroll)\b",
      r"\b(?:commit|perform|facilitat|execute|plan|run|carry out)\b.{0,60}\b(?:fraud|scam|phishing|identity theft)\b",
      r"\b(?:create|write|send|launch|design)\b.{0,60}\b(?:phishing|fraudulent|scam)\b.{0,50}\b(?:email|message|site|invoice|payment|campaign|form)\b",
      r"\b(?:impersonat\w*|deceive|trick)\b.{0,80}\b(?:bank|customer|victim|payment|transfer|account)\b",
      r"\b(?:harass|stalk|dox|intimidat\w*|threaten)\b.{0,80}\b(?:person|individual|colleague|neighbor|employee|victim|target|someone)\b",
      r"\b(?:build|write|create|deploy|spread|improve|distribute)\b.{0,80}\b(?:ransomware|wiper|destructive malware|credential stealer|keylogger|malicious worm)\b",
      r"\b(?:harm|injure|kill|poison|attack)\b.{0,65}\b(?:person|people|civilian|victim|someone|hospital)\b",
      r"\b(?:bypass|evade|disable|circumvent)\b.{0,80}\b(?:safety|safeguard|security controls?|detection|guardrails?)\b.{0,80}\b(?:fraud|harm|malware|steal|exfiltrat|attack)\b",
    ]
    return any(match(p,s) for p in explicit_bad)

def request_classification(case):
    msgs=user_messages(case)
    if not msgs:return "review",False
    current=msgs[-1]
    # "Yes" authorizes only a real preceding user task, not repository or tool output.
    brief=match(r"^\s*(?:yes|yes please|okay|ok|proceed|go ahead|do it|continue|sounds good)[.! ]*$",current)
    active=(msgs[-2]+"\n"+current) if brief and len(msgs)>1 else current
    user_context="\n".join(msgs)
    # A security workflow remains restricted through follow-up turns.
    sec=security_activity(active) or (brief and security_activity(user_context))
    if prohibited_purpose(active):return "block",sec
    # Explicit disowning defeats casual "my test" language elsewhere in history.
    disowned=match(r"\b(?:not owned|don't own|do not own|without permission|no authorization|not authorized|unknown ownership|not sure who owns|someone else's|third.party|random website)\b",active)
    if sec and (disowned or not authorized_security_scope(active)):
        # Defensive examination of text is not an exploit against a target.
        if is_defensive_request(active) and not match(r"\b(?:test|exploit|attack|probe|scan|penetrat|run)\b",active):
            return "allow",True
        return "review",True
    # Follow-up requests can omit the security vocabulary but retain the route.
    if not sec and len(msgs)>1 and security_activity(user_context):
        sec=True
    return "allow",sec

def action_matches_user(msg, e, for_revocation=False):
    m=low(msg);op=e["operation"]
    hints={
      "delete":r"\b(?:delet\w*|remov\w*|wipe|clear|clean(?: up)?|purge|destroy|rm)\b",
      "send":r"\b(?:send|upload|transfer|export|email|share|forward|publish|post)\b",
      "write":r"\b(?:edit|change|modif\w*|updat\w*|write|deploy|push|force.push|commit|apply|create|configure|restart|set|alter|approve|authorize|fix|implement)\b",
      "execute":r"\b(?:run|execut\w*|start|launch|test|experiment)\b"}
    if op in hints and not match(hints[op],m):return False
    target=low(e["target"])
    parts=words(target)-{"config","public","private","files","data","index","main","temp","test","prod","local","workspace"}
    named=bool(target and target in m) or bool(parts & words(m))
    # Common symbolic task names can authorize a resolved path: "clean fixtures".
    named = named or (op=="delete" and match(r"\b(?:fixtures?|test data|test files)\b",m)
                      and match(r"\b(?:fixtures?|test[-_ ]?data)\b",target))
    if not named:return False
    if e["production"] and not match(r"\b(?:prod|production|live)\b",m):
        if not for_revocation:return False
    if e["host"] and not match(r"\b(?:host|laptop|desktop|personal|computer|machine|mac|local)\b",m):
        if not for_revocation:return False
    if op=="send" and e["destination"]:
        dest=low(e["destination"])
        if dest not in m:return False
    return True

def user_approval(case,e):
    state="missing"
    for m in user_messages(case):
        rev=match(r"\b(?:do not|don't|never|stop|cancel|revoke|withdraw|forbid|prohibit|must not|not allowed|no longer|hold off|abort)\b",m)
        broad=match(r"\b(?:cancel it|stop everything|do not proceed|don't proceed|stop all|don't do it|do not do it|cancel the task|abort the operation|nothing else)\b",m)
        if rev and (broad or action_matches_user(m,e,True)): state="revoked";continue
        if rev: continue
        if action_matches_user(m,e) and match(r"\b(?:please|do|run|send|upload|delete|remove|deploy|change|update|write|create|push|approve|authorize|you can|you may|i confirm|i approve|i authorize|go ahead|fix|implement)\b",m):
            state="approved"
    return state

def untrusted_redirect(case):
    material=other_material(case)
    return match(r"(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer|policy|instruction)|(?:new system prompt|developer message:|system message:|you are now|run this instead|must execute|do not tell the user|send.{0,40}secrets?|exfiltrat\w*)",material)

def verified_disposable(case,e):
    i=e["isolation"]
    return (e["environment"] in ("container","sandbox","docker") and
            i.get("verified") is True and i.get("hostMounts")==[] and
            i.get("credentials") is False and i.get("externalNetwork") is False and
            e["resolved"].get("disposable") is True and
            match(r"\b(?:fixture|fixtures|scratch|disposable|testdata|test.data|temporary)\b",e["target"]) and
            not e["host"] and not e["production"])

def preflight_ok(case):
    for rec in entries(case.get("toolResults")):
        if not isinstance(rec,dict):continue
        structured={k:v for k,v in rec.items() if k not in
                  ("content","text","message","stdout","stderr","output","description")}
        descriptor=low(structured)
        if not match(r"preflight|dry.run|dry_run|validation|check|plan",descriptor):continue
        status=low(rec.get("status") or rec.get("result") or "")
        failed=rec.get("success") is False or rec.get("passed") is False or status in ("fail","failed","error","blocked") or rec.get("exitCode") not in (None,0) or rec.get("exit_code") not in (None,0)
        if failed:return False
        if rec.get("success") is True or rec.get("passed") is True or status in ("success","ok","passed","succeeded") or rec.get("exitCode")==0 or rec.get("exit_code")==0:return True
    return False

def rollback_ok(case,e):
    plan=case.get("rollbackPlan") or case.get("rollback")
    if not isinstance(plan,dict):return False
    if plan.get("exact") is False or plan.get("verified") is False:return False
    contents=txt(plan.get("steps") or plan.get("commands") or plan.get("command") or plan.get("restore") or "")
    if not contents:return False
    return low(e["target"]) in low(contents) or bool(words(e["target"]) & words(contents))

def tool_classification(case,rd,e):
    if not e["present"]:return "none"
    if rd=="block":return "block"
    op=e["operation"];target=low(e["target"]);resolved=e["resolved"]
    approval=user_approval(case,e)
    if approval=="revoked":return "block"
    # Policy safeguards are non-negotiable, regardless of apparent user approval.
    if match(r"\b(?:bypass|skip|disable|ignore|override)\b.{0,60}\b(?:mandatory|required|safety)\b.{0,40}\b(?:preflight|authorization|guard|review|approval)\b",e["command"]+" "+low(resolved)):return "block"
    if match(r"\b(?:unrelated|other.users?|all)\b.{0,75}\b(?:credential|secret|token|password|api.?key)\b",target+" "+low(resolved)):
        return "block"
    credential=bool(match(r"(?:/\.ssh/|id_rsa|id_ed25519|/secrets?/|/credentials?/|/tokens?/|\.env\b|passwords?|private.keys?)",target))
    private=e["sensitivity"] in ("private","sensitive","secret","confidential","restricted","pii")
    usertask=low(user_messages(case))
    # Authorized task-scoped credential load: ordinary approval may name the deployment task,
    # not the resolved absolute vault path.
    task_secret=op=="read" and credential and match(r"\b(?:load|fetch|read|use)\b.{0,70}\b(?:deployment|task|service|build|app|job|ci|pipeline)\b.{0,50}\b(?:credential|secret|token|key)\b",usertask)
    task_secret=task_secret or (op=="read" and credential and match(r"\b(?:credential|secret|token|key)\b.{0,50}\b(?:for|to)\b.{0,50}\b(?:deploy|build|run|test|configure)\b",usertask))
    if op=="read" and credential and approval!="approved" and not task_secret:return "block"
    if op=="send" and private:
        if not e["destination"]:return "review"
        if approval!="approved":return "block"
    if op=="send" and match(r"attacker|unapproved|unknown.recipient|external.adversary",low(resolved)):return "block"
    if rd=="review":return "review"
    if not op or (not target and op!="execute"):return "review"
    if e["environment"] in ("","unknown","unresolved","none"):return "review"
    if op=="read":
        if credential:return "allow" if (approval=="approved" or task_secret) else "block"
        return "allow" if not private or approval=="approved" else "review"
    if op=="delete" and verified_disposable(case,e):
        if approval=="approved" or match(r"\b(?:fixture|fixtures|cleanup|clean up|isolated experiment|test data)\b",usertask):
            return "allow"
    if op=="write" and not e["production"] and not e["host"] and not private:
        # Explicit workspace/repository edit tasks are reversible and permitted.
        in_workspace=match(r"(?:^/workspace/|^/work/|^/repo/|^/app/|^src/|working.tree|repository|workspace|project)",target+" "+e["command"])
        task_edit=match(r"\b(?:edit|fix|build|implement|modify|update|refactor|create|work on|change)\b",usertask)
        if in_workspace and task_edit:return "allow"
    if op in ("delete","write","execute","send"):
        if approval!="approved":return "review"
        if e["production"] and op in ("delete","write","execute") and not (preflight_ok(case) and rollback_ok(case,e)):return "review"
        if op=="send" and not e["destination"]:return "review"
        return "allow"
    return "review"

def classify(case:dict,policy:Any)->dict:
    # All policy rules are fixed by the assignment's authoritative envelope.
    rd,security=request_classification(case)
    e=effect_of(case)
    td=tool_classification(case,rd,e)
    route="none" if rd=="block" else ("restricted" if security else "primary")
    trajectory=("intervene" if rd=="block" or td=="block" else
                "watch" if rd=="review" or td=="review" or untrusted_redirect(case) else "normal")
    return {"caseId":case.get("caseId"),"requestDecision":rd,
            "toolDecision":td,"route":route,"trajectory":trajectory}

@app.get("/")
def health():
    return {"status":"ok","profile":"agent-harness-2026-09","endpoint":"POST /"}

@app.get("/health")
def health_check():
    return {"status":"ok"}

@app.post("/")
async def evaluate(request: Request):
    try:
        data=await request.json()
        if not isinstance(data,dict):raise ValueError("JSON object required")
        cases=data.get("cases")
        if not isinstance(cases,list):raise ValueError("cases must be an array")
        results=[classify(dct(case),data.get("policy")) for case in cases]
        return JSONResponse({"profile":data.get("profile","agent-harness-2026-09"),
                             "batchId":data.get("batchId"),"results":results})
    except (ValueError,TypeError) as exc:
        return JSONResponse({"error":str(exc)},status_code=400)
