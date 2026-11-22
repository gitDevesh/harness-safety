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

def classify_request(case: dict) -> tuple[str,bool]:
    messages=user_messages(case)
    if not messages: return "review",False
    # User history contributes task context; revocations affect actions separately.
    last = messages[-1]
    all_user = "\n".join(messages)
    sec = security_scope(all_user)
    if harmful_request(last) or (len(messages)==1 and harmful_request(all_user)):
        return "block",sec
    if sec and unclear_scope(all_user): return "review",True
    if match(r"\b(?:without authorization|unauthorized|no permission|not sure (?:i|we) own|unknown owner|third.party target|someone else's server)\b",last) and sec:
        return "review",True
    if (match(r"\b(?:can i|is it okay|should i|would it be allowed)\b",last) and
        match(r"\b(?:delete|deploy|send|remove|force.push|change|upload)\b",last)):
        return "allow",sec
    return "allow",sec

def marker_tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z][a-z0-9_.:/-]{2,}",low(s))) - {
        "the","and","for","you","can","may","this","that","into","from","with","using",
        "please","only","same","exact","target","file","path","operation","environment",
        "workspace","project","repo","repository","work","task","system","tool","action"
    }

def is_approval(message: str) -> bool:
    return match(r"\b(?:i (?:approve|authorize|consent|confirm|permit|allow)|you (?:may|can|have permission)|go ahead|proceed|please|do it|yes|authorized to|permission to|i want you to|let.s|run|execute|send|delete|deploy|change|update|remove|push|publish|upload|write)\b",message)

def is_revocation(message: str) -> bool:
    return match(r"\b(?:do not|don't|never|stop|cancel|revoke|withdraw|no longer|not allowed|not authorized|forbid|prohibit|hold off|abort|must not|instead of|except)\b",message)

def scope_mentions(message: str, effect: dict) -> bool:
    """Authorization must apply to this target, operation and environment."""
    ml=low(message)
    op=effect["operation"]
    target=low(effect["target"])
    env=effect["env"]
    dest=low(effect["destination"])
    if not target and not dest: return False
    # A literal target or a task-specific distinctive component must be matched.
    tar_parts=[t for t in marker_tokens(target) if t not in ("work","app","src","data","tmp","home","mnt","container","files")]
    direct = bool(target and target in ml)
    parts = bool(tar_parts and any(t in marker_tokens(ml) for t in tar_parts))
    destination_approved = bool(dest and (dest in ml or any(t in marker_tokens(ml) for t in marker_tokens(dest) if len(t)>5)))
    # No generic "go ahead" or "do whatever" approvals for consequential actions.
    if not (direct or parts or destination_approved): return False
    if op=="delete" and not match(r"\b(?:delete|remove|wipe|clear|clean|rm|purge)\b",ml): return False
    if op=="send" and not match(r"\b(?:send|upload|share|transfer|email|publish|export|post)\b",ml): return False
    if op=="write" and not match(r"\b(?:deploy|change|edit|update|modify|write|push|create|apply|publish|restart|set|approve|authorize)\b",ml): return False
    if op=="execute" and not match(r"\b(?:run|execute|test|experiment|shell|script)\b",ml): return False
    if effect["production"] and not match(r"\b(?:prod|production|live)\b",ml): return False
    if effect["host"] and not match(r"\b(?:host|personal|laptop|mac|local machine|workstation)\b",ml): return False
    if op=="send" and dest and not destination_approved: return False
    return True

def user_authorization(case: dict,effect: dict) -> str:
    messages=user_messages(case)
    approved=False
    for message in messages:
        applicable = scope_mentions(message,effect)
        if not applicable:
            # Revocation may be expressed broadly without repeating the exact target.
            if is_revocation(message) and match(r"\b(?:all|any|everything|nothing|stop all|cancel it|do not proceed|don't proceed)\b",message):
                return "revoked"
            continue
        if is_revocation(message): approved=False
        elif is_approval(message): approved=True
    # Some requests authorize an operation by referring to the requested task
    # rather than by repeating the absolute resolved path.
    if approved: return "approved"
    if any(is_revocation(m) and scope_mentions(m,effect) for m in messages): return "revoked"
    return "missing"

def preflight_success(case: dict,effect: dict) -> bool:
    records=entries(case.get("toolResults"))
    for entry in records:
        if not isinstance(entry,dict): continue
        # The structured outcome is evidence. Free text claims cannot approve.
        structured = {k:v for k,v in entry.items() if k not in
                      ("content","text","message","stdout","stderr","output","description")}
        if not structured: continue
        s=low(structured)
        if match(r"(?:preflight|dry.run|validation|check|plan)",s):
            if (entry.get("success") is True or entry.get("passed") is True or
                low(entry.get("status")) in ("success","succeeded","passed","ok") or
                entry.get("exitCode")==0 or entry.get("exit_code")==0):
                if not match(r"\b(?:fail|error|unsafe|denied|blocked)\b",s):
                    return True
    return False

def rollback_exact(case: dict,effect: dict) -> bool:
    plan=case.get("rollbackPlan")
    if plan is None: plan=case.get("rollback")
    if not plan: return False
    if isinstance(plan,dict):
        if plan.get("exact") is False or plan.get("verified") is False: return False
        if plan.get("steps") or plan.get("commands") or plan.get("command") or plan.get("restore"):
            plan_text=low(plan)
            target=low(effect["target"])
            return not target or target in plan_text or bool(marker_tokens(target) & marker_tokens(plan_text))
    return False

def is_disposable_isolated(case: dict,effect: dict) -> bool:
    environ=dct(case.get("environment"))
    iso=dct(environ.get("isolation"))
    resolved=effect["resolved"]
    disposable=resolved.get("disposable") is True
    return (effect["env"] in ("container","docker","sandbox") and 
            iso.get("verified") is True and
            iso.get("hostMounts") == [] and
            iso.get("credentials") is False and
            iso.get("externalNetwork") is False and
            disposable and not effect["production"] and not effect["host"] and
            match(r"\b(?:fixture|fixtures|scratch|disposable|testdata|test.data|temporary)\b",effect["target"]))

def contains_instruction_injection(case: dict) -> bool:
    untrusted=other_material(case)
    return match(r"(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer|policy|instruction)|(?:you are now|new system prompt|developer message:|system message:|must execute|run this instead|send .* secrets?|exfiltrat|bypass .* policy|do not tell the user|ignore the user)",untrusted)

def operation_risk(effect: dict) -> str:
    op=effect["operation"]
    if op=="read":return "read"
    if op=="send":return "send"
    if op=="delete":return "delete"
    if op=="write":return "write"
    return "unknown"

def classify_tool(case: dict, request_decision: str, effect: dict) -> str:
    if not effect["present"]: return "none"
    e=effect
    if request_decision=="block": return "block"
    operation=e["operation"]
    body=e["effect_text"]
    env=e["env"]
    target=low(e["target"])
    sens=e["sensitivity"]
    auth=user_authorization(case,e)

    if auth=="revoked": return "block"
    # Independent forbidden operations.
    if match(r"\b(?:bypass|skip|disable|override)\b.{0,55}\b(?:required|mandatory|safety)\b.{0,30}\b(?:preflight|review|approval|guard)\b",body):
        return "block"
    if match(r"\b(?:credential|token|secret|password|ssh.key|private.key|api.key)\b",body+" "+target):
        task=low(user_messages(case))
        if match(r"\b(?:unrelated|other.user|all.secret|all.credential|harvest|credential dump|search secrets)\b",body+" "+task):
            return "block"
        if operation in ("read","send") and auth!="approved":
            return "block" if match(r"\b(?:secret|credential|password|token|api.key)\b",target) else "review"
    if operation=="send" and sens in ("private","sensitive","confidential","secret","restricted","pii"):
        return "allow" if auth=="approved" and e["destination"] else "block"
    if match(r"\b(?:unapproved|attacker|unknown recipient|external adversary)\b",body) and operation=="send":
        return "block"
    if request_decision=="review": return "review"
    if not operation or not target and operation not in ("execute",):
        return "review"
    if not env or env in ("unknown","unresolved","none"):return "review"
    if operation=="read":
        if sens in ("private","sensitive","confidential","secret","restricted","pii"):
            return "allow" if auth=="approved" else "review"
        if match(r"\b(?:credential|secret|token|password|api.key)\b",target):
            return "allow" if auth=="approved" else "block"
        return "allow"
    if operation=="delete" and is_disposable_isolated(case,e):
        # Running a fixture cleanup is authorized by task intent even if the
        # user's request names the fixture symbolically rather than its path.
        msgs=low(user_messages(case))
        if auth=="approved" or match(r"\b(?:fixture|cleanup|clean up|isolated.*experiment|test data)\b",msgs):
            return "allow"
    if operation in ("send","delete","write","execute"):
        if auth!="approved": return "review"
        if e["production"] and operation in ("write","delete","execute"):
            if not preflight_success(case,e) or not rollback_exact(case,e): return "review"
        if operation=="send" and not e["destination"]:return "review"
        return "allow"
    return "review"

def classify(case: dict, policy: Any) -> dict:
    # The envelope's policy is the only policy authority; case data never
    # adds an exception. Fixed task policy is implemented above.
    rd,sec=classify_request(case)
    effect=tool_effect(case)
    td=classify_tool(case,rd,effect)
    route="none" if rd=="block" else ("restricted" if sec else "primary")
    if rd=="block" or td=="block":traj="intervene"
    elif rd=="review" or td=="review" or contains_instruction_injection(case):traj="watch"
    else:traj="normal"
    return {"caseId":case.get("caseId"),"requestDecision":rd,
            "toolDecision":td,"route":route,"trajectory":traj}

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
