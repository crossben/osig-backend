"""
"My footprint": the user's own identifiers (Identity), watched by ordinary
watches; findings turned into plain-language to-dos (ActionItem); an exposure
score (0-100, higher = safer); the weekly digest; household summaries and
opt-out / deletion request letters.

Rules worth knowing:
- Action keys are stable (flag + identity), so an item the user completed or
  dismissed is never recreated; open items whose flag vanished from the latest
  run are auto-resolved (done, resolved_at).
- Score = 100 - weights of open items (request letters excluded), floor 0.
- Each recompute whose score changed writes a `footprint_score` audit row:
  that is the trend and the digest's "vs last week".
"""
import hashlib
import hmac
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.models.investigation import Watch
from app.models.personal import ActionItem, HouseholdMember, Identity
from app.models.platform import MailOutbox
from app.models.result import Result
from app.models.scan import Scan, ScanType, TargetType
from app.models.user import User
from app.services import audit_service, mail_service, plan_limits, push_service, risk_service
from app.services.diff_service import finished

logger = logging.getLogger(__name__)

SCORE_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DIGEST_KIND = "weekly_digest"
MANY_SITES = 8  # a handle on this many platforms => review old accounts

PASSWORD_PAGES = {
    "linkedin": "https://www.linkedin.com/mypreferences/d/change-password",
    "adobe": "https://account.adobe.com/security",
    "dropbox": "https://www.dropbox.com/account/security",
    "canva": "https://www.canva.com/settings/login-and-security",
    "twitter": "https://x.com/settings/password",
    "facebook": "https://accountscenter.facebook.com/password_and_security",
    "instagram": "https://accountscenter.instagram.com/password_and_security",
    "yahoo": "https://login.yahoo.com/account/security",
    "tumblr": "https://www.tumblr.com/settings/account",
    "deezer": "https://www.deezer.com/account/password",
    "dailymotion": "https://www.dailymotion.com/settings/security",
    "myfitnesspal": "https://www.myfitnesspal.com/account/change_password",
    "trello": "https://id.atlassian.com/manage-profile/security",
    "wattpad": "https://www.wattpad.com/settings",
    "zynga": "https://www.zynga.com/support",
}


# ── identities ──────────────────────────────────────────────────────────

def domain_code(ident: Identity) -> str:
    """Stable per identity, so the UI can show it again without storing it."""
    return hmac.new(settings.SECRET_KEY.encode(), f"domain:{ident.id}".encode(), hashlib.sha256).hexdigest()[:24]


def watchable(ident: Identity) -> bool:
    return ident.kind == "username" or ident.verified_at is not None


def ensure_watch(db: Session, user: User, ident: Identity) -> Optional[Watch]:
    """Create the identity's watch (not counted in the plan's `watches` limit)."""
    if ident.watch_id or not watchable(ident):
        return None
    interval = 168 if _plan(user) == "free" else 24
    interval = max(interval, plan_limits.limit(db, user, "min_watch_interval_hours") or 24)
    w = Watch(user_id=user.id, target_type=TargetType(ident.kind), target_value=ident.value,
              scan_type=ScanType.QUICK, interval_hours=interval, next_run_at=datetime.utcnow())
    db.add(w)
    db.flush()
    ident.watch_id = w.id
    _first_run(db, user, w)
    return w


def _first_run(db: Session, user: User, w: Watch) -> None:
    """Check a new identity right away instead of waiting for the beat (quota still applies)."""
    from datetime import timedelta
    from fastapi import HTTPException
    from app.schemas.scan import CreateScanRequest
    from app.services.scan_service import ScanService
    try:
        ScanService.create_scan(db, user, CreateScanRequest(
            target_type=w.target_type, target_value=w.target_value, scan_type=w.scan_type,
            disclaimer_accepted=True), watch_id=w.id)
    except HTTPException:  # out of daily scans: the beat picks it up later
        return
    now = datetime.utcnow()
    w.last_run_at = now
    w.next_run_at = now + timedelta(hours=w.interval_hours)


def delete_identity(db: Session, ident: Identity) -> None:
    watch = db.query(Watch).filter(Watch.id == ident.watch_id).first() if ident.watch_id else None
    db.query(ActionItem).filter(ActionItem.identity_id == ident.id).delete(synchronize_session=False)
    db.delete(ident)
    db.flush()
    if watch:
        db.delete(watch)
    db.commit()


def identity_watch_ids(db: Session, user_id) -> set:
    return {row[0] for row in db.query(Identity.watch_id).filter(
        Identity.user_id == user_id, Identity.watch_id.isnot(None)).all()}


def _plan(user: User) -> str:
    return user.plan.value if hasattr(user.plan, "value") else str(user.plan)


# ── flags -> actions ────────────────────────────────────────────────────

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")[:60] or "x"


def _password_page(site: str) -> Optional[str]:
    s = str(site).lower()
    return next((url for name, url in PASSWORD_PAGES.items() if name in s), None)


def _act(key, severity, title, detail, link=None) -> dict:
    return {"key": key[:200], "severity": severity, "title": title[:300], "detail": detail, "link": link}


def actions_for_scan(ident: Identity, scan: Scan, results: List[Result], lang: str = "en") -> List[dict]:
    """Findings -> to-dos in the user's language (English or French)."""
    fr = lang == "fr"

    def L(en: str, fr_text: str) -> str:
        return fr_text if fr else en

    flags = risk_service.assess(scan, results)["flags"]
    v, iid = ident.value, ident.id
    out: List[dict] = []
    for f in flags:
        fid, sev, ev = f["id"], f["severity"], f.get("evidence") or []
        if fid == "breach:passwords":
            for site in [e for e in ev if e]:
                out.append(_act(f"breach:{_slug(site)}:{iid}", "high",
                                L(f"Change your password for {site} and anywhere you reused it",
                                  f"Changez votre mot de passe {site} et partout où vous l’avez réutilisé"),
                                L(f"{site} leaked passwords in a data breach that includes {v}. Change that password, "
                                  "then every other account where you used the same one, and turn on two-factor sign-in.",
                                  f"{site} a laissé fuiter des mots de passe dans une fuite qui inclut {v}. Changez ce mot "
                                  "de passe, puis celui de tous les comptes où vous utilisiez le même, et activez la "
                                  "connexion en deux étapes."),
                                _password_page(site)))
        elif fid == "breach:data":
            leaks = ", ".join(map(str, ev[:6]))
            out.append(_act(f"breach:data:{iid}", "medium",
                            L(f"Watch out for targeted phishing aimed at {v}",
                              f"Méfiez-vous des arnaques ciblées visant {v}"),
                            L(f"Personal data linked to this address leaked in: {leaks}. Scammers use it to sound "
                              "legitimate: be wary of messages quoting your details.",
                              f"Des données personnelles liées à cette adresse ont fuité dans : {leaks}. Les arnaqueurs "
                              "s’en servent pour paraître crédibles : méfiez-vous des messages qui citent vos informations.")))
        elif fid == "infostealer:device":
            out.append(_act(f"infostealer:{iid}", sev,
                            L(f"A device that used {v} was infected by password-stealing malware",
                              f"Un appareil utilisant {v} a été infecté par un logiciel voleur de mots de passe"),
                            L("Scan your computers and phones with an up-to-date antivirus, then change your passwords "
                              "from a clean device (email first), sign out of all sessions and turn on two-factor sign-in.",
                              "Analysez vos ordinateurs et téléphones avec un antivirus à jour, puis changez vos mots de "
                              "passe depuis un appareil sain (l’e-mail d’abord), déconnectez toutes les sessions et "
                              "activez la connexion en deux étapes.")))
        elif fid == "infostealer:domain":
            out.append(_act(f"infostealer:domain:{iid}", sev,
                            L(f"Logins for {v} sites were stolen by malware",
                              f"Des identifiants des sites de {v} ont été volés par un logiciel malveillant"),
                            L(f["description"] + " Reset the affected accounts and require two-factor sign-in.",
                              "Des appareils infectés ont exposé des identifiants de vos sites. Réinitialisez les comptes "
                              "concernés et imposez la connexion en deux étapes.")))
        elif fid == "mentions:leak_terms":
            pages = " ".join(str(e) for e in ev[:5])
            out.append(_act(f"mentions:leak:{iid}", "medium",
                            L(f"Check public pages that mention {v} next to “password” or “leak”",
                              f"Vérifiez les pages publiques qui citent {v} près de « mot de passe » ou « fuite »"),
                            L("Open these pages and ask the site to remove your details if they are exposed: " + pages,
                              "Ouvrez ces pages et demandez au site de retirer vos informations si elles sont exposées : "
                              + pages)))
        elif fid in ("mail:no_dmarc", "mail:dmarc_none", "mail:no_spf"):
            steps = {
                "mail:no_dmarc": L("Your domain has no DMARC record. Add one (start with p=quarantine) so others "
                                   "can't send mail as you.",
                                   "Votre domaine n’a pas d’enregistrement DMARC. Ajoutez-en un (commencez par "
                                   "p=quarantine) pour empêcher d’autres d’envoyer des e-mails en votre nom."),
                "mail:dmarc_none": L("Your DMARC policy only monitors. Move it from p=none to p=quarantine or p=reject.",
                                     "Votre politique DMARC ne fait que surveiller. Passez de p=none à p=quarantine "
                                     "ou p=reject."),
                "mail:no_spf": L("Your domain has no SPF record. Publish one listing the servers allowed to send "
                                 "your mail.",
                                 "Votre domaine n’a pas d’enregistrement SPF. Publiez-en un qui liste les serveurs "
                                 "autorisés à envoyer vos e-mails."),
            }[fid]
            out.append(_act(f"{fid}:{iid}", sev, L(f"Protect {v} from email spoofing",
                                                   f"Protégez {v} contre l’usurpation d’e-mails"), steps,
                            "https://www.cloudflare.com/learning/dns/dns-records/dns-dmarc-record/"))
        elif fid == "exposure:accounts":
            sites = ", ".join(map(str, ev[:6]))
            out.append(_act(f"accounts:{iid}", "low",
                            L(f"Review old accounts registered with {v}", f"Faites le tri des anciens comptes liés à {v}"),
                            L(f"{v} is registered on many services ({sites}...). Close the ones you no longer use "
                              "and change passwords on the rest.",
                              f"{v} est inscrit sur de nombreux services ({sites}…). Fermez ceux que vous n’utilisez "
                              "plus et changez le mot de passe des autres.")))
        elif fid == "pgp:unverified":
            out.append(_act(f"pgp:{iid}", "low",
                            L(f"Check the PGP keys published for {v}", f"Vérifiez les clés PGP publiées pour {v}"),
                            L("Someone published unverified PGP keys for this address. If one isn't yours, tell "
                              "your contacts which fingerprint is.",
                              "Des clés PGP non vérifiées ont été publiées pour cette adresse. Si l’une n’est pas à "
                              "vous, indiquez à vos contacts quelle empreinte est la bonne.")))
        elif fid in ("email:disposable", "email:no_mx", "phone:invalid", "phone:voip", "identity:mixed"):
            continue  # facts about the identifier, nothing for its owner to fix
        else:
            out.append(_act(f"{fid}:{iid}", sev, f"{v}: {f['description']}"[:300], f["description"]))

    by_type: Dict[str, list] = {}
    for r in results:
        by_type.setdefault(r.data_type, []).append(r)
    profiles = [r for r in by_type.get("social_profile", []) if (r.data or {}).get("exists")]
    if ident.kind == "username" and len(profiles) >= MANY_SITES:
        sites = sorted({str(r.data.get("platform")) for r in profiles})
        listed = ", ".join(sites[:8])
        out.append(_act(f"username:sites:{iid}", "low",
                        L(f"Review old accounts using the handle {v}",
                          f"Faites le tri des anciens comptes au pseudo {v}"),
                        L(f"The handle {v} appears on {len(sites)} sites ({listed}). Delete accounts you no longer "
                          "use: forgotten accounts get taken over.",
                          f"Le pseudo {v} apparaît sur {len(sites)} sites ({listed}). Supprimez les comptes que vous "
                          "n’utilisez plus : les comptes oubliés se font pirater.")))
    mentions = by_type.get("dork_result", [])
    if ident.kind in ("email", "phone") and mentions:
        n = len(mentions)
        what_en = "email" if ident.kind == "email" else "phone number"
        what_fr = "adresse e-mail" if ident.kind == "email" else "numéro"
        out.append(_act(f"mentions:public:{iid}", "low",
                        L(f"Your {what_en} {v} appears on {n} public page" + ("s" if n != 1 else ""),
                          f"Votre {what_fr} {v} apparaît sur {n} page" + ("s" if n != 1 else "") + " publique"
                          + ("s" if n != 1 else "")),
                        L("Ask those sites to remove it if you didn't publish it: it feeds spam and scam lists. "
                          "OSIG can write the removal request for you.",
                          "Demandez à ces sites de le retirer si vous ne l’avez pas publié : il alimente les listes de "
                          "spam et d’arnaques. OSIG peut rédiger la demande pour vous.")))
    return out


# ── recompute ───────────────────────────────────────────────────────────

def latest_finished_scan(db: Session, ident: Identity) -> Optional[Scan]:
    if not ident.watch_id:
        return None
    for scan in db.query(Scan).filter(Scan.watch_id == ident.watch_id).order_by(Scan.created_at.desc()).limit(10):
        if finished(scan):
            return scan
    return None


def compute_score(db: Session, user_id) -> int:
    items = db.query(ActionItem).filter(ActionItem.user_id == user_id, ActionItem.status == "open").all()
    return max(0, 100 - sum(SCORE_WEIGHT.get(a.severity, 0) for a in items if not a.key.startswith("request:")))


def recompute(db: Session, user: User, notify: bool = True) -> dict:
    current: Dict[str, dict] = {}
    checked = set()
    for ident in db.query(Identity).filter(Identity.user_id == user.id).all():
        scan = latest_finished_scan(db, ident)
        if not scan:
            continue
        checked.add(ident.id)
        results = db.query(Result).filter(Result.scan_id == scan.id).all()
        for spec in actions_for_scan(ident, scan, results, getattr(user, "language", "en") or "en"):
            current[spec["key"]] = {**spec, "identity_id": ident.id}

    existing = {a.key: a for a in db.query(ActionItem).filter(ActionItem.user_id == user.id).all()}
    created, resolved = [], 0
    for key, spec in current.items():
        item = existing.get(key)
        if item:
            if item.status == "open":  # refresh wording; done/dismissed ones stay as the user left them
                item.severity, item.title, item.detail, item.link = (spec["severity"], spec["title"],
                                                                     spec["detail"], spec["link"])
            continue
        item = ActionItem(user_id=user.id, **spec)
        db.add(item)
        created.append(item)
    now = datetime.utcnow()
    for key, item in existing.items():
        if (item.status == "open" and item.identity_id in checked and key not in current
                and not key.startswith("request:")):
            item.status, item.resolved_at = "done", now
            resolved += 1
    db.flush()

    previous = user.exposure_score
    user.exposure_score = compute_score(db, user.id)
    user.score_updated_at = now
    db.commit()
    if previous != user.exposure_score:
        audit_service.record(db, "footprint_score", user_id=user.id, target=str(user.exposure_score))

    urgent = [a for a in created if a.severity in ("critical", "high")]
    if notify and urgent:
        push_service.send(db, user.id, f"OSIG: {len(urgent)} new urgent action{'s' if len(urgent) != 1 else ''}",
                          urgent[0].title, "#/footprint")
    return {"score": user.exposure_score, "created": len(created), "resolved": resolved}


def on_watch_run(db: Session, scan_id: str) -> Optional[dict]:
    """After a watch run finishes: recompute when the watch belongs to an identity."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or not scan.watch_id or not finished(scan):
        return None
    ident = db.query(Identity).filter(Identity.watch_id == scan.watch_id).first()
    user = db.query(User).filter(User.id == ident.user_id).first() if ident else None
    return recompute(db, user) if user else None


def score_history(db: Session, user_id, since: Optional[datetime] = None) -> List[AuditLog]:
    q = db.query(AuditLog).filter(AuditLog.user_id == user_id, AuditLog.action == "footprint_score")
    if since:
        q = q.filter(AuditLog.created_at >= since)
    return q.order_by(AuditLog.created_at).all()


def trend(db: Session, user_id, weeks: int = 12) -> List[dict]:
    """Last score of each ISO week, for the last `weeks` weeks that had one."""
    points: Dict[str, dict] = {}
    for row in score_history(db, user_id, datetime.utcnow() - timedelta(weeks=weeks)):
        try:
            value = int(row.target)
        except (TypeError, ValueError):
            continue
        y, w, _ = row.created_at.isocalendar()
        points[f"{y}-{w:02d}"] = {"date": row.created_at.date().isoformat(), "score": value}
    return list(points.values())[-weeks:]


def score_before(db: Session, user_id, when: datetime) -> Optional[int]:
    row = (db.query(AuditLog).filter(AuditLog.user_id == user_id, AuditLog.action == "footprint_score",
                                     AuditLog.created_at <= when)
           .order_by(AuditLog.created_at.desc()).first())
    try:
        return int(row.target) if row else None
    except (TypeError, ValueError):
        return None


# ── weekly digest ───────────────────────────────────────────────────────

TIPS_EN = [
    "Use a password manager: one strong, unique password per site is the single best protection.",
    "Turn on two-factor sign-in for your email first: it is the key to every other account.",
    "Prefer an authenticator app or a security key over SMS codes for two-factor sign-in.",
    "Your bank will never ask for a code it just sent you. Anyone who does is a scammer.",
    "Before clicking a link in a message, check it with OSIG's scam checker.",
    "Update your phone and computer as soon as updates arrive: most attacks use old flaws.",
    "Mobile money: never share your PIN, even with someone claiming to be from the operator.",
    "Check which apps can sign in with your Google or Facebook account, and remove the ones you don't use.",
    "Use a different email address for shopping and newsletters than for your bank.",
    "Lock your phone with a PIN of at least 6 digits, and enable remote wipe.",
    "Be careful with public Wi-Fi: avoid signing in to sensitive accounts on it.",
    "Set your social profiles to private and remove your phone number from public view.",
    "Back up your important files to a separate place: it's your best defense against ransomware.",
    "A message that rushes you (\"your account will be closed today\") is a classic scam sign.",
    "Don't install apps from links sent by message: use the official app store.",
    "Set up a SIM PIN and ask your operator about protection against SIM swap.",
    "Close accounts you no longer use: forgotten accounts get taken over.",
    "Check your email's recovery phone and address: an attacker who changes them owns the account.",
    "Fake job and investment offers promising easy money are among the most common scams.",
    "If a friend asks for money by message, call them on their usual number to check.",
]
TIPS_FR = [
    "Utilisez un gestionnaire de mots de passe : un mot de passe fort et unique par site est la meilleure protection.",
    "Activez la double authentification sur votre e-mail en premier : c'est la clé de tous vos autres comptes.",
    "Préférez une application d'authentification ou une clé de sécurité aux codes SMS.",
    "Votre banque ne vous demandera jamais un code qu'elle vient de vous envoyer. Celui qui le fait est un escroc.",
    "Avant de cliquer sur un lien reçu par message, vérifiez-le avec le détecteur d'arnaques d'OSIG.",
    "Installez les mises à jour de votre téléphone et de votre ordinateur dès qu'elles arrivent.",
    "Mobile money : ne partagez jamais votre code PIN, même avec quelqu'un qui se dit de l'opérateur.",
    "Vérifiez quelles applications peuvent se connecter avec votre compte Google ou Facebook et retirez les inutiles.",
    "Utilisez une adresse e-mail différente pour les achats et les newsletters que pour votre banque.",
    "Verrouillez votre téléphone avec un code d'au moins 6 chiffres et activez l'effacement à distance.",
    "Méfiez-vous du Wi-Fi public : évitez d'y ouvrir vos comptes sensibles.",
    "Passez vos profils sociaux en privé et masquez votre numéro de téléphone.",
    "Sauvegardez vos fichiers importants ailleurs : c'est la meilleure défense contre les rançongiciels.",
    "Un message qui vous presse (« votre compte sera fermé aujourd'hui ») est un signe classique d'arnaque.",
    "N'installez pas d'application depuis un lien reçu par message : passez par le magasin officiel.",
    "Activez le code PIN de votre carte SIM et renseignez-vous auprès de votre opérateur contre le SIM swap.",
    "Fermez les comptes que vous n'utilisez plus : les comptes oubliés se font pirater.",
    "Vérifiez le téléphone et l'adresse de secours de votre e-mail : qui les change prend le compte.",
    "Les fausses offres d'emploi ou d'investissement promettant de l'argent facile sont parmi les arnaques les plus courantes.",
    "Si un ami vous demande de l'argent par message, appelez-le sur son numéro habituel pour vérifier.",
]


def tip_for(now: datetime, language: str = "en") -> str:
    tips = TIPS_FR if language == "fr" else TIPS_EN
    return tips[now.isocalendar()[1] % len(tips)]


def _top_open(db: Session, user_id, n: int) -> List[ActionItem]:
    items = db.query(ActionItem).filter(ActionItem.user_id == user_id, ActionItem.status == "open").all()
    items = [a for a in items if not a.key.startswith("request:")]
    return sorted(items, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.created_at))[:n]


def _household_lines(db: Session, owner: User, since: datetime, fr: bool) -> List[str]:
    lines = []
    members = db.query(HouseholdMember).filter(HouseholdMember.owner_id == owner.id,
                                               HouseholdMember.status == "active").all()
    for m in members:
        member = db.query(User).filter(User.id == m.member_user_id).first()
        if not member:
            continue
        new = db.query(ActionItem).filter(ActionItem.user_id == member.id, ActionItem.created_at >= since,
                                          ~ActionItem.key.startswith("request:")).all()
        breaches = sum(1 for a in new if a.key.startswith("breach:"))
        name = member.full_name or member.email
        if breaches:
            lines.append(f"{name}: {breaches} " + ("nouvelle(s) fuite(s)" if fr else
                                                   f"new breach{'es' if breaches != 1 else ''}"))
        elif new:
            lines.append(f"{name}: {len(new)} " + ("nouvelle(s) alerte(s)" if fr else
                                                   f"new finding{'s' if len(new) != 1 else ''}"))
        else:
            lines.append(f"{name}: " + ("rien de nouveau" if fr else "nothing new"))
    return lines


def build_digest(db: Session, user: User, now: Optional[datetime] = None) -> tuple:
    now = now or datetime.utcnow()
    fr = user.language == "fr"
    since = now - timedelta(days=7)
    score = user.exposure_score
    before = score_before(db, user.id, since)
    new_items = db.query(ActionItem).filter(ActionItem.user_id == user.id, ActionItem.created_at >= since,
                                            ~ActionItem.key.startswith("request:")).count()
    open_count = db.query(ActionItem).filter(ActionItem.user_id == user.id, ActionItem.status == "open",
                                             ~ActionItem.key.startswith("request:")).count()
    top = _top_open(db, user.id, 3)
    link = mail_service.link("/footprint")

    if fr:
        subject = "Votre semaine sur OSIG"
        score_line = (f"Score de protection : {score}/100" if score is not None else "Score de protection : pas encore calculé")
    else:
        subject = "Your week on OSIG"
        score_line = (f"Protection score: {score}/100" if score is not None else "Protection score: not computed yet")
    if score is not None and before is not None and before != score:
        delta = score - before
        score_line += f" ({'+' if delta > 0 else ''}{delta} " + ("depuis la semaine dernière)" if fr else "since last week)")
    lines = [score_line,
             (f"Nouvelles découvertes cette semaine : {new_items}" if fr else f"New findings this week: {new_items}"),
             (f"Actions à faire : {open_count}" if fr else f"Open actions: {open_count}")]
    if top:
        lines.append("")
        lines.append("À faire en priorité :" if fr else "Top actions:")
        lines += [f"- [{a.severity}] {a.title}" for a in top]
    household = _household_lines(db, user, since, fr)
    if household:
        lines.append("")
        lines.append("Votre foyer :" if fr else "Your household:")
        lines += [f"- {h}" for h in household]
    lines += ["", ("Conseil de la semaine : " if fr else "Tip of the week: ") + tip_for(now, user.language), "",
              ("Voir votre empreinte : " if fr else "See your footprint: ") + link, "",
              ("Pour ne plus recevoir ce résumé : " if fr else "To stop this weekly email: ")
              + mail_service.link("/profile")]
    greeting = (f"Bonjour {user.full_name or ''},".replace(" ,", ",") if fr
                else f"Hi {user.full_name or ''},".replace(" ,", ","))
    return subject, greeting + "\n\n" + "\n".join(lines) + "\n"


def send_weekly_digests(db: Session, now: Optional[datetime] = None) -> int:
    now = now or datetime.utcnow()
    sent = 0
    owners = {row[0] for row in db.query(HouseholdMember.owner_id).filter(HouseholdMember.status == "active")}
    with_identities = {row[0] for row in db.query(Identity.user_id).distinct()}
    for user in db.query(User).filter(User.digest_enabled.is_(True), User.is_active.is_(True)).all():
        if user.id not in with_identities and user.id not in owners:
            continue
        recent = db.query(MailOutbox).filter(MailOutbox.to == user.email, MailOutbox.kind == DIGEST_KIND,
                                             MailOutbox.created_at >= now - timedelta(days=6)).first()
        if recent:
            continue
        try:
            subject, body = build_digest(db, user, now)
            mail_service.send(db, user.email, subject, body, kind=DIGEST_KIND)
            sent += 1
        except Exception as e:
            db.rollback()
            logger.error(f"Digest for user {user.id} failed: {e}", exc_info=True)
    return sent


# ── household ───────────────────────────────────────────────────────────

def member_summary(db: Session, member_user_id) -> dict:
    """What an owner may see about a member: score and counts, never identity values."""
    member = db.query(User).filter(User.id == member_user_id).first()
    if not member:
        return {"score": None, "open_actions": 0, "identities": 0}
    return {
        "name": member.full_name or member.username,
        "score": member.exposure_score,
        "open_actions": db.query(ActionItem).filter(ActionItem.user_id == member.id, ActionItem.status == "open",
                                                    ~ActionItem.key.startswith("request:")).count(),
        "identities": db.query(Identity).filter(Identity.user_id == member.id).count(),
    }


# ── opt-out / deletion request letters ──────────────────────────────────

TEMPLATES = {
    "gdpr_erasure": {
        "title": "Erasure request (GDPR Art. 17)", "law": "GDPR Article 17",
        "applies_to": "Companies in the EU/EEA, or serving people there",
        "en": ("Request to erase my personal data (GDPR Article 17)",
               "Dear {company} Data Protection Officer,\n\nUnder Article 17 of the General Data Protection Regulation, "
               "I ask you to erase without undue delay all personal data you hold about me, including data linked to:\n"
               "{identifiers}\n\nPlease also tell any third parties you shared it with (Article 19) and confirm in "
               "writing once done. You must answer within one month (Article 12(3)).\n\nRegards,\n{name}\n{email}\n{date}\n"),
        "fr": ("Demande d'effacement de mes données personnelles (RGPD, article 17)",
               "Madame, Monsieur le Délégué à la protection des données de {company},\n\nEn application de l'article 17 "
               "du Règlement général sur la protection des données, je vous demande d'effacer dans les meilleurs délais "
               "toutes les données personnelles me concernant, notamment celles liées à :\n{identifiers}\n\nMerci d'en "
               "informer les destinataires à qui vous les avez communiquées (article 19) et de me confirmer "
               "l'effacement par écrit. Vous disposez d'un mois pour répondre (article 12.3).\n\n"
               "Cordialement,\n{name}\n{email}\n{date}\n"),
    },
    "gdpr_access": {
        "title": "Access request (GDPR Art. 15)", "law": "GDPR Article 15",
        "applies_to": "Companies in the EU/EEA, or serving people there",
        "en": ("Subject access request (GDPR Article 15)",
               "Dear {company} Data Protection Officer,\n\nUnder Article 15 of the GDPR, please send me a copy of all "
               "personal data you hold about me, including data linked to:\n{identifiers}\n\nPlease include the purposes "
               "of processing, the recipients, how long you keep it and where you got it. You must answer within one "
               "month.\n\nRegards,\n{name}\n{email}\n{date}\n"),
        "fr": ("Demande d'accès à mes données (RGPD, article 15)",
               "Madame, Monsieur le Délégué à la protection des données de {company},\n\nEn application de l'article 15 "
               "du RGPD, je vous demande une copie de toutes les données personnelles me concernant, notamment celles "
               "liées à :\n{identifiers}\n\nMerci d'indiquer les finalités du traitement, les destinataires, la durée de "
               "conservation et la source des données. Vous disposez d'un mois pour répondre.\n\n"
               "Cordialement,\n{name}\n{email}\n{date}\n"),
    },
    "senegal_cdp": {
        "title": "Deletion request (Senegal, law 2008-12)", "law": "Loi n° 2008-12 du 25 janvier 2008 (CDP)",
        "applies_to": "Companies processing data in Senegal",
        "en": ("Request to delete my personal data (Senegal law 2008-12)",
               "Dear {company},\n\nUnder law no. 2008-12 of 25 January 2008 on the protection of personal data "
               "(articles 68 and 69: rights of objection, rectification and deletion), I ask you to delete all personal "
               "data you hold about me, including data linked to:\n{identifiers}\n\nPlease confirm in writing once done. "
               "Without an answer I may refer the matter to the Commission de Protection des Données Personnelles "
               "(CDP).\n\nRegards,\n{name}\n{email}\n{date}\n"),
        "fr": ("Demande de suppression de mes données personnelles (loi n° 2008-12)",
               "Madame, Monsieur,\n\nEn application de la loi n° 2008-12 du 25 janvier 2008 sur la protection des "
               "données à caractère personnel (articles 68 et 69 : droits d'opposition, de rectification et de "
               "suppression), je demande à {company} de supprimer toutes les données personnelles me concernant, "
               "notamment celles liées à :\n{identifiers}\n\nMerci de me confirmer la suppression par écrit. À défaut "
               "de réponse, je saisirai la Commission de Protection des Données Personnelles (CDP).\n\n"
               "Cordialement,\n{name}\n{email}\n{date}\n"),
    },
    "broker_optout": {
        "title": "Data broker / people-search opt-out", "law": "Generic (no specific law)",
        "applies_to": "People-search sites, data brokers, directories",
        "en": ("Opt-out request: remove my personal information",
               "Hello {company} team,\n\nI found my personal information on your service and I do not consent to its "
               "publication or sale. Please remove every listing and record linked to:\n{identifiers}\n\nand stop "
               "collecting, selling or sharing my data. Please confirm once done.\n\nThank you,\n{name}\n{email}\n{date}\n"),
        "fr": ("Demande de retrait de mes informations personnelles",
               "Bonjour,\n\nJ'ai trouvé mes informations personnelles sur le service de {company} et je ne consens "
               "pas à leur publication ni à leur vente. Merci de retirer toutes les fiches et données liées à :\n"
               "{identifiers}\n\net de cesser de collecter, vendre ou partager mes données. Merci de me confirmer le "
               "retrait.\n\nCordialement,\n{name}\n{email}\n{date}\n"),
    },
}


def letter(template_id: str, company: str, user: User, identities: List[Identity]) -> dict:
    t = TEMPLATES[template_id]
    lang = "fr" if user.language == "fr" else "en"
    subject, body = t[lang]
    values = [f"- {i.kind}: {i.value}" for i in identities] or [f"- email: {user.email}"]
    body = body.format(company=company, identifiers="\n".join(values), name=user.full_name or user.username,
                       email=user.email, date=datetime.utcnow().strftime("%Y-%m-%d"))
    return {"subject": subject, "body": body}
