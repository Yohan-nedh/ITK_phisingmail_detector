"""
analyser.py
Analyse complète d'un email pour détecter le phishing
Compatible avec mail_parsing.py
"""

import re
import tldextract
from urllib.parse import urlparse

# === CONFIGURATION LOCALE ===
WHITELIST_DOMAINS = {
    "paypal.com", "paypal.fr",
    "amazon.com", "amazon.fr",
    "banque-populaire.fr", "credit-agricole.fr", "labanquepostale.fr",
    "gmail.com", "outlook.com", "yahoo.com", "orange.fr", "free.fr"
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "immédiatement", "bloqué", "suspendu", "désactivé",
    "cliquez ici", "vérifiez votre compte", "mot de passe", "confidentiel",
    "mise à jour", "sécurité", "paiement", "facture", "problème",
    "action requise", "identifiez-vous", "connexion", "accès"
]

BLACKLIST_DOMAINS = {
    "paypa1.com", "amaz0n-security.com", "gma1l.com",
    "paypal-support.net", "banque-securite.com", "amazon-verification.org"
}

URL_SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".zip", ".rar"}


# === FONCTIONS UTILITAIRES ===
def take_domain(email):
    """Extrait le domaine d'une adresse email."""
    email = email.split()[-1]
    if isinstance(email, str) and "@" in email:
        if email.startswith('<') and email.endswith('>'):
            email = email[1:-1]
        return email.split("@")[-1].strip().lower()
    return ""


def get_tld(domain):
    """Extrait le TLD du domaine"""
    domain = take_domain(domain)
    ext = tldextract.extract(domain)
    return ext.domain + '.' + ext.suffix


def take_url(url):
    """Extrait le domaine d'une URL."""
    try:
        return urlparse(url).netloc.lower()
    except:
        return ""


# === ANALYSES ===
def analyse_headers(headers):
    """Analyse les en-têtes (From, Reply-To, authentification)."""
    score = 0
    issues = []

    # --- Expéditeur ---
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    from_domain = take_domain(from_addr)
    
    if from_addr and reply_to and get_tld(from_addr) != get_tld(reply_to):
        score += 30
        issues.append("Incohérence entre De et Répondre à")

    if get_tld(from_domain) in BLACKLIST_DOMAINS:
        score += 50
        issues.append(f"Domaine connu pour phishing : {from_domain}")
    elif from_domain and get_tld(from_domain) not in WHITELIST_DOMAINS:
        if any(legit in from_domain for legit in ["paypal", "amazon", "banque", "gmail"]): # À revoir, ça va créer trop de faux positifs, le cas de 
            score += 40
            issues.append(f"Domaine falsifié : {from_domain}")
        else:
            score += 20
            issues.append(f"Domaine non reconnu : {from_domain}")

    # --- Authentification (SPF, DKIM, DMARC) ---
    auth = headers.get("authentication_results", {})
    for protocol in ["SPF", "DKIM", "DMARC"]:
        result = auth.get(protocol, "").lower()
        if result == "fail":
            score += 30
            issues.append(f"{protocol} a échoué")
        elif result == "none":
            score += 15
            issues.append(f"{protocol} absent")

    # --- Sujet ---
    subject = headers.get("subject", "").lower()
    if any(word in subject for word in ["urgent", "immédiat", "bloqué", "suspendu"]):
        score += 20
        issues.append("Sujet alarmiste")
    if "compte" in subject and ("bloqué" in subject or "suspendu" in subject):
        score += 25
        issues.append("Phrase typique de phishing dans le sujet")

    return score, issues


def analyse_corps(body):
    """Analyse le texte du corps."""
    score = 0
    issues = []
    text = body.get("text", "").lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            score += 10
            issues.append(f"Mot suspect : « {keyword} »")

    return score, issues


def analyse_liens(body, sender_domain):
    """Analyse les liens (usurpation, raccourcisseur, domaine)."""
    score = 0
    issues = []
    links = body.get("links", [])

    for link in links:
        # Si c'est une URL brute (str), pas un tuple
        if isinstance(link, str):
            url = link
            display_text = url
        else:
            display_text, url = link

        url_domain = take_url(url)

        # Lien usurpé (texte ≠ domaine)
        if display_text.lower() not in url_domain and sender_domain not in url_domain: # Un peu, il faut comparer le display text au domaine seulement si le texte affiché ressemble à un lien
            score += 25
            issues.append(f"Lien usurpé : « {display_text} » → {url_domain}")

        # Domaine différent de l'expéditeur
        if sender_domain and sender_domain not in url_domain:
            score += 20
            issues.append(f"Lien externe : {url_domain}")

        # Raccourcisseur
        if url_domain in URL_SHORTENERS:
            score += 20
            issues.append(f"Raccourcisseur détecté : {url_domain}")

        # Domaine dans la liste noire
        if url_domain in BLACKLIST_DOMAINS:
            score += 50
            issues.append(f"Domaine malveillant : {url_domain}")

    return score, issues


def analyse_pieces_jointes(body):
    """Analyse les pièces jointes."""
    score = 0
    issues = []
    files = body.get("attachments", [])

    for f in files:
        ext = "." + f.split(".")[-1].lower() if "." in f else "" # Ajouter la détection du type MIME, pour les cas où la vraie extension est masquée: malicious.exe.pdf
        if ext in DANGEROUS_EXT:
            score += 50
            issues.append(f"Pièce jointe dangereuse : {f}")

    return score, issues


# === FONCTION PRINCIPALE ===
def detecter_phishing(headers, body):
    """Analyse complète de l'email."""
    total_score = 0
    all_issues = []

    sender_domain = take_domain(headers.get("from", ""))

    # Toutes les analyses
    analyses = [
        analyse_headers(headers),
        analyse_corps(body),
        analyse_liens(body, sender_domain),
        analyse_pieces_jointes(body)
    ]

    for s, i in analyses:
        total_score += s
        all_issues.extend(i)

    total_score = min(total_score, 100)

    if total_score >= 70:
        niveau = "Élevé"
    elif total_score >= 40:
        niveau = "Modéré"
    else:
        niveau = "Faible"

    return {
        "score": total_score,
        "niveau_risque": niveau,
        "problemes": all_issues,
        "recommandations": [
            "Ne cliquez sur aucun lien",
            "Ne téléchargez pas les pièces jointes",
            "Signalez cet email comme spam",
            "Contactez l’expéditeur via un canal officiel"
        ] if total_score >= 50 else []
    }




"""
MODIFS:
- Amélioration de la fonction take_domain pour gérer le cas l'email sera entre < >
- Ajout de la fonction get_tld(), pour détecter les vrais domaines(TLD), dans les cas où il aura des sous domaines. Par ex, si on a: info.microsoft.com.evil.org, ça donnera : evil.org
- 
"""

"""
AUTRES REMARQUES
- La white list, black list, suspicious word ne sont pas assez exhaustives. Ça peut biaiser les résultats. DOnc, on va revoir ça.
- 
"""