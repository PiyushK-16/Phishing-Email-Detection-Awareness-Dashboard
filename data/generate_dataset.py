"""Generate a SYNTHETIC email dataset (fictional domains only). Run: python data/generate_dataset.py"""
import csv, os, random
from email.utils import parseaddr

random.seed(42)
NAMES = ["Alex", "Priya", "Sam", "Jordan", "Mina", "Chris", "Taylor", "Riya", "Jamie", "Noor"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
TOPICS = ["Cloud Basics", "Network Security", "Data Ethics", "Python for Analysts", "Incident Response"]
SHOPS = ["Example Retail", "Sample Mart", "Demo Store"]
BANKS = ["Example Bank", "Sample Credit Union"]
d = lambda: f"{random.randint(1, 28)} {random.choice(MONTHS)}"
n = lambda: random.randint(1000, 99999)


def legit(hard=False):
    k, who = random.randrange(8), random.choice(NAMES)
    dom = random.choice(["example.org", "example.com", "mail.example.net"])
    r = dict(attachment_name="", urls="")
    if hard:  # legitimate but urgent-sounding (tests false positives)
        r.update(sender=f"Example HR <hr@{dom}>", subject="Urgent: Submit your documents today",
                 body=f"Hi {who}, please submit your onboarding documents by {d()} via the HR portal https://hr.{dom}/onboarding. Thanks, HR team (ref {n()})")
        r["urls"] = f"https://hr.{dom}/onboarding"; return r
    if k == 0:
        r.update(sender=f"Example University <registrar@{dom}>", subject=f"Notice: exam schedule update {n()}",
                 body=f"Dear {who}, the {random.choice(TOPICS)} exam is on {d()} at 10:00. Details: https://portal.{dom}/exams. Regards, Registrar")
        r["urls"] = f"https://portal.{dom}/exams"
    elif k == 1:
        r.update(sender=f"Example HR <hr@{dom}>", subject=f"HR update: holiday calendar {n()}",
                 body=f"Hi {who}, the holiday calendar for next quarter is attached. Please review before {d()}.", attachment_name=f"holiday_{n()}.pdf")
    elif k == 2:
        r.update(sender=f"{who} <{who.lower()}@{dom}>", subject=f"Project update #{n()}",
                 body=f"Hi team, the {random.choice(TOPICS)} sprint is on track. Demo on {d()}. Notes: https://wiki.{dom}/notes/{n()}")
        r["urls"] = f"https://wiki.{dom}/notes/{n()}"
    elif k == 3:
        r.update(sender=f"{who} <{who.lower()}@{dom}>", subject=f"Meeting reminder: {random.choice(TOPICS)}",
                 body=f"Reminder: meeting on {d()} at 14:30 in room {random.randint(1, 40)}. Agenda attached.", attachment_name=f"agenda_{n()}.docx")
    elif k == 4:
        shop = random.choice(SHOPS)
        r.update(sender=f"{shop} <orders@{dom}>", subject=f"Your order {n()} has shipped",
                 body=f"Hi {who}, your order {n()} shipped and arrives by {d()}. Track it at https://shop.{dom}/track/{n()}. Thank you for shopping with us.")
        r["urls"] = f"https://shop.{dom}/track/{n()}"
    elif k == 5:
        r.update(sender=f"Example Newsletter <news@{dom}>", subject=f"Monthly newsletter: {random.choice(TOPICS)}",
                 body=f"Hello {who}, this month: new workshops and a student spotlight. Read more at https://news.{dom}/issue/{n()}. Unsubscribe anytime in settings.")
        r["urls"] = f"https://news.{dom}/issue/{n()}"
    elif k == 6:
        r.update(sender=f"Example Accounts <accounts@{dom}>", subject="Your password was changed",
                 body=f"Hi {who}, your password was changed on {d()}. If this was you, no action is needed. Otherwise contact the help desk at the number on our official website.")
    else:
        bank = random.choice(BANKS)
        r.update(sender=f"{bank} <alerts@example-bank.example.com>", subject=f"Monthly statement ready ({n()})",
                 body=f"Hello {who}, your statement for {random.choice(MONTHS)} is ready. Sign in through the official app to view it. We never ask for your password by email.")
    return r


def phish(hard=False):
    k, who = random.randrange(7), random.choice(NAMES)
    ip = f"198.51.100.{random.randint(1, 250)}"
    bad = random.choice([f"http://{ip}/verify-account", f"http://account-check.invalid.test/login?id={n()}",
                         f"https://secure-login.verify.update.example.net/signin/{n()}", f"http://tiny.example/x{n()}",
                         f"http://example-bank.secure-update.example.com/confirm/{n()}"])
    r = dict(urls=bad, attachment_name="")
    if hard:  # polite, no urgency, https (tests false negatives)
        r.update(sender=f"Shared Docs <share@docs-example.example.net>", subject=f"{who} shared a document with you",
                 body=f"Hello {who}, a document is waiting for you. Open it here: https://docs-share.example.net/view/{n()}")
        r["urls"] = f"https://docs-share.example.net/view/{n()}"; return r
    if k == 0:
        r.update(sender=f"Security Alert <security-alert@account-check.invalid.test>", subject="URGENT: Verify Your Account Immediately",
                 body=f"Dear customer, your account will be suspended within 24 hours. Verify your password now: {bad}")
    elif k == 1:
        r.update(sender=f"Billing <billing@invoice-center.example.net>", subject=f"Invoice {n()} overdue",
                 body=f"Dear user, outstanding payment of ${random.randint(100, 9000)} is overdue. See the attached invoice or pay at {bad}",
                 attachment_name=random.choice([f"Invoice_{n()}.pdf.exe", f"Invoice_{n()}.zip", f"Payment_{n()}.js"]))
    elif k == 2:
        r.update(sender="Rewards <promo@prize-winner.example.org>", subject="You have won a free gift!!!",
                 body=f"Congratulations winner! You have won a prize. Claim your reward now, enter your personal details at {bad}")
    elif k == 3:
        r.update(sender="IT Helpdesk <helpdesk@mail-verify.example.net>", subject="Password expires today",
                 body=f"Dear member, your password expires today. Confirm your password immediately to avoid account lock: {bad}")
    elif k == 4:
        r.update(sender="Delivery <track@parcel-update.example.com>", subject=f"Delivery failed for parcel {n()}",
                 body=f"Your parcel could not be delivered. Act now: update your delivery details and card number at {bad}")
    elif k == 5:
        r.update(sender="HR Department <hr-benefits@example-hr.invalid.test>", subject="Action required: confirm your personal information",
                 body=f"Dear employee, please confirm your personal details and bank details today at {bad}", attachment_name=f"Benefits_{n()}.docm")
    else:
        r.update(sender="CEO Office <ceo.office@exec-mail.example.net>", subject="Urgent request",
                 body=f"Hi {who}, I need gift cards immediately for a client. Do not call me, just reply with the codes. Send ASAP.")
        r["urls"] = ""
    return r


def main(total=600):
    rows, seen = [], set()
    while len(rows) < total:
        label = "LEGITIMATE" if len(rows) % 2 == 0 else "PHISHING"
        hard = random.random() < 0.10
        r = legit(hard) if label == "LEGITIMATE" else phish(hard)
        key = (r["sender"], r["subject"], r["body"])
        if key in seen:
            continue
        seen.add(key)
        dom = parseaddr(r["sender"])[1].split("@")[-1]
        rows.append({"email_id": len(rows) + 1, "sender": r["sender"], "sender_domain": dom, "subject": r["subject"],
                     "body": r["body"], "urls": r["urls"], "attachment_name": r["attachment_name"], "label": label})
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_email_dataset.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"Saved {len(rows)} synthetic records to {out}")


if __name__ == "__main__":
    main()
