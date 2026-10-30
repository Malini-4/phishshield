"""Generate synthetic SMS dataset for scam language classification."""
from __future__ import annotations

import csv
import os
import random
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data" / "sms_training"
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = DATA_DIR / "sms_dataset.csv"

random.seed(42)

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Bank of Baroda", "Canara Bank", "Union Bank"]
AMOUNTS = ["499", "1,200", "2,499", "5,000", "8,950", "12,450", "25,000", "48,500", "75,000", "1,00,000", "2,50,000"]
SCAM_LINKS = [
    "http://bit.ly/3x8yz", "https://sbi-kyc-verify.top", "http://update-pan-aadhaar.live",
    "https://tinyurl.com/fast-loan-app", "http://cutt.ly/refund77", "https://hdfc-net.club",
    "http://electricity-bills-officer.site", "https://yono-sbi-portal.xyz/login",
    "http://trai-support-verify.online", "https://uidai-aadhaar-link.tech",
    "https://t.me/parttimejob_earn", "http://cbi-cybercell-notice.site",
]
OFFICIAL_LINKS = [
    "https://sbi.co.in", "https://hdfcbank.com", "https://icicibank.com",
    "https://amazon.in", "https://flipkart.com", "https://irctc.co.in", "https://incometax.gov.in"
]
PHONES = ["9823456781", "9811223344", "7890123456", "9988776655", "8765432109", "9123456780", "9012345678"]
UPIS = ["refund.desk@upi", "officer.pay@okaxis", "support@ybl", "merchant@paytm", "claims@okhdfcbank"]
DEADLINES = ["within 24 hours", "tonight 9:30 PM", "today immediately", "within 2 hours", "by tomorrow"]
ACCOUNTS = ["XX4812", "XX9021", "XX1104", "XX5678", "XX3389", "XX7712"]
OTPS = ["492019", "831920", "104928", "672381", "902184", "382910"]
TIMES = ["10 mins", "5 minutes", "15 mins", "10 minutes"]
ORDERS = ["OD9283748291", "402-9102-129", "AMZ-991823", "FKT-338291", "BD-882910"]
PNRS = ["2849201928", "8291029384", "4920192831", "6718291029"]
TRAINS = ["12951 Mumbai Rajdhani", "12002 Shatabdi Exp", "22691 Bangalore Rajdhani", "12301 Howrah Rajdhani"]
NAMES = ["Ramesh", "Priya", "Rahul", "Amit", "Sneha", "Vikram", "Anjali", "Suresh"]

SCAM_TEMPLATES = [
    # KYC
    ("Dear {bank} customer, your account {account} KYC is incomplete. Update your KYC immediately at {link} to avoid suspension.", "en", "kyc", "scam_kyc_1"),
    ("Urgent: Your {bank} netbanking is blocked due to pending KYC. Visit {link} to complete PAN verification within {deadline}.", "en", "kyc", "scam_kyc_2"),
    ("Dear customer, your PAN card is not linked to account {account}. Submit aadhaar at {link} within {deadline} or services terminated.", "en", "kyc", "scam_kyc_3"),
    ("Complete your KYC verification today at {link} otherwise your ATM card and account {account} will be deactivated.", "en", "kyc", "scam_kyc_4"),
    ("Dear customer, KYC is required for {bank} account {account}. Click {link} to renew KYC online.", "en", "kyc", "scam_kyc_5"),
    ("Your {bank} debit card has been suspended. Verify your PAN and KYC at {link} to reactivate.", "en", "kyc", "scam_kyc_6"),
    
    # Credential theft
    ("Dear {bank} user, your credit card {account} is blocked. Please share your OTP with customer support at {phone} to unblock.", "en", "credential_theft", "scam_cred_1"),
    ("{bank} security alert: Unauthorized transaction of Rs {amount} detected on card {account}. Reply with OTP to cancel.", "en", "credential_theft", "scam_cred_2"),
    ("Your card {account} reward points worth Rs {amount} will expire today. Submit your card details and MPIN at {link} to redeem.", "en", "credential_theft", "scam_cred_3"),
    ("Customer support: Verify your netbanking password and OTP at {link} to restore services immediately.", "en", "credential_theft", "scam_cred_4"),
    ("Dear user, suspicious login attempt on {bank} mobile app. Enter your credentials and OTP at {link} to secure account.", "en", "credential_theft", "scam_cred_5"),

    # Electricity
    ("Dear consumer, your electricity bill of Rs {amount} is unpaid. Power supply will be disconnected {deadline}. Contact electricity officer at {phone} immediately.", "en", "electricity", "scam_elec_1"),
    ("Bijli bill alert: Your power will be disconnected at {deadline} from sub-station. Call electricity officer on {phone} to clear bill.", "en", "electricity", "scam_elec_2"),
    ("Electricity board notification: Pay pending bill of Rs {amount} at {link} or electricity line will be cut off tonight.", "en", "electricity", "scam_elec_3"),

    # Parcel / customs
    ("Your courier package with tracking {order} is on hold at customs due to unpaid fee of Rs {amount}. Pay now at {link} to release.", "en", "delivery_fee", "scam_parcel_1"),
    ("Delivery failed: Address incomplete for package {order}. Update your delivery address and pay Rs 25 redelivery fee at {link}.", "en", "delivery_fee", "scam_parcel_2"),
    ("India Post alert: Your parcel {order} is pending at customs. Clear duty fee of Rs {amount} at {link} within {deadline}.", "en", "delivery_fee", "scam_parcel_3"),

    # Cashback / refund
    ("Congratulations! You have received a cashback of Rs {amount} from PhonePe reward program. Claim your reward into bank via {link}.", "en", "cashback", "scam_cash_1"),
    ("Dear user, Rs {amount} refund is pending approval from merchant. Accept refund into your UPI ID via {link}.", "en", "cashback", "scam_cash_2"),
    ("Paytm cashback offer: You won Rs {amount} scratch card reward. Click {link} to transfer amount to your bank account.", "en", "cashback", "scam_cash_3"),
    ("Paid by mistake! I have sent Rs {amount} to your UPI account by error. Please send it back to {upi} immediately.", "en", "wrong_payment", "scam_wrongpay_1"),
    ("Dear sir, transferred Rs {amount} to your number by mistake. Please refund it back to UPI {upi} kindly.", "en", "wrong_payment", "scam_wrongpay_2"),

    # Work from home
    ("Part time job offer: Earn Rs {amount} daily by liking YouTube videos and rating hotels on Google. Join Telegram group {link}.", "en", "job", "scam_job_1"),
    ("Work from home opportunity! Simple typing and review tasks. Daily payment Rs 2500-5000 directly to UPI. Contact on WhatsApp {phone}.", "en", "job", "scam_job_2"),
    ("Amazon part-time hiring: Earn Rs {amount} weekly from home. No experience needed. Join Telegram channel {link} to start today.", "en", "job", "scam_job_3"),

    # Instant loan
    ("Congratulations! Pre-approved personal loan of Rs {amount} sanctioned with 0% interest for 6 months. Download app {link} to disburse in 5 mins.", "en", "loan", "scam_loan_1"),
    ("Instant cash loan approved for Rs {amount}! No CIBIL check, no documentation. Click {link} to apply now.", "en", "loan", "scam_loan_2"),

    # Lottery / KBC
    ("Dear customer, your mobile number has won Rs 25 Lakhs in Kaun Banega Crorepati lucky draw! Call KBC manager on {phone} to claim.", "en", "lottery", "scam_lottery_1"),
    ("Mega Lottery: You are selected as winner of Rs {amount} cash prize in lucky contest. Contact claims officer at {phone}.", "en", "lottery", "scam_lottery_2"),

    # SIM / TRAI block
    ("TRAI notice: Your mobile number will be blocked within 2 hours due to illegal activity and abusive messaging. Contact customer desk at {phone}.", "en", "sim_block", "scam_sim_1"),
    ("Telecom alert: Multiple complaints lodged against your number. Outgoing and incoming calls will stop in {deadline}. Call {phone} to resolve.", "en", "sim_block", "scam_sim_2"),

    # Digital arrest / police
    ("CBI Crime Branch: A warrant has been issued against you for money laundering and illegal parcel smuggling. You are under digital arrest. Call officer at {phone} immediately.", "en", "digital_arrest", "scam_arrest_1"),
    ("Delhi Police Cyber Cell: Your Aadhaar was used in illegal bank accounts for money laundering. Appear before court or call cyber crime officer at {phone}.", "en", "digital_arrest", "scam_arrest_2"),
    ("Customs Department notice: Contraband drugs intercepted under your name at airport. Money laundering case registered. Digital arrest initiated. Contact customs officer at {phone}.", "en", "digital_arrest", "scam_arrest_3"),

    # Income tax refund
    ("Income Tax Department: Tax refund of Rs {amount} has been approved for AY 2026-27. Update your bank account details at {link} to credit.", "en", "tax_refund", "scam_tax_1"),
    ("IT Department alert: Refund notice for PAN. An amount of Rs {amount} is waiting. Verify your account at {link} within {deadline}.", "en", "tax_refund", "scam_tax_2"),

    # Investment / crypto
    ("Guaranteed crypto trading returns! Invest Rs 1,000 and earn Rs {amount} in 24 hours with AI auto-trader. Join VIP group {link}.", "en", "investment", "scam_invest_1"),
    ("Stock market insider tips: 500% profit guaranteed on IPO allocations. Register with our registered broker at {link}.", "en", "investment", "scam_invest_2"),

    # Fake bank APK
    ("Dear {bank} customer, install mandatory new security patch APK from {link} to protect your account against fraudulent transactions.", "en", "fake_apk", "scam_apk_1"),
    ("{bank} Mobile Banking App update: Download and install updated YONO APK from {link} to continue transactions.", "en", "fake_apk", "scam_apk_2"),

    # Aadhaar suspension
    ("UIDAI notification: Your Aadhaar card has been suspended due to biometric mismatch. Visit {link} to upload documents and reactivate.", "en", "aadhaar", "scam_aadhaar_1"),

    # Hinglish & Devanagari scams
    ("Aapka {bank} khata band ho jayega. Turant {link} par click kare aur KYC update kare nahi to account freeze hoga.", "hinglish", "kyc", "scam_hinglish_1"),
    ("Aapka bijli connection aaj raat {deadline} cut kar diya jayega. Turant officer se baat kare {phone}.", "hinglish", "electricity", "scam_hinglish_2"),
    ("Aapko Rs {amount} ka lottery laga hai. Claim karne ke liye WhatsApp kare {phone}.", "hinglish", "lottery", "scam_hinglish_3"),
    ("Galti se paise bhej diye! Maine Rs {amount} aapke a/c me bhej diya hai, kripya {upi} par vapas bhej de.", "hinglish", "wrong_payment", "scam_hinglish_4"),
    ("आपका बैंक खाता 24 घंटे में ब्लॉक कर दिया जाएगा। तुरंत केवाईसी अपडेट करें {link}।", "hi", "kyc", "scam_hi_1"),
    ("प्रिय उपभोक्ता, आपका बिजली बिल बकाया है। आज रात बिजली काट दी जाएगी। संपर्क करें {phone}।", "hi", "electricity", "scam_hi_2"),
    ("सीबीआई साइबर क्राइम: आपके खिलाफ मनी लॉन्ड्रिंग और डिजिटल अरेस्ट वारंट जारी हुआ है। तुरंत संपर्क करें {phone}।", "hi", "digital_arrest", "scam_hi_3"),
]

GENUINE_TEMPLATES = [
    # OTP with do not share
    ("{otp} is your secret OTP for login to {bank} netbanking. Do not share this OTP with anyone, including bank staff. Valid for {time}.", "en", "otp", "gen_otp_1"),
    ("Your one time password (OTP) for transaction of Rs {amount} on card {account} is {otp}. Never share OTP or PIN with anyone.", "en", "otp", "gen_otp_2"),
    ("OTP for UPI registration is {otp}. Do not share this code with anyone. {bank} never calls asking for OTP.", "en", "otp", "gen_otp_3"),
    ("{otp} is the OTP to verify your mobile number on Amazon. Do not disclose this password to anyone.", "en", "otp", "gen_otp_4"),
    ("Your login OTP for Flipkart is {otp}. Valid for {time}. Do not share with anyone.", "en", "otp", "gen_otp_5"),

    # Debit / credit / UPI alerts
    ("Your a/c {account} has been debited by Rs {amount} on 28-Oct-26 via UPI reference {order}. Avl bal: Rs 42,910. - {bank}", "en", "transaction", "gen_txn_1"),
    ("Rs {amount} credited to your account {account} on 29-Oct-26 by UPI/{upi}. Current balance: Rs 15,300. - {bank}", "en", "transaction", "gen_txn_2"),
    ("Sent Rs {amount} from {bank} a/c {account} to {upi} on 29-Oct-26. UPI Ref: 429102918291.", "en", "transaction", "gen_txn_3"),
    ("Your card {account} was used for Rs {amount} at Reliance Retail on 27-Oct-26. Available limit: Rs 75,000.", "en", "transaction", "gen_txn_4"),
    ("A/C {account} debited for Rs {amount} towards ATM cash withdrawal on 26-Oct-26. Available balance Rs 28,400. - {bank}", "en", "transaction", "gen_txn_5"),

    # Card alerts
    ("Transaction alert: An amount of Rs {amount} was charged on your credit card ending {account} at Starbucks. If not done by you, SMS BLOCK to 56767.", "en", "card_alert", "gen_card_1"),
    ("Monthly statement for card {account} generated. Total due: Rs {amount}. Due date: 15-Nov-26. Pay via official {bank} mobile app.", "en", "card_alert", "gen_card_2"),

    # Delivery updates
    ("Your package with tracking number {order} from Amazon is out for delivery with our associate {name}. Expected by 7 PM.", "en", "delivery", "gen_del_1"),
    ("Flipkart order {order} has been delivered successfully. Thank you for shopping with us.", "en", "delivery", "gen_del_2"),
    ("BlueDart shipment {order} arrived at destination hub. Courier will contact you on delivery.", "en", "delivery", "gen_del_3"),
    ("Swiggy: Your order from Biryani Blues is on the way! Delivery partner {name} is arriving shortly.", "en", "delivery", "gen_del_4"),

    # Bill reminders
    ("Dear customer, bill for your Airtel postpaid mobile is Rs {amount}. Due date: 05-Nov-26. Pay safely through Airtel Thanks app.", "en", "bill", "gen_bill_1"),
    ("Your Tata Power electricity bill of Rs {amount} for consumer number {account} is due on 10-Nov-26. Pay via consumer portal or official app.", "en", "bill", "gen_bill_2"),
    ("Jio Fiber bill of Rs {amount} for account {account} is generated. Due date is 08-Nov-26. Pay via MyJio app.", "en", "bill", "gen_bill_3"),

    # Hard negatives: Real KYC notices (branch visit / verified)
    ("Dear customer, as per RBI guidelines, periodic KYC update is due for your {bank} account. Please visit your home branch with original KYC documents.", "en", "kyc_genuine", "gen_kyc_1"),
    ("Your {bank} KYC details have been verified successfully. No further action is required from your side.", "en", "kyc_genuine", "gen_kyc_2"),
    ("Dear customer, periodic re-KYC can be completed by visiting your nearest {bank} branch with PAN and Aadhaar.", "en", "kyc_genuine", "gen_kyc_3"),
    ("Your Aadhaar authentication for {bank} account {account} was successful on 25-Oct-26.", "en", "kyc_genuine", "gen_kyc_4"),

    # Recharge / appointment / train
    ("Recharge of Rs {amount} successful for Jio number {account}. Plan benefits: 1.5GB/day for 28 days. Enjoy unlimited 5G data.", "en", "recharge", "gen_rech_1"),
    ("Your train ticket for PNR {pnr}, Train {train} is confirmed in Coach B3 Berth 41. Charting status: Confirmed.", "en", "travel", "gen_travel_1"),
    ("Appointment reminder: Your consultation with Dr. Sharma is scheduled for tomorrow at 11:30 AM at Apollo Clinic.", "en", "service", "gen_serv_1"),

    # Official promo
    ("Celebrate Diwali with 10% instant discount on {bank} credit cards at Vijay Sales. T&C apply. Visit {official_link} for details.", "en", "promo", "gen_promo_1"),
    ("Earn 5X reward points on dining spends this weekend with your {bank} privilege card. Terms apply. View details at {official_link}.", "en", "promo", "gen_promo_2"),

    # Personal messages
    ("Hey, are we still meeting for lunch today? Let me know what time works for you.", "en", "personal", "gen_pers_1"),
    ("Please send me the notes from yesterday's class when you get a chance. Thanks!", "en", "personal", "gen_pers_2"),
    ("Reached home safely. Thanks for hosting dinner tonight, had a great time!", "en", "personal", "gen_pers_3"),
    ("Can you please call me back once you are free? Need to discuss project work.", "en", "personal", "gen_pers_4"),

    # Hinglish genuine
    ("Bhai, maine Rs {amount} GPay kar diye hain. Check kar lena aur batana.", "hinglish", "personal", "gen_hinglish_1"),
    ("Aapka {bank} account balance Rs {amount} hai. Surakshit banking ke liye apna PIN kisi se share na kare.", "hinglish", "banking", "gen_hinglish_2"),
    ("Order deliver ho gaya hai. Rating dene ke liye app open kare.", "hinglish", "delivery", "gen_hinglish_3"),
]


def apply_noise(text: str) -> str:
    """Apply shorthand, case variation, and slight noise evenly across classes."""
    words = text.split(" ")
    noisy_words = []
    for w in words:
        wl = w.lower()
        r = random.random()
        if r < 0.15:
            if wl == "your":
                w = "ur" if random.random() < 0.7 else "yr"
            elif wl == "you":
                w = "u"
            elif wl == "please":
                w = "pls" if random.random() < 0.6 else "plz"
            elif wl == "account":
                w = "a/c" if random.random() < 0.6 else "acc"
            elif wl == "transaction":
                w = "txn"
            elif wl == "blocked":
                w = "blkd"
            elif wl == "update":
                w = "updt"
        noisy_words.append(w)

    res = " ".join(noisy_words)

    # Occasional case variations
    r_case = random.random()
    if r_case < 0.08:
        res = res.upper()
    elif r_case < 0.15:
        res = res.lower()

    # Occasional missing period at the end
    if random.random() < 0.25 and res.endswith("."):
        res = res[:-1]

    return res


def generate_rows() -> list[dict]:
    rows = []
    
    # Generate ~1150 scam rows
    target_scam = 1150
    per_scam = target_scam // len(SCAM_TEMPLATES) + 1
    for template, lang, cat, tid in SCAM_TEMPLATES:
        for _ in range(per_scam):
            msg = template.format(
                bank=random.choice(BANKS),
                amount=random.choice(AMOUNTS),
                link=random.choice(SCAM_LINKS),
                phone=random.choice(PHONES),
                upi=random.choice(UPIS),
                deadline=random.choice(DEADLINES),
                account=random.choice(ACCOUNTS),
                order=random.choice(ORDERS),
            )
            msg = apply_noise(msg)
            rows.append({
                "text": msg,
                "label": 1,
                "lang": lang,
                "category": cat,
                "template_id": tid,
                "source": "synthetic_template",
            })

    # Generate ~1150 genuine rows
    target_genuine = 1150
    per_gen = target_genuine // len(GENUINE_TEMPLATES) + 1
    for template, lang, cat, tid in GENUINE_TEMPLATES:
        for _ in range(per_gen):
            msg = template.format(
                bank=random.choice(BANKS),
                amount=random.choice(AMOUNTS),
                official_link=random.choice(OFFICIAL_LINKS),
                phone=random.choice(PHONES),
                upi=random.choice(UPIS),
                account=random.choice(ACCOUNTS),
                otp=random.choice(OTPS),
                time=random.choice(TIMES),
                order=random.choice(ORDERS),
                pnr=random.choice(PNRS),
                train=random.choice(TRAINS),
                name=random.choice(NAMES),
            )
            msg = apply_noise(msg)
            rows.append({
                "text": msg,
                "label": 0,
                "lang": lang,
                "category": cat,
                "template_id": tid,
                "source": "synthetic_template",
            })

    random.shuffle(rows)
    return rows


def main():
    rows = generate_rows()
    print(f"Generated {len(rows)} rows (scam: {sum(1 for r in rows if r['label'] == 1)}, genuine: {sum(1 for r in rows if r['label'] == 0)}).")
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "lang", "category", "template_id", "source"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved dataset to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
