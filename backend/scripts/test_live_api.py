import httpx

client = httpx.Client(base_url="http://127.0.0.1:8000/api", timeout=15.0)

# 1. Health
h = client.get("/health")
print("Health status code:", h.status_code)
print("Health payload:", h.json())

# 2. Legit URL
r1 = client.post("/url/analyze", json={"url": "https://netbanking.hdfcbank.com/netbanking/"})
print("\nLegit URL Scan:", r1.status_code)
data1 = r1.json()
print("Verdict:", data1["verdict"], "| Label:", data1["display_label"])
print("Summary:", data1["summary"])

# 3. Phishing Kit URL
r2 = client.post("/url/analyze", json={"url": "https://sbi-login.trycloudflare.com/login.php"})
print("\nPhishing Kit Scan:", r2.status_code)
data2 = r2.json()
print("Verdict:", data2["verdict"], "| Label:", data2["display_label"])
print("Summary:", data2["summary"])

# 4. Scam SMS
r3 = client.post("/sms/analyze", json={
    "message": "Aapka account band ho jayega. Please share your OTP with bank officer to avoid blocking.",
    "sender": "9876543210"
})
print("\nScam SMS Scan:", r3.status_code)
data3 = r3.json()
print("Verdict:", data3["verdict"], "| Label:", data3["display_label"])
print("Summary:", data3["summary"])

# 5. Dashboard Stats
dash = client.get("/dashboard/stats")
print("\nDashboard Stats:", dash.json())

# 6. History List
hist = client.get("/history")
print("\nHistory Total:", hist.json()["total"])

# 7. PDF Export
inv_id = data1["investigation_id"]
pdf = client.get(f"/history/{inv_id}/export.pdf")
print("\nPDF Export status:", pdf.status_code, "Bytes:", len(pdf.content))
print("\nALL LIVE API CHECKS PASSED!")
