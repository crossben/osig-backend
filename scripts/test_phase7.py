import asyncio
import os
from app.osint.domain_intel import domain_intel
from app.osint.email_intel import email_intel

def test_phase7():
    print("Testing Spacy & Rapidfuzz & aiodns on microsoft.com")
    try:
        domain_results = domain_intel.run("microsoft.com", deep=True)
        for r in domain_results:
            if r.data_type == "webpage_info":
                print("--- AI Scraper Results ---")
                print("Title:", r.data.get("title"))
                print("NLP Entities:", r.data.get("nlp_entities"))
                print("Phishing Analysis:", r.data.get("phishing_analysis"))
            elif r.data_type == "dns_record":
                print(f"Found DNS {r.data.get('record_type')} records:", r.data.get('count'))
    except Exception as e:
        print("Domain test failed:", e)

    print("\nTesting h8mail on test@example.com")
    try:
        email_results = email_intel.run("test@example.com", deep=True)
        for r in email_results:
            if r.data_type == "breach":
                print("--- h8mail Leak Results ---")
                print("Leaks found:", r.data.get("leaks_found"))
    except Exception as e:
        print("Email test failed:", e)

if __name__ == "__main__":
    test_phase7()
