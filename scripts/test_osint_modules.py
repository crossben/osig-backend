"""
OSINT Modules Test Script

This script tests all OSINT modules to ensure they work correctly.
Run this to verify that each module can gather intelligence successfully.
"""

import sys
from app.osint.email_intel import email_intel
from app.osint.username_intel import username_intel
from app.osint.phone_intel import phone_intel
from app.osint.domain_intel import domain_intel


def print_results(module_name: str, results: list):
    """
    Print results in a readable format.
    
    Args:
        module_name: Name of the module being tested
        results: List of OSINTResult objects
    """
    print(f"\n{'='*60}")
    print(f"{module_name} Results")
    print(f"{'='*60}")
    print(f"Total findings: {len(results)}\n")
    
    for i, result in enumerate(results, 1):
        print(f"{i}. Source: {result.source}")
        print(f"   Type: {result.data_type}")
        print(f"   Confidence: {result.confidence}")
        if result.source_url:
            print(f"   URL: {result.source_url}")
        print(f"   Data: {result.data}")
        print()


def test_email_intel():
    """Test Email Intelligence Module"""
    print("\n" + "="*60)
    print("Testing Email Intelligence Module")
    print("="*60)
    
    # Test with a sample email
    test_email = "test@example.com"
    print(f"\nTarget: {test_email}")
    
    try:
        results = email_intel.run(test_email)
        print_results("Email Intelligence", results)
        return True
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
        return False


def test_username_intel():
    """Test Username Intelligence Module"""
    print("\n" + "="*60)
    print("Testing Username Intelligence Module")
    print("="*60)
    
    # Test with a sample username
    test_username = "github"  # Known to exist on multiple platforms
    print(f"\nTarget: {test_username}")
    
    try:
        results = username_intel.run(test_username)
        print_results("Username Intelligence", results)
        return True
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
        return False


def test_phone_intel():
    """Test Phone Intelligence Module"""
    print("\n" + "="*60)
    print("Testing Phone Intelligence Module")
    print("="*60)
    
    # Test with a sample phone number
    test_phone = "+14155552671"  # Google's example number
    print(f"\nTarget: {test_phone}")
    
    try:
        results = phone_intel.run(test_phone)
        print_results("Phone Intelligence", results)
        return True
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
        return False


def test_domain_intel():
    """Test Domain Intelligence Module"""
    print("\n" + "="*60)
    print("Testing Domain Intelligence Module")
    print("="*60)
    
    # Test with a sample domain
    test_domain = "google.com"
    print(f"\nTarget: {test_domain}")
    
    try:
        results = domain_intel.run(test_domain)
        print_results("Domain Intelligence", results)
        return True
    except Exception as e:
        print(f"❌ Failed: {str(e)}")
        return False


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("OSINT MODULES TEST SUITE")
    print("="*60)
    
    results_summary = {
        "Email Intel": test_email_intel(),
        "Username Intel": test_username_intel(),
        "Phone Intel": test_phone_intel(),
        "Domain Intel": test_domain_intel()
    }
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for module, passed in results_summary.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{module}: {status}")
    
    # Overall result
    all_passed = all(results_summary.values())
    print("\n" + "="*60)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("⚠️  SOME TESTS FAILED")
    print("="*60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
