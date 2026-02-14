"""
Test script for scan endpoints.

This script tests the scan management API endpoints.
"""
import requests
import json

BASE_URL = "http://localhost:8000/api/v1"

def test_scan_endpoints():
    """Test scan endpoints with a registered user."""
    
    print("=" * 60)
    print("OSIG Backend - Scan Endpoints Test")
    print("=" * 60)
    
    # 1. Register a test user
    print("\n1. Registering test user...")
    register_data = {
        "email": "scantest1@osig.com",
        "username": "scantest",
        "password": "TestPass123",
        "full_name": "Scan Tester"
    }
    
    
    # Check if server is running
    try:
        health_check = requests.get("http://localhost:8000/health", timeout=2)
        if health_check.status_code != 200:
            print("✗ Server is not healthy")
            return
        print("✓ Server is running")
    except requests.exceptions.RequestException as e:
        print(f"✗ Cannot connect to server at http://localhost:8000")
        print(f"  Make sure uvicorn is running: uvicorn app.main:app --port 8000")
        return
    
    try:
        response = requests.post(f"{BASE_URL}/auth/register", json=register_data)
        if response.status_code == 201:
            auth_data = response.json()
            token = auth_data["access_token"]
            print(f"✓ User registered: {auth_data['user']['email']}")
            print(f"✓ Token: {token[:20]}...")
        else:
            # User might already exist, try login
            print(f"User already exists (status {response.status_code}), logging in...")
            login_data = {
                "email": register_data["email"],
                "password": register_data["password"]
            }
            response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
            
            if response.status_code != 200:
                print(f"✗ Login failed with status {response.status_code}")
                print(f"  Response: {response.text}")
                return
            
            auth_data = response.json()
            token = auth_data["access_token"]
            print(f"✓ Logged in: {auth_data['user']['email']}")
    except Exception as e:
        print(f"✗ Auth failed: {e}")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Check quota status
    print("\n2. Checking quota status...")
    try:
        response = requests.get(f"{BASE_URL}/scans/quota/status", headers=headers)
        quota = response.json()
        print(f"✓ Plan: {quota['plan']}")
        print(f"✓ Daily limit: {quota['daily_limit']}")
        print(f"✓ Used today: {quota['used_today']}")
        print(f"✓ Remaining: {quota['remaining']}")
    except Exception as e:
        print(f"✗ Quota check failed: {e}")
    
    # 3. Create a scan
    print("\n3. Creating email scan...")
    scan_data = {
        "target_type": "email",
        "target_value": "target@example.com",
        "scan_type": "quick",
        "disclaimer_accepted": True
    }
    
    try:
        response = requests.post(f"{BASE_URL}/scans", json=scan_data, headers=headers)
        if response.status_code == 201:
            scan = response.json()
            scan_id = scan["id"]
            print(f"✓ Scan created: {scan_id}")
            print(f"  - Target: {scan['target_value']}")
            print(f"  - Status: {scan['status']}")
            print(f"  - Progress: {scan['progress']}%")
        else:
            print(f"✗ Scan creation failed: {response.status_code}")
            print(f"  {response.text}")
            return
    except Exception as e:
        print(f"✗ Scan creation failed: {e}")
        return
    
    # 4. List scans
    print("\n4. Listing scans...")
    try:
        response = requests.get(f"{BASE_URL}/scans?page=1&page_size=10", headers=headers)
        scans_list = response.json()
        print(f"✓ Total scans: {scans_list['total']}")
        print(f"✓ Page: {scans_list['page']}/{scans_list['total_pages']}")
        for s in scans_list['scans']:
            print(f"  - {s['target_value']} ({s['status']})")
    except Exception as e:
        print(f"✗ List scans failed: {e}")
    
    # 5. Get scan details
    print("\n5. Getting scan details...")
    try:
        response = requests.get(f"{BASE_URL}/scans/{scan_id}", headers=headers)
        scan_detail = response.json()
        print(f"✓ Scan ID: {scan_detail['id']}")
        print(f"  - Type: {scan_detail['target_type']}")
        print(f"  - Value: {scan_detail['target_value']}")
        print(f"  - Status: {scan_detail['status']}")
    except Exception as e:
        print(f"✗ Get scan failed: {e}")
    
    # 6. Test validation errors
    print("\n6. Testing validation...")
    
    # Invalid email
    invalid_scan = {
        "target_type": "email",
        "target_value": "not-an-email",
        "scan_type": "quick",
        "disclaimer_accepted": True
    }
    response = requests.post(f"{BASE_URL}/scans", json=invalid_scan, headers=headers)
    if response.status_code == 422:
        print("✓ Email validation working")
    else:
        print("✗ Email validation failed")
    
    # Disclaimer not accepted
    invalid_scan2 = {
        "target_type": "email",
        "target_value": "test@example.com",
        "scan_type": "quick",
        "disclaimer_accepted": False
    }
    response = requests.post(f"{BASE_URL}/scans", json=invalid_scan2, headers=headers)
    if response.status_code == 422:
        print("✓ Disclaimer validation working")
    else:
        print("✗ Disclaimer validation failed")
    
    print("\n" + "=" * 60)
    print("✓ All tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    test_scan_endpoints()
