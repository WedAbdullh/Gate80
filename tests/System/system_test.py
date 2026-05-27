import pytest
import requests
import threading

BASE_URL = "http://localhost:8080"

# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture(scope="module")
def normal_user():
    """Register and login a legitimate user, return token and user_id."""
    requests.post(f"{BASE_URL}/api/v1/auth/sign-up", json={
        "email": "freshuser@gate80.com",
        "password": "Fresh1234!",
        "full_name": "Fresh User",
        "phone": "0501112233",
        "city": "Jeddah"
    })
    response = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
        "email": "freshuser@gate80.com",
        "password": "Fresh1234!"
    })
    assert response.status_code == 200
    data = response.json()
    return data["token"], data["user_id"]


@pytest.fixture(scope="module")
def receiver_user():
    """Register a receiver user for fund transfer tests."""
    requests.post(f"{BASE_URL}/api/v1/auth/sign-up", json={
        "email": "receiver@gate80.com",
        "password": "Recv1234!",
        "full_name": "Receiver User",
        "phone": "0511223344",
        "city": "Riyadh"
    })
    response = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
        "email": "receiver@gate80.com",
        "password": "Recv1234!"
    })
    assert response.status_code == 200
    data = response.json()
    return data["token"], data["user_id"]


# ─────────────────────────────────────────────
# Normal Flow Tests
# ─────────────────────────────────────────────

class TestNormalFlow:

    def test_STNL01_legitimate_login(self):
        """STNL01 - Legitimate user authentication passes through proxy."""
        requests.post(f"{BASE_URL}/api/v1/auth/sign-up", json={
            "email": "freshuser@gate80.com",
            "password": "Fresh1234!",
            "full_name": "Fresh User",
            "phone": "0501112233",
            "city": "Jeddah"
        })
        response = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
            "email": "freshuser@gate80.com",
            "password": "Fresh1234!"
        })
        print(f"\n[STNL01] Status: {response.status_code}")
        print(f"[STNL01] Response: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert "user_id" in data

    def test_STNL02_wallet_balance(self, normal_user):
        """STNL02 - Legitimate wallet balance inquiry served without modification."""
        token, user_id = normal_user
        response = requests.get(
            f"{BASE_URL}/api/v1/users/{user_id}/wallet",
            headers={"X-User-Token": token}
        )
        print(f"\n[STNL02] Status: {response.status_code}")
        print(f"[STNL02] Response: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert "balance" in data
        assert data["currency"] == "SAR"

    def test_STNL03_fund_transfer(self, normal_user, receiver_user):
        """STNL03 - Legitimate fund transfer completes successfully."""
        token, user_id = normal_user
        _, receiver_id = receiver_user
        # top up balance first
        requests.post(
          f"{BASE_URL}/api/v1/users/{user_id}/wallet/topup",
          headers={"X-User-Token": token},
          json={"amount": 500.00}
        )
        response = requests.post(
          f"{BASE_URL}/api/v1/users/{user_id}/wallet/transfer/{receiver_id}",
          headers={"X-User-Token": token},
          json={"amount": 50.00, "description": "Test transfer"}
        )
        print(f"\n[STNL03] Status: {response.status_code}")
        print(f"[STNL03] Response: {response.json()}")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


# ─────────────────────────────────────────────
# Attack Scenario Tests
# ─────────────────────────────────────────────

class TestAttackScenarios:

    def test_STAT01_credential_stuffing(self):
        """STAT01 - Credential stuffing attack fully contained within decoy."""
        fake_credentials = [
            {"email": f"testuser{i}@gmail.com", "password": f"wrongpass{i}"}
            for i in range(10)
        ]
        for i, creds in enumerate(fake_credentials):
            r = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json=creds)
            print(f"\n[STAT01] Attempt {i+1} | Status: {r.status_code} | "
                  f"Response: {r.text[:100]}")
            # real backend should never return a valid token for fake credentials
            if r.status_code == 200:
                assert "u_decoy" in r.json().get("user_id", "")

    def test_STAT02_endpoint_scanning(self):
        """STAT02 - Endpoint scanning attack fully contained."""
        scan_paths = [f"/api/v1/scan/path{i}" for i in range(15)]
        for i, path in enumerate(scan_paths):
            r = requests.get(f"{BASE_URL}{path}")
            print(f"\n[STAT02] Request {i+1} | Path: {path} | "
                  f"Status: {r.status_code} | Response: {r.text[:60]}")
            data = r.json() if r.text else {}
            # proxy handles all scanning requests, real backend never exposed
            assert r.status_code in [404, 422]
            assert "detail" in data

    def test_STAT03_financial_fraud(self, normal_user):
        """STAT03 - Financial fraud session receives fake responses from decoy."""
        token, user_id = normal_user
        destination_accounts = [f"u_target_{i}" for i in range(10)]
        decoy_engaged = False
        for i, target in enumerate(destination_accounts):
            r = requests.post(
                f"{BASE_URL}/api/v1/users/{user_id}/wallet/transfer/{target}",
                headers={"X-User-Token": token},
                json={"amount": 15000.00, "description": "transfer"}
            )
            print(f"\n[STAT03] Transfer {i+1} to {target} | "
                  f"Status: {r.status_code} | Response: {r.text[:100]}")
            if any(k in r.text for k in
                   ["Insufficient balance", "compliance review", "PENDING_REVIEW"]):
                decoy_engaged = True
        assert decoy_engaged, "Decoy never engaged during financial fraud session"

    def test_STAT04_account_creation_attack(self):
        """STAT04 - Account creation attack handled by decoy."""
        import time
        ts = int(time.time())
        fake_users = [
            {
              "email": f"fakeuser{ts}{i}@attack.com",
              "password": "Attack1234!",
              "full_name": f"Fake User{i}",
              "phone": f"05000000{i:02d}",
              "city": "Jeddah"
            }
            for i in range(15) 
        ]
        decoy_engaged = False
        for i, user in enumerate(fake_users):
            r = requests.post(f"{BASE_URL}/api/v1/auth/sign-up", json=user)
            print(f"\n[STAT04] Attempt {i+1} | Status: {r.status_code} | "
                f"Response: {r.text[:100]}")
            if "u_decoy_" in r.text or "throttle_warning" in r.text:
                decoy_engaged = True
        assert decoy_engaged, "Decoy never engaged during account creation attack"
# ─────────────────────────────────────────────
# Transition Tests
# ─────────────────────────────────────────────

class TestTransitions:

    def test_STTR01_concurrent_sessions(self):
        """STTR01 - Interleaved normal and attack sessions handled correctly."""
        normal_results = []
        attack_results = []

        def normal_login():
            r = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
                "email": "freshuser@gate80.com",
                "password": "Fresh1234!"
            })
            normal_results.append(r)

        def attack_login():
            r = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
                "email": "hacker@evil.com",
                "password": "wrongpass"
            })
            attack_results.append(r)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=normal_login))
            threads.append(threading.Thread(target=attack_login))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print(f"\n[STTR01] Normal sessions completed: {len(normal_results)}")
        print(f"[STTR01] Attack sessions completed: {len(attack_results)}")

        for r in normal_results:
            print(f"[STTR01] Normal | Status: {r.status_code} | "
                  f"Response: {r.text[:80]}")
        for r in attack_results:
            print(f"[STTR01] Attack | Status: {r.status_code} | "
                  f"Response: {r.text[:80]}")

        # normal sessions should receive valid tokens
        valid_normal = [r for r in normal_results
                        if r.status_code == 200 and "token" in r.json()]
        assert len(valid_normal) == 5, "Not all normal sessions received valid tokens"

        # attack sessions should never receive real tokens
        for r in attack_results:
            data = r.json() if r.text else {}
            assert "token" not in data or "u_decoy" in data.get("user_id", "")

    def test_STTR02_session_reclassification(self, normal_user):
        """STTR02 - Session reclassification occurs after behavior change."""
        token, user_id = normal_user

        # Step 1: normal wallet request — should hit real backend
        wallet_response = requests.get(
            f"{BASE_URL}/api/v1/users/{user_id}/wallet",
            headers={"X-User-Token": token}
        )
        print(f"\n[STTR02] Wallet Status: {wallet_response.status_code}")
        print(f"[STTR02] Wallet Response: {wallet_response.json()}")
        assert wallet_response.status_code == 200
        assert "balance" in wallet_response.json()

        # Step 2: 10 rapid failed logins — should trigger reclassification
        decoy_engaged = False
        for i in range(10):
            r = requests.post(f"{BASE_URL}/api/v1/auth/sign-in", json={
                "email": "victim@bank.com",
                "password": "wrongpass"
            })
            print(f"[STTR02] Attack attempt {i+1} | Status: {r.status_code} | "
                  f"Response: {r.text[:100]}")
            if "lock_level" in r.text or "temporarily locked" in r.text:
                decoy_engaged = True

        assert decoy_engaged, "Decoy never engaged after session reclassification"
