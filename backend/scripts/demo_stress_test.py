import asyncio
import time
import uuid
import httpx

API_URL = "http://127.0.0.1:8080/chat"

TEST_CASES = [
    # English Edge Cases
    {"message": "I live in Aragon, it's a great place.", "expect_masked": True, "target": "Aragon", "lang": "en"},
    {"message": "What are the best hiking routes in Aragon?", "expect_masked": False, "target": "Aragon", "lang": "en"},
    {"message": "My password is Password123!", "expect_masked": True, "target": "Password123!", "lang": "en"},
    # Spanish Edge Cases
    {"message": "Yo vivo en Madrid.", "expect_masked": True, "target": "Madrid", "lang": "es"},
    {"message": "El clima en Madrid está soleado hoy.", "expect_masked": False, "target": "Madrid", "lang": "es"},
    {"message": "Mi cuenta de banco es ES12 3456 7890 1234 5678 9012.", "expect_masked": True, "target": "ES12", "lang": "es"}
]

async def fire_request(client, case, request_id):
    sid = str(uuid.uuid4())
    headers = {"X-Session-ID": sid}
    t0 = time.time()
    
    try:
        # Note: we are passing provider="google" but in a real demo we might want to test the LLM. 
        # For stress testing just the privacy engine, we are hitting the endpoint which calls the LLM. 
        response = await client.post(
            API_URL, 
            json={"message": case["message"]}, 
            headers=headers,
            params={"provider": "google"}
        )
        latency = time.time() - t0
        
        if response.status_code != 200:
            return f"[FAIL] Request {request_id} returned {response.status_code}"
            
        data = response.json()
        masked_text = data.get("masked_text", "")
        
        # Verify correctness
        is_masked = case["target"] not in masked_text
        if is_masked == case["expect_masked"]:
            status = "PASS"
        else:
            status = f"FAIL (Expected masked={case['expect_masked']}, got masked={is_masked})"
            
        return f"[{status}] Lang: {case['lang'].upper()} | Latency: {latency:.2f}s | {case['message'][:30]}..."
        
    except Exception as e:
        return f"[ERROR] Request {request_id} failed: {str(e)}"

async def main():
    print("========================================")
    print("AXION Privacy Middleware - Demo Stress Test")
    print("========================================")
    
    # 1. Edge Case Functional Test
    print("\n--- Running Functional Edge Cases ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, case in enumerate(TEST_CASES):
            result = await fire_request(client, case, i)
            print(result)

    # 2. Concurrency Stress Test
    print("\n--- Running Rate-Limited Stress Test (5 requests to avoid API bans) ---")
    async with httpx.AsyncClient(timeout=60.0) as client:
        tasks = []
        for i in range(5):
            case = TEST_CASES[i % len(TEST_CASES)]
            tasks.append(fire_request(client, case, i))
            
        t0 = time.time()
        # To avoid 429 rate limit from Gemini free tier
        results = []
        for task in tasks:
            results.append(await task)
            await asyncio.sleep(1) # rate limit delay
            
        total_time = time.time() - t0
        
        passed = sum(1 for r in results if "[PASS]" in r)
        print(f"\nStress Test Results: {passed}/5 Passed in {total_time:.2f}s total.")
        if passed != 5:
            for r in results:
                if "[PASS]" not in r:
                    print("  ->", r)

if __name__ == "__main__":
    asyncio.run(main())
