import json
import urllib.request

def test_analyze():
    # Read the XML file
    with open('panos-random-100rules.xml', 'r', encoding='utf-8') as f:
        xml_data = f.read()

    # Create the payload strictly matching the API schema
    payload = json.dumps({
        "vendor": "paloalto",
        "rules": [xml_data]
    }).encode('utf-8')

    # Send the request
    req = urllib.request.Request(
        'http://localhost:8000/analyze', 
        data=payload, 
        headers={'Content-Type': 'application/json'}
    )
    
    print("Sending request to http://localhost:8000/analyze...")
    try:
        with urllib.request.urlopen(req) as response:
            result = response.read().decode('utf-8')
            print("Success! Response:")
            print(result)
            
            # Extract task ID to show the next step
            data = json.loads(result)
            task_id = data.get("task_id")
            print(f"\nTo check status, run:")
            print(f"python -c \"import urllib.request; print(urllib.request.urlopen('http://localhost:8000/status/{task_id}').read().decode())\"")
            
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code}")
        print(e.read().decode('utf-8'))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_analyze()
