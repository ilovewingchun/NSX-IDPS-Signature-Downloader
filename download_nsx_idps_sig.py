import requests
import urllib3
import json
import csv
import os

# You may need to install the 'requests' and 'urllib3' modules.
# You can install them using pip:
# pip install requests urllib3

# User-configurable options
base_url = "https://<NSX Manager>/policy/api/v1"
username = "<NSX admin username>"
password = "<The corresponding password>"
output_directory = ""  # Set your desired output directory here, default to the same directory as the script itself
output_format = "csv"  # Choose "csv" or "json" as the output format

# Non-configurable option
endpoint = "/infra/settings/firewall/security/intrusion-services/signature-versions/"

# Disable the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Step 1: Retrieve the version ID
response = requests.get(base_url + endpoint, auth=(username, password), verify=False)
response.raise_for_status()
data = response.json()

version_id = None
for item in data["results"]:
    if "IDPSSignatures" in item.get("version_id", ""):
        version_id = item["version_id"]
        break

if version_id is None:
    print("Error: Could not find the correct version ID.")
    exit(1)

print("The identified signature version is:", version_id)

# Step 2: Fetch the signatures
output_data = []
cursor = ""

num_requests = 0  # Track the number of requests made
total_requests = 12  # Set the total number of expected requests here

while True:
    url = base_url + endpoint + version_id + "/signatures"
    params = {"cursor": cursor}

    response = requests.get(url, auth=(username, password), params=params, verify=False)
    response.raise_for_status()
    data = response.json()

    output_data.append(data)

    num_requests += 1

    # Calculate and output the estimated progress
    progress = (num_requests / total_requests) * 100
    print(f"{progress:.0f}% complete")

    if "cursor" not in data:
        break

    cursor = data["cursor"]

# Combine all the output data
combined_data = {"results": output_data}

# Save the data to a file
if output_directory:
    output_file = os.path.join(output_directory, f"IDPSSignatures.{version_id.split('.')[1]}")
else:
    output_file = f"IDPSSignatures.{version_id.split('.')[1]}"

if output_format == "csv":
    output_file += ".csv"
    fieldnames = set()
    for result in combined_data["results"]:
        for signature in result["results"]:
            fieldnames.update(signature.keys())
    with open(output_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for result in combined_data["results"]:
            for signature in result["results"]:
                writer.writerow(signature)
elif output_format == "json":
    output_file += ".json"
    with open(output_file, "w") as file:
        json.dump(combined_data, file)
else:
    print("Invalid output format specified.")

print("Data saved to", output_file)
