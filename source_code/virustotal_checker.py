import hashlib
import time
import requests
import psycopg2
from datetime import datetime, timedelta

# Configure your VirusTotal API keys here (minimum 2)!!
API_KEYS = ['','']

# Base API URL for file lookup by hash
search_url = 'https://www.virustotal.com/api/v3/files/'

# Function to obtain a database connection
def get_db_connection():
    return psycopg2.connect(
        dbname='malware_db',
        user='POSTGRES_USER',
        password='POSTGRES_PASSWORD',
        host='POSTGRES_IP',
        port='POSTGRES_PORT'
    )

# Function to initialize the API usage table
def initialize_api_usage():
    with get_db_connection() as conn_virus:
        with conn_virus.cursor() as cursor:
            for api_key in API_KEYS:
                cursor.execute("""
                    INSERT INTO api_usage (api_key, usage_count, last_used)
                    VALUES (%s, 0, CURRENT_TIMESTAMP)
                    ON CONFLICT (api_key) DO NOTHING;
                """, (api_key,))
        conn_virus.commit()

# Function to check if an API key can make another request
def can_use_api(api_key):
    with get_db_connection() as conn_virus:
        with conn_virus.cursor() as cursor:
            cursor.execute("""
                SELECT usage_count, last_used FROM api_usage WHERE api_key = %s;
            """, (api_key,))
            result = cursor.fetchone()

    usage_count, last_used = result
    current_time = datetime.now()

    # If more than 60 seconds have passed since the last use, reset the counter
    if current_time - last_used >= timedelta(seconds=60):
        with get_db_connection() as conn_virus:
            with conn_virus.cursor() as cursor:
                cursor.execute("""
                    UPDATE api_usage SET usage_count = 0, last_used = %s WHERE api_key = %s;
                """, (current_time, api_key))
            conn_virus.commit()
        usage_count = 0

    # If the API hasn't reached the 4-requests-per-minute limit, allow its use
    return usage_count < 4

# Function to record API usage
def record_api_usage(api_key):
    with get_db_connection() as conn_virus:
        with conn_virus.cursor() as cursor:
            cursor.execute("""
                UPDATE api_usage SET usage_count = usage_count + 1, last_used = %s WHERE api_key = %s;
            """, (datetime.now(), api_key))
        conn_virus.commit()

# Function to generate the MD5 hash of a file
def generate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to check if the file is malicious
def is_file_malicious(scan_results):
    if 'data' in scan_results and 'attributes' in scan_results['data']:
        scan_stats = scan_results['data']['attributes']['last_analysis_stats']
        positives = scan_stats.get('malicious', 0)
        total = scan_stats.get('total', 0)
        
        if positives > 0:
            return True
        else:
            return False
    return False

# Function to search for a file by its MD5 hash
def search_file_by_hash(md5_hash, api_key):
    headers = {
        'x-apikey': api_key,
    }
    
    url = search_url + md5_hash
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Record API usage after a successful request
        record_api_usage(api_key)
        return response.json()
    elif response.status_code == 404:
        # print(f"File with MD5 hash {md5_hash} not found in VirusTotal.")
        return None
    elif response.status_code == 403:
        # print(f"Authorization error with API key {api_key}.")
        return None
    elif response.status_code == 400:
        # print(f"Bad request for file with MD5 hash {md5_hash}.")
        return None
    else:
        # print(f"Error during search with {api_key}: {response.status_code} - {response.text}")
        return None

# Main function to handle the entire process
def process_file(file_path):
    # Generate the MD5 hash of the file
    md5_hash = generate_md5(file_path)
    
    # Initialize the API usage table
    initialize_api_usage()
    
    # Get the first available API key for the search
    for api_key in API_KEYS:
        if can_use_api(api_key):
            search_result = search_file_by_hash(md5_hash, api_key)
            if search_result:
                result = is_file_malicious(search_result)
                # print(f"File with MD5 hash {md5_hash} is malicious: {result}")
                return result
            else:
                # print(f"Unable to obtain analysis results for file with MD5 hash {md5_hash}.")
                return False
        else:
            # print(f"API {api_key} has reached its limit, switching to the next one...")
            time.sleep(15)  # Wait before trying another API key

    return None

# Function to close the database connection (no longer needed with `with` blocks)
def close_connection():
    pass  # Connection management is already handled by 'with' blocks

    