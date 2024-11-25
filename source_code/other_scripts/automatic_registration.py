import requests

url = "https://cybermail.es/register" # Ajust

for i in range(1,31):
    data = {
    "name": "user"+str(i),
    "email": "user"+str(i),
    "password": "Str0ngP@ss!", # Ajust
    "confirm_password": "Str0ngP@ss!" # Ajust
    }
    # POST request
    response = requests.post(url, data=data,verify='/home/username/myCA.pem') # Ajust

    print(f"Status code: {response.status_code}")
    #print(f"Headers response: {response.headers}")
    #print(f"Body response: {response.text}")
    print(f"The user user{i} has been registered")