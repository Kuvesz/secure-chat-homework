import requests 

while True:
    data = input('Please enter your message:')
    url = "http://127.0.0.1:8080"

    r = requests.post(url = url, data = data)
    print(r.text)