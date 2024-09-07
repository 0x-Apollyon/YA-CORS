<pre>
▄██   ▄      ▄████████             ▄████████  ▄██████▄     ▄████████    ▄████████ 
███   ██▄   ███    ███            ███    ███ ███    ███   ███    ███   ███    ███ 
███▄▄▄███   ███    ███            ███    █▀  ███    ███   ███    ███   ███    █▀  
▀▀▀▀▀▀███   ███    ███   ██████   ███        ███    ███  ▄███▄▄▄▄██▀   ███        
▄██   ███ ▀███████████   ██████   ███        ███    ███ ▀▀███▀▀▀▀▀   ▀███████████ 
███   ███   ███    ███            ███    █▄  ███    ███ ▀███████████          ███ 
███   ███   ███    ███            ███    ███ ███    ███   ███    ███    ▄█    ███ 
 ▀█████▀    ███    █▀             ████████▀   ▀██████▀    ███    ███  ▄████████▀    </pre>
                                
### Yet another - cross origin resource sharing misconfig scanner
##### By: Apollyon


## Commands

| COMMAND | DESCRIPTION |
| ------------- | ------------- |
| -h / --help | Request help |
| -u / --url | Target Website |
| -ulist / --url_list | Target multiple websites from file |
| -to / --timeout | Set the timeout for requests |
| -wiz / --wizard | Wizard for new users |
| -t / --threads | Multi threaded scanning |
| -pr / --proxy | Using proxies (HTTP, HTTPS, SOCKS) |
| -auth / --authentication | Authentication using headers and/or cookies |
| -save / --save_to_file | Saves valid payloads to file on disk |

## Installation
Normal
```
git clone https://github.com/0x-Apollyon/YA-CORS.git
cd YA-CORS
pip install -r requirements.txt
```
Using virtual environment (Arch based linux distros)
```
git clone https://github.com/0x-Apollyon/YA-CORS.git
cd YA-CORS
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

You can run it using commands given below or use the wizard

View help
```
python main.py -h
```
Default usage
```
python main.py -u https://example.com
```
Using with wizard
```
python main.py -wiz
```
![image](https://github.com/user-attachments/assets/85e5ec2b-a156-4196-ad6c-70fc5d611a16)


## Using with TOR

If you want to use YA-CORS with TOR you can do the following <br>
- Run the tor service
- Add socks5://127.0.0.1:9050 to the proxy list
- Run YA-CORS with the proxies flag

Tor uses the port 9050 for socks proxies by default, so if you have changed that change the port aswell <br>
