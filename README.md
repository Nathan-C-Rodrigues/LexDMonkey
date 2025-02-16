# LexDMonkey
Lex D. Monkey [firmware developer based]

#Enter Virtual Environment

python3 -m venv lex_env
source lex_env/bin/activate

#Required System Packages

sudo apt install -y python3 python3-pip python3-venv git curl wget \
    build-essential libssl-dev libffi-dev python3-dev \
    libpq-dev libxml2-dev libxslt1-dev libjpeg-dev zlib1g-dev \
    xvfb libfontconfig1 ffmpeg geckodriver

#Required Python Dependencies

pip install --upgrade pip setuptools wheel

pip install pyautogui frida r2pipe faiss-cpu pickle-mixin psutil paramiko \
    scapy openai tiktoken pwn ropper pexpect tensorflow keras numpy requests \
    beautifulsoup4 shodan lief capstone unicorn crcmod speechrecognition \
    pywhatkit edge-tts asyncio webbrowser googlesearch-python newspaper3k \
    python-dotenv transformers sentence-transformers scikit-learn adb-shell \
    hachoir selenium


    
