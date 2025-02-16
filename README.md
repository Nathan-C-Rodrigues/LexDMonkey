# LexDMonkey
Lex D. Monkey [firmware developer based]

#Enter Virtual Environment

python3 -m venv lex_env

source lex_env/bin/activate

#Required System Packages

sudo apt-get install python3-tk python3-dev

sudo apt install -y python3 python3-pip python3-venv git curl wget \
    build-essential libssl-dev libffi-dev python3-dev \
    libpq-dev libxml2-dev libxslt1-dev libjpeg-dev zlib1g-dev \
    xvfb libfontconfig1 ffmpeg geckodriver

#Required Python Dependencies

sudo apt update && sudo apt install -y python3-scapy python3-dotenv python3-hachoir

pip install --upgrade pip setuptools wheel

pip install pyautogui frida r2pipe faiss-cpu psutil paramiko openai tiktoken pwntools ropper pexpect tensorflow keras numpy requests beautifulsoup4 shodan lief capstone unicorn crcmod SpeechRecognition pywhatkit edge-tts googlesearch-python newspaper3k transformers sentence-transformers scikit-learn adb-shell selenium

#Allow GUI Access

xhost +SI:localuser:$USER


#COMMAND TO RUN THE SCRIPT 

DISPLAY=:0 python3 Lex.py
