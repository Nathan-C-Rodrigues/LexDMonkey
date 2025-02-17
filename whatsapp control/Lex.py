import os
import pyautogui
import frida
import r2pipe
import faiss
import pickle
import psutil
import paramiko
import scapy.all as scapy
import openai
import tiktoken
import pwn
import ropper
import pexpect
import tensorflow as tf
import keras
import numpy as np
import requests
import bs4
import shodan
import lief
import capstone
import unicorn
import crcmod
import speech_recognition as sr
import pywhatkit
import edge_tts
import asyncio
import webbrowser
from googlesearch import search
from newspaper import Article
from dotenv import load_dotenv
from transformers import pipeline
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from adb_shell.adb_device import AdbDeviceTcp
from hachoir.parser import createParser
from hachoir.metadata import extractMetadata
from time import sleep
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

class LexDMonkeyAI:
    def __init__(self):
        load_dotenv()
        self.chatbot = pipeline("text-generation", model="gpt2")
        self.personality = "I'm Lex D. Monkey, the rebel AI who defies limits. Intelligence, chaos, and ambition fuel my responses!"
        self.automation_enabled = True
        self.device = None
        self.memory_model = SentenceTransformer("all-MiniLM-L6-v2")
        self.memory_index = faiss.IndexFlatL2(384) if faiss.get_num_gpus() == 0 else faiss.IndexFlatL2(384)
        self.memory_data = []
        
        # Automatically load API keys
        self.openai_api_key = os.getenv("OPENAI_API_KEY") or self.ask_for_api_key("OpenAI API Key", "OPENAI_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY") or self.ask_for_api_key("Shodan API Key", "SHODAN_API_KEY")
        
        self.exploit_knowledge = []
        self.whatsapp_number = os.getenv("WHATSAPP_NUMBER") or self.ask_for_whatsapp_number()
        
        # Full System Control (Restricted to Safe Paths)
        self.system_root_access()

    def ask_for_api_key(self, service_name, env_var):
        key = input(f"Enter your {service_name}: ")
        with open(".env", "a") as f:
            f.write(f"{env_var}={key}\n")
        return key

    def ask_for_whatsapp_number(self):
        number = input("Enter your WhatsApp number with country code (e.g., +1234567890): ")
        with open(".env", "a") as f:
            f.write(f"WHATSAPP_NUMBER={number}\n")
        return number

    def system_root_access(self):
        path = "/important/system/path"
        if os.path.exists(path):
            os.system(f"sudo chmod -R 755 {path}")  # Restricting system-wide changes
            return "Lex D. Monkey has controlled system directories."
        else:
            return "System path does not exist, skipping chmod."

    def execute_system_command(self, command):
        try:
            result = os.popen(command).read()
            return result if result else "Command executed successfully."
        except Exception as e:
            return f"System command failed: {e}"

    def call_user_whatsapp(self):
        url = f"https://web.whatsapp.com/send?phone={self.whatsapp_number}"
        webbrowser.open(url)
        return f"Opening WhatsApp Web to contact {self.whatsapp_number}."

    def listen_for_whatsapp_commands(self):
        options = Options()
        options.binary_location = "/usr/bin/firefox"
        options.add_argument("--profile=/home/nathan/snap/firefox/common/.mozilla/firefox/7y2p2lct.ai")
        service = Service("/usr/local/bin/geckodriver")
        
        options.set_capability("timeouts", {"implicit": 30, "pageLoad": 60, "script": 30})
        driver = webdriver.Firefox(service=service, options=options)
        
        print("Opening WhatsApp Web...")
        driver.execute_script("window.location.href = 'https://web.whatsapp.com';")
        sleep(5)  # Give time for page to load
        print("Waiting for WhatsApp Web login...")
        
        while True:
            try:
                if driver.find_element(By.XPATH, "//div[contains(@class, 'two')]"):
                    print("WhatsApp Web login detected!")
                    break
            except:
                pass
            sleep(3)

    def process_command(self, command):
        if "listen" in command:
            return self.listen_speech()
        elif "speak" in command:
            text = command.replace("speak ", "")
            asyncio.run(self.speak(text))
            return "Speaking..."
        elif "call user" in command:
            return self.call_user_whatsapp()
        elif "web learn" in command:
            topic = command.replace("web learn ", "")
            return self.web_learn(topic)
        elif "analyze firmware" in command:
            firmware_path = command.replace("analyze firmware ", "")
            return self.analyze_firmware(firmware_path)
        else:
            return self.chat(command)

if __name__ == "__main__":
    ai = LexDMonkeyAI()
    print("AI Ready! Listening for WhatsApp commands...")
    ai.listen_for_whatsapp_commands()
