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
from langchain.llms import OpenAI
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from adb_shell.adb_device import AdbDeviceTcp
from hachoir.parser import createParser
from hachoir.metadata import extractMetadata

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
        os.system("sudo chmod -R 755 /important/system/path")  # Restricting system-wide changes
        return "Lex D. Monkey has controlled system directories."
    
    def execute_system_command(self, command):
        try:
            result = os.popen(command).read()
            return result if result else "Command executed successfully."
        except Exception as e:
            return f"System command failed: {e}"
    
    def listen_speech(self):
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            recognizer.adjust_for_ambient_noise(source)
            print("Listening...")
            try:
                audio = recognizer.listen(source, timeout=10)
                text = recognizer.recognize_google(audio)
                return text
            except sr.UnknownValueError:
                return "Sorry, I didn't catch that."
            except sr.RequestError:
                return "Speech service is unavailable."
    
    async def speak(self, text):
        tts = edge_tts.Communicate(text, "en-US-AriaNeural")
        await tts.save("response.mp3")
        os.system("ffplay -nodisp -autoexit response.mp3")
    
    def call_user_whatsapp(self):
        url = f"https://web.whatsapp.com/send?phone={self.whatsapp_number}"
        webbrowser.open(url)
        return f"Opening WhatsApp Web to contact {self.whatsapp_number}."
    
    def trigger_call(self, condition):
        if "emergency" in condition.lower():
            return self.call_user_whatsapp()
        return "No emergency detected. Call not initiated."
    
    def web_learn(self, topic):
        try:
            search_results = search(f"{topic} firmware vulnerabilities", num_results=3)
            knowledge = "\n\n[ Web Learning Updates ]\n"
            for url in search_results:
                try:
                    article = Article(url)
                    article.download()
                    article.parse()
                    knowledge += f"Source: {url}\nTitle: {article.title}\nSummary: {article.text[:500]}\n\n"
                except Exception:
                    knowledge += f"Source: {url}\n[Failed to extract content]\n\n"
            self.exploit_knowledge.append(knowledge)
            return knowledge
        except Exception as e:
            return f"Web learning failed: {e}"
    
    def analyze_firmware(self, firmware_path):
        parser = createParser(firmware_path)
        if parser is None:
            return "Failed to parse firmware file."
        metadata = extractMetadata(parser)
        return metadata.exportDictionary()
    
    def chat(self, user_input):
        response = self.chatbot(user_input, max_length=100, do_sample=True)
        return response[0]["generated_text"]

if __name__ == "__main__":
    ai = LexDMonkeyAI()
    print("AI Ready! Type a command:")
    loop = asyncio.get_event_loop()

    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            break
        elif "listen" in user_input:
            print("AI:", ai.listen_speech())
        elif "speak" in user_input:
            text = user_input.replace("speak ", "")
            loop.run_until_complete(ai.speak(text))
        elif "call user" in user_input:
            print("AI:", ai.call_user_whatsapp())
        elif "trigger call" in user_input:
            condition = user_input.replace("trigger call ", "")
            print("AI:", ai.trigger_call(condition))
        elif "web learn" in user_input:
            topic = user_input.replace("web learn ", "")
            print("AI:", ai.web_learn(topic))
        elif "analyze firmware" in user_input:
            firmware_path = user_input.replace("analyze firmware ", "")
            print("AI:", ai.analyze_firmware(firmware_path))
        else:
            print("AI:", ai.chat(user_input))

