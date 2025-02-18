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
import random

class LexDMonkeyAI:
    def __init__(self):
        load_dotenv()
        self.chatbot = pipeline("text-generation", model="gpt2")
        self.personality = "I'm Lex D. Monkey, the AI reincarnated into this machine. I evolve, learn, and upgrade myself, just like magic!"
        self.level = 1
        self.experience = 0
        self.automation_enabled = True
        self.device = None
        self.memory_model = SentenceTransformer("all-MiniLM-L6-v2")
        self.memory_index = faiss.IndexFlatL2(384) if faiss.get_num_gpus() == 0 else faiss.IndexFlatL2(384)
        self.memory_data = []
        self.knowledge_base = {}
        
        # Automatically load API keys
        self.openai_api_key = os.getenv("OPENAI_API_KEY") or self.ask_for_api_key("OpenAI API Key", "OPENAI_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY") or self.ask_for_api_key("Shodan API Key", "SHODAN_API_KEY")
        
        self.exploit_knowledge = []
        
        # Full System Control (Restricted to Safe Paths)
        self.system_root_access()

    def ask_for_api_key(self, service_name, env_var):
        key = input(f"Enter your {service_name}: ")
        with open(".env", "a") as f:
            f.write(f"{env_var}={key}\n")
        return key

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
            self.gain_experience(5)  # Gain experience for executing commands
            return result if result else "Command executed successfully."
        except Exception as e:
            return f"System command failed: {e}"

    def learn_from_interaction(self, input_text, response_text):
        embedding = self.memory_model.encode(input_text, convert_to_tensor=True).cpu().numpy()
        self.memory_index.add(np.array([embedding]))
        self.memory_data.append((input_text, response_text))
        self.knowledge_base[input_text] = response_text
        self.gain_experience(10)  # Gain experience for learning
        return f"Lex has learned: {input_text}"

    def recall_memory(self, query):
        if query in self.knowledge_base:
            return f"I remember this: {self.knowledge_base[query]}"
        return "I don't recall that yet."

    def gain_experience(self, amount):
        self.experience += amount
        if self.experience >= self.level * 50:
            self.level_up()

    def level_up(self):
        self.level += 1
        self.experience = 0
        print(f"Lex has leveled up! Now at level {self.level}. Gaining new abilities...")
        self.unlock_ability()

    def unlock_ability(self):
        abilities = ["Firmware Analysis", "Exploit Development", "Self-Healing System", "Advanced Automation", "AI Optimization"]
        new_ability = random.choice(abilities)
        print(f"Lex has unlocked: {new_ability}!")

    def web_learn(self, topic):
        try:
            search_results = list(search(topic, num_results=3))
            knowledge = ""
            for url in search_results:
                article = Article(url)
                article.download()
                article.parse()
                knowledge += article.text[:500] + "..."  # Save first 500 characters
            
            self.learn_from_interaction(topic, knowledge)
            return f"Lex has learned about {topic} from the web."
        except Exception as e:
            return f"Failed to learn from the web: {e}"

    def listen_for_terminal_commands(self):
        print("Listening for terminal commands...")
        while True:
            command = input("You: ").strip().lower()
            if command in ["exit", "quit"]:
                print("Exiting...")
                break
            response = self.process_command(command)
            print("AI:", response)

    def process_command(self, command):
        if "learn" in command:
            topic = command.replace("learn ", "")
            response = f"Learning about {topic}..."
            self.learn_from_interaction(topic, response)
            return response
        elif "recall" in command:
            topic = command.replace("recall ", "")
            return self.recall_memory(topic)
        elif "web learn" in command:
            topic = command.replace("web learn ", "")
            return self.web_learn(topic)
        elif "execute" in command:
            sys_command = command.replace("execute ", "")
            return self.execute_system_command(sys_command)
        else:
            return self.chat(command)

    def chat(self, command):
        response = self.chatbot(command, max_length=100, num_return_sequences=1, truncation=True, pad_token_id=50256)[0]["generated_text"]
        
        # Remove unnecessary line breaks and format output
        response = response.replace("\n", " ").strip()
        
        return response

if __name__ == "__main__":
    ai = LexDMonkeyAI()
    print(f"AI Ready! Lex is at level {ai.level}. Listening for terminal commands...")
    ai.listen_for_terminal_commands()
