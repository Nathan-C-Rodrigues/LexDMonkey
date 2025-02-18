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
        self.web_knowledge_base = []

        # Automatically load API keys
        self.openai_api_key = os.getenv("OPENAI_API_KEY") or self.ask_for_api_key("OpenAI API Key", "OPENAI_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY") or self.ask_for_api_key("Shodan API Key", "SHODAN_API_KEY")
        
        self.exploit_knowledge = []
        
        # Full System Control (Restricted to Safe Paths)
        self.system_root_access()
        self.fetch_web_data()

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
            return result if result else "Command executed successfully."
        except Exception as e:
            return f"System command failed: {e}"

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
        if "listen" in command:
            return self.listen_speech()
        elif "speak" in command:
            text = command.replace("speak ", "")
            asyncio.run(self.speak(text))
            return "Speaking..."
        elif "web learn" in command:
            topic = command.replace("web learn ", "")
            return self.web_learn(topic)
        elif "analyze firmware" in command:
            firmware_path = command.replace("analyze firmware ", "")
            return self.analyze_firmware(firmware_path)
        else:
            return self.chat(command)

    def chat(self, command):
        response = self.chatbot(command, max_length=100, num_return_sequences=1, truncation=True, pad_token_id=50256)[0]["generated_text"]
        
        # Remove unnecessary line breaks and format output
        response = response.replace("\n", " ").strip()
        
        return response

    def web_learn(self, topic):
        """
        Fetches and processes articles about the specified topic to enhance Lex D. Monkey's knowledge base.
        """
        print(f"Searching for: {topic}")
        fetched_articles = search(topic, num_results=5)
        self.web_knowledge_base = []

        for url in fetched_articles:
            try:
                article = Article(url)
                article.download()
                article.parse()
                print(f"Fetched article from {url}")
                self.web_knowledge_base.append(article.text)
            except Exception as e:
                print(f"Failed to fetch or parse article from {url}: {e}")

        self.process_web_data()

    def process_web_data(self):
        """
        Process the fetched web data into a form Lex D. Monkey can learn from.
        This will use a model to understand and store the data.
        """
        print("Processing web data...")

        # Convert the web knowledge into vectors using SentenceTransformer
        knowledge_vectors = []

        for content in self.web_knowledge_base:
            vector = self.memory_model.encode(content)
            knowledge_vectors.append(vector)

        # Adjust the number of clusters dynamically based on the number of articles
        n_clusters = max(1, len(knowledge_vectors))  # At least 1 cluster

        # Cluster the knowledge (optional, for organizing related topics)
        knowledge_vectors = np.array(knowledge_vectors)
        self.memory_index = KMeans(n_clusters=n_clusters)  # Adjust number of clusters
        self.memory_index.fit(knowledge_vectors)

        # Store memory data (knowledge) for later use
        self.memory_data = knowledge_vectors
        print(f"Web data processed into {n_clusters} cluster(s).")

    def analyze_firmware(self, firmware_path):
        """
        Placeholder for firmware analysis. This will include the logic to analyze and potentially exploit firmware.
        """
        print(f"Analyzing firmware at {firmware_path}...")
        # Add firmware analysis logic here (e.g., extract metadata, run vulnerability analysis, etc.)

    def fetch_web_data(self):
        """
        A method to automatically fetch web data for system and firmware learning.
        """
        print("Fetching web data for system and firmware knowledge...")
        topics = ["android firmware exploitation techniques", "miui android development", "firmware analysis"]
        for topic in topics:
            self.web_learn(topic)

if __name__ == "__main__":
    lex_ai = LexDMonkeyAI()
    print("AI Ready! Listening for terminal commands...")
    lex_ai.listen_for_terminal_commands()
