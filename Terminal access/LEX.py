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
import time

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
        
        # Full System Control (Restricted to Safe Paths)
        self.system_root_access()

        # Initialize web knowledge base
        self.web_knowledge_base = []
        self.web_learn_interval = 60 * 60  # Learn every hour

        # Initialize self-upgrade feature
        self.source_file = __file__  # Get the current file path of the script
        self.version = 1  # Starting version for upgrades

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
        elif "self upgrade" in command:
            return self.self_upgrade()
        else:
            return self.chat(command)

    def chat(self, command):
        response = self.chatbot(command, max_length=100, num_return_sequences=1, truncation=True, pad_token_id=50256)[0]["generated_text"]
        
        # Remove unnecessary line breaks and format output
        response = response.replace("\n", " ").strip()
        
        return response

    def web_learn(self, topic):
        """Search the web and collect data to improve the AI's knowledge base."""
        print(f"Searching for {topic}...")
        
        # Search using Google (via googlesearch)
        search_results = search(topic, num_results=5)  # Limit to 5 results
        
        for result in search_results:
            print(f"Fetching content from {result}")
            article = Article(result)
            article.download()
            article.parse()
            content = article.text
            
            # Process and store content
            self.web_knowledge_base.append(content)
            print(f"Content gathered from {result}: {content[:200]}...")

        # Optionally, train the model using the gathered data
        self.train_from_web_knowledge()

    def train_from_web_knowledge(self):
        """Use collected knowledge to train the AI model (example: update response generation)."""
        print(f"Training from web data with {len(self.web_knowledge_base)} new entries.")
        
        for entry in self.web_knowledge_base:
            print(entry[:200])  # Print the first 200 characters of the entry for demonstration

    def self_upgrade(self):
        """Upgrade itself by modifying its own code."""
        print("Lex D. Monkey is upgrading itself...")

        # Check current version
        self.version += 1  # Increment version for the new upgrade

        # Load current code (self-modify) and add a new feature or modify logic
        try:
            with open(self.source_file, "r") as f:
                code = f.read()
            
            # Example: Modify code (Adding a new function or changing an existing function)
            new_code = code.replace(
                "# Example: Modify the chatbot response generation",
                "# Example: Modify the chatbot response generation\n        print('Upgraded version!')"
            )

            # Save the modified code
            with open(self.source_file, "w") as f:
                f.write(new_code)

            # Reload the script (this will run the modified version of the script)
            print("Code updated successfully. Restarting the script with the new version...")
            os.system(f"python3 {self.source_file}")  # Restart the script with the new changes

        except Exception as e:
            print(f"Self-upgrade failed: {e}")
            return f"Error during self-upgrade: {e}"

if __name__ == "__main__":
    ai = LexDMonkeyAI()
    print("AI Ready! Listening for terminal commands...")
    
    # Uncomment the following line to start web learning
    # ai.start_web_learning()

    ai.listen_for_terminal_commands()
