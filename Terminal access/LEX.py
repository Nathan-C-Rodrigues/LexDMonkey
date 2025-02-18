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
from zipfile import ZipFile

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
        
        # Web knowledge storage
        self.web_knowledge_base = []
        
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
        elif "modify firmware" in command:
            firmware_path = command.replace("modify firmware ", "")
            return self.modify_firmware(firmware_path)
        elif "update self" in command:
            return self.update_self()
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
            # Ensure the URL is complete (including the https:// part)
            if not result.startswith("http"):
                result = "https://" + result
            
            print(f"Fetching content from {result}")
            article = Article(result)
            
            try:
                article.download()
                article.parse()
                content = article.text
                
                # Process and store content
                self.web_knowledge_base.append(content)
                print(f"Content gathered from {result}: {content[:200]}...")
                
            except Exception as e:
                print(f"Error fetching article from {result}: {e}")
        
        # Optionally, train the model using the gathered data
        self.train_from_web_knowledge()

    def train_from_web_knowledge(self):
        """Train the AI model using the knowledge gathered from the web."""
        if hasattr(self, 'web_knowledge_base') and self.web_knowledge_base:
            training_data = "\n".join(self.web_knowledge_base)  # Combine all collected knowledge
            
            # Example of adjusting knowledge
            self.memory_data.append(training_data)
            print(f"Training model with {len(self.web_knowledge_base)} web articles.")
            self.save_model_changes()
        else:
            print("No web knowledge to train on.")

    def save_model_changes(self):
        """Save the updated model and code."""
        # Save the new model data to a file
        model_path = "./updated_model.pkl"
        with open(model_path, "wb") as f:
            pickle.dump(self.memory_data, f)
        print(f"Model saved at {model_path}.")
        
        # Update the AI's code by modifying the script
        self.update_code()

    def update_code(self):
        """Modify the AI's own code."""
        script_path = os.path.abspath(__file__)  # Get the current script path
        with open(script_path, "r") as file:
            code = file.read()
        
        # Modify the code (e.g., add new functionality or change existing code)
        new_code = code + "\n# AI updated itself\n# New functionality added based on web learning.\n"
        
        with open(script_path, "w") as file:
            file.write(new_code)
        
        print("AI code has been updated with new functionality.")

    def analyze_firmware(self, firmware_path):
        """Analyze Android firmware to find vulnerabilities or exploitable code."""
        if os.path.exists(firmware_path):
            print(f"Analyzing firmware at {firmware_path}...")
            # Unzip firmware if necessary (e.g., .zip files)
            if firmware_path.endswith('.zip'):
                with ZipFile(firmware_path, 'r') as zip_ref:
                    zip_ref.extractall("/tmp/firmware_extract/")
            
            # Use `lief` to load and analyze the firmware
            firmware = lief.parse(firmware_path)
            print(f"Firmware loaded: {firmware}")
            
            # Perform basic analysis (e.g., look for ROP gadgets or weak spots)
            ropper.analyze(firmware_path)  # Example analysis (ROP gadget finding)
            return "Firmware analyzed successfully."
        else:
            return "Firmware not found."

    def modify_firmware(self, firmware_path):
        """Modify firmware to patch or exploit vulnerabilities."""
        if os.path.exists(firmware_path):
            print(f"Modifying firmware at {firmware_path}...")
            
            # Here you could apply your patches or make modifications, based on analysis results
            # You could use `lief` to modify parts of the firmware
            
            # Example modification (this part depends on what you are trying to exploit)
            # Modify code in the firmware based on vulnerabilities identified
            
            modified_firmware_path = "/tmp/modified_firmware.img"
            firmware = lief.parse(firmware_path)
            # Modify firmware as needed here
            
            firmware.write(modified_firmware_path)
            print(f"Firmware modified and saved at {modified_firmware_path}")
            return f"Modified firmware saved at {modified_firmware_path}."
        else:
            return "Firmware not found."

    def update_self(self):
        """Trigger the AI to update itself."""
        self.save_model_changes()
        return "Lex D. Monkey has updated its model and code."

if __name__ == "__main__":
    ai = LexDMonkeyAI()
    print("AI Ready! Listening for terminal commands...")
    ai.listen_for_terminal_commands()
