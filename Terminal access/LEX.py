import os
import subprocess
import time
import lief
import ropper
import requests
from bs4 import BeautifulSoup
from zipfile import ZipFile
import numpy as np
from transformers import pipeline
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from googlesearch import search
from newspaper import Article

class LexDMonkeyAI:
    def __init__(self):
        self.exploit_knowledge = []
        self.web_knowledge_base = []
        self.automation_enabled = True
        self.device = None
        self.memory_model = SentenceTransformer("all-MiniLM-L6-v2")
        self.memory_index = None
        self.memory_data = []

        self.chatbot = pipeline("text-generation", model="gpt2")

        # Learning through the web
        self.fetch_web_data()

    def fetch_web_data(self):
        """
        Fetches web data about system paths and firmware analysis for Lex D. Monkey to learn.
        This will use Google search and web scraping.
        """
        search_query = "android firmware exploitation techniques"
        print("Searching for: ", search_query)

        # Perform a web search to gather knowledge
        search_results = search(search_query, num_results=5)

        for url in search_results:
            try:
                article = Article(url)
                article.download()
                article.parse()

                # Extract text and add to the knowledge base
                text = article.text
                self.web_knowledge_base.append(text)

                print(f"Fetched article from {url}")
            except Exception as e:
                print(f"Failed to fetch or parse article from {url}: {e}")

        print("Web data collection complete.")

        # Process the fetched data into meaningful learning information
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

        # Cluster the knowledge (optional, for organizing related topics)
        knowledge_vectors = np.array(knowledge_vectors)
        self.memory_index = KMeans(n_clusters=5)  # Adjust the number of clusters as necessary
        self.memory_index.fit(knowledge_vectors)

        # Store memory data (knowledge) for later use
        self.memory_data = knowledge_vectors
        print("Web data processing complete.")

    def open_new_terminal_and_run(self, firmware_path):
        """
        Opens a new terminal and starts analyzing and exploiting the provided firmware.
        """
        print("Opening a new terminal to begin firmware analysis and exploitation...")

        # Check if firmware exists
        if not os.path.exists(firmware_path):
            print("Firmware path does not exist!")
            return "Error: Firmware path does not exist."

        # Unzip firmware if necessary (e.g., .zip files)
        if firmware_path.endswith('.zip'):
            with ZipFile(firmware_path, 'r') as zip_ref:
                zip_ref.extractall("/tmp/firmware_extract/")
                firmware_path = "/tmp/firmware_extract/"  # Update path to extracted firmware

        # Create the command to analyze and exploit firmware
        firmware_analysis_command = f"python3 /home/nathan/LexDMonkey/firmware_analysis.py {firmware_path}"

        # Open a new terminal and run the analysis and exploitation script
        try:
            subprocess.Popen(['bash', '-c', firmware_analysis_command])
            print(f"New terminal opened. Running the command: {firmware_analysis_command}")
        except Exception as e:
            print(f"Error opening terminal: {e}")
            return f"Error opening terminal: {e}"

    def process_command(self, command):
        """
        Process the command issued by the user.
        """
        if "learn firmware" in command:
            self.fetch_web_data()
            return "Lex D. Monkey is learning about firmware exploitation from the web."
        elif "analyze and exploit firmware" in command:
            firmware_path = command.replace("analyze and exploit firmware ", "").strip()
            return self.open_new_terminal_and_run(firmware_path)
        elif "search knowledge" in command:
            return self.search_for_knowledge(command)
        else:
            return self.chat(command)

    def search_for_knowledge(self, query):
        """
        Searches for specific knowledge based on a query.
        """
        print(f"Searching for knowledge: {query}")
        knowledge_results = []
        
        for content in self.web_knowledge_base:
            if query.lower() in content.lower():
                knowledge_results.append(content)

        if knowledge_results:
            return "\n".join(knowledge_results[:5])  # Show top 5 results
        else:
            return "No matching knowledge found."

    def analyze_firmware(self, firmware_path):
        """
        Analyze Android firmware to find vulnerabilities or exploitable code.
        """
        if os.path.exists(firmware_path):
            print(f"Analyzing firmware at {firmware_path}...")

            # Use `lief` to load and analyze the firmware
            try:
                firmware = lief.parse(firmware_path)
                print(f"Firmware loaded: {firmware}")
                ropper.analyze(firmware_path)  # Example analysis (ROP gadget finding)
                return "Firmware analyzed successfully."
            except Exception as e:
                print(f"Error analyzing firmware: {e}")
                return f"Error analyzing firmware: {e}"
        else:
            return "Firmware not found."

    def exploit_firmware(self, firmware_path):
        """
        Exploit vulnerabilities in the firmware.
        This will be a placeholder for adding exploitation logic.
        """
        print(f"Exploiting firmware at {firmware_path}...")
        
        # Example exploit logic: finding vulnerabilities
        # Modify this section to suit specific exploitation techniques
        if os.path.exists(firmware_path):
            try:
                firmware = lief.parse(firmware_path)
                # Perform exploit action based on vulnerabilities discovered
                # Save modified firmware or add exploit payload
                
                modified_firmware_path = "/tmp/exploited_firmware.img"
                firmware.write(modified_firmware_path)
                print(f"Firmware successfully exploited and saved to: {modified_firmware_path}")
                return f"Exploited firmware saved at {modified_firmware_path}."
            except Exception as e:
                print(f"Error exploiting firmware: {e}")
                return f"Error exploiting firmware: {e}"
        else:
            return "Firmware not found."

    def listen_for_terminal_commands(self):
        print("Lex D. Monkey is listening for terminal commands...")
        while True:
            command = input("You: ").strip().lower()
            if command in ["exit", "quit"]:
                print("Exiting...")
                break
            response = self.process_command(command)
            print("Lex D. Monkey:", response)

if __name__ == "__main__":
    lex_ai = LexDMonkeyAI()
    print("Lex D. Monkey Ready! Listening for terminal commands...")
    lex_ai.listen_for_terminal_commands()
