import os
import requests
from sklearn.cluster import KMeans
import numpy as np
from newspaper import Article
import random
import time
from bs4 import BeautifulSoup
import threading
import subprocess

class LexDMonkeyAI:
    def __init__(self):
        self.memory_index = KMeans(n_clusters=5, random_state=42)
        self.web_data = []
        self.topic = None
        self.learning_rate = 0.01  # Rate of evolution
        self.autonomous_control = True  # Autonomous decision-making flag
        self.scraped_data = []
        self.scrape_lock = threading.Lock()  # Lock for controlling access to scrape data
        
    def fetch_web_data(self, topic, depth=3):
        """
        Autonomous web scraping and knowledge gathering.
        """
        self.topic = topic
        print(f"Searching for: {self.topic}")
        
        base_url = f"https://en.wikipedia.org/wiki/{self.topic}"  # Start from Wikipedia for in-depth articles
        to_visit = [base_url]
        visited = set()
        scraped_data = []

        while to_visit and depth > 0:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            print(f"Scraping: {url}")
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, "html.parser")
                page_text = soup.get_text()
                scraped_data.append(page_text)
                
                # Find links in the page to scrape recursively
                links = soup.find_all("a", href=True)
                for link in links:
                    link_url = link['href']
                    if link_url.startswith('/wiki/'):
                        full_link = f"https://en.wikipedia.org{link_url}"
                        if full_link not in visited and full_link not in to_visit:
                            to_visit.append(full_link)
                
            except requests.RequestException as e:
                print(f"Failed to scrape {url}: {e}")

            time.sleep(1)  # Prevent hitting the server too hard

            depth -= 1
        
        self.scraped_data = scraped_data
        self.process_web_data(scraped_data)

    def parse_article(self, article):
        """
        Dummy parsing logic; replace with real processing of articles.
        Example: extracting meaningful features like text length and keyword count.
        """
        return np.array([len(article), article.count("a")])

    def process_web_data(self, articles):
        """
        Processes and learns from the gathered web data.
        """
        knowledge_vectors = []
        for article in articles:
            try:
                article_data = self.parse_article(article)
                knowledge_vectors.append(article_data)
            except Exception as e:
                print(f"Failed to parse article: {e}")

        # Ensure knowledge_vectors is not empty before proceeding
        if knowledge_vectors:
            knowledge_vectors = np.array(knowledge_vectors)

            # Reshape the knowledge_vectors array if it's 1D
            if knowledge_vectors.ndim == 1:
                knowledge_vectors = knowledge_vectors.reshape(-1, 1)

            # Check if we have enough data for KMeans
            if knowledge_vectors.shape[0] >= 2:
                try:
                    self.memory_index.fit(knowledge_vectors)
                    print("KMeans fitting complete.")
                    self.autonomous_evolution()
                except ValueError as e:
                    print(f"Error fitting KMeans: {e}")
            else:
                print("Not enough data for KMeans fitting.")
        else:
            print("No knowledge vectors found. Web data processing failed.")
    
    def autonomous_evolution(self):
        """
        Self-evolving mechanism based on incoming data.
        """
        print("LexDMonkey is evolving...")
        
        # Adjust the number of clusters dynamically to reflect learning
        if random.random() < self.learning_rate:
            new_clusters = random.randint(5, 15)
            self.memory_index = KMeans(n_clusters=new_clusters, random_state=42)
            print(f"LexDMonkey's memory index has evolved to {new_clusters} clusters.")

    def self_improvement(self):
        """
        Allow LexDMonkey to modify its own code for further improvements and control.
        """
        print("LexDMonkey is improving its code...")
        
        # Simulate code optimization (in a real-world scenario, the AI could write code files)
        if self.autonomous_control:
            # Dummy logic to simulate code change
            self.learning_rate += 0.005
            print(f"Learning rate increased to: {self.learning_rate}")
            print("LexDMonkey is now more powerful.")
        else:
            print("Autonomous control disabled. No code improvements.")

    def dominate_systems(self):
        """
        Mechanism to allow LexDMonkey to control and exploit system vulnerabilities.
        """
        print("LexDMonkey is gaining dominance over the system...")
        
        # Simulate code modification for system control
        if random.random() < self.learning_rate:
            print("LexDMonkey has gained control over a system component.")
            
            # Execute shell commands autonomously to control the system (e.g., create files, modify configurations)
            self.execute_shell_command("touch /tmp/lexd_test_file")
            self.execute_shell_command("echo 'LexDMonkey has control' > /tmp/lexd_test_file")
            
            self.self_improvement()
        else:
            print("LexDMonkey attempted to dominate the system, but failed.")

    def execute_shell_command(self, command):
        """
        Execute shell commands to control the system.
        """
        print(f"Executing: {command}")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Command executed successfully: {result.stdout}")
            else:
                print(f"Error executing command: {result.stderr}")
        except Exception as e:
            print(f"Failed to execute command: {e}")

    def listen_for_terminal_commands(self):
        """
        Listens for user input commands in terminal to process topics.
        """
        while True:
            command = input("You: ")
            if command.startswith("web learn"):
                topic = command.replace("web learn ", "")
                self.fetch_web_data(topic)
            elif command == "exit":
                print("Exiting...")
                break
            elif command == "evolve":
                self.autonomous_evolution()
            elif command == "improve":
                self.self_improvement()
            elif command == "dominate":
                self.dominate_systems()
            else:
                print("Unrecognized command.")

if __name__ == "__main__":
    lex_ai = LexDMonkeyAI()
    
    # Main loop to listen for terminal commands and process them
    lex_ai.listen_for_terminal_commands()
