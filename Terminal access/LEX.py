import os
import requests
from sklearn.cluster import KMeans
import numpy as np
from newspaper import Article

class LexDMonkeyAI:
    def __init__(self):
        self.memory_index = KMeans(n_clusters=5, random_state=42)
        self.web_data = []
        self.topic = None
    
    def fetch_web_data(self, topic):
        self.topic = topic
        print(f"Searching for: {self.topic}")
        
        # Example URLs (replace these with real URLs related to the topic)
        urls = [
            f"https://example.com/{self.topic}",
            f"https://developer.android.com/{self.topic}",
            f"https://geeksforgeeks.org/{self.topic}",
            f"https://en.wikipedia.org/wiki/{self.topic}",
            f"https://roadmap.sh/{self.topic}"
        ]

        articles = []
        for url in urls:
            try:
                article = Article(url)
                article.download()
                article.parse()
                articles.append(article.text)
                print(f"Fetched article from {url}")
            except Exception as e:
                print(f"Failed to fetch article from {url}: {e}")

        self.process_web_data(articles)

    def parse_article(self, article):
        """
        Dummy parsing logic; replace with real processing of articles.
        Example: extracting meaningful features like text length and keyword count.
        """
        # For now, we are creating dummy vectors just for illustration.
        return np.array([len(article), article.count("a")])

    def process_web_data(self, articles):
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

            try:
                self.memory_index.fit(knowledge_vectors)
                print("KMeans fitting complete.")
            except ValueError as e:
                print(f"Error fitting KMeans: {e}")
        else:
            print("No knowledge vectors found. Web data processing failed.")
    
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
            else:
                print("Unrecognized command.")

    def evolve(self):
        """
        Logic for LexDMonkey to evolve itself over time.
        Involves dynamically learning from its experiences.
        """
        print("LexDMonkey is evolving...")
        # Example logic to simulate evolution (you can replace with actual algorithms)
        # In a more advanced system, LexDMonkey could improve itself by adjusting parameters
        self.memory_index = KMeans(n_clusters=10, random_state=42)  # Simulating self-improvement
        print("LexDMonkey's memory index has evolved.")

if __name__ == "__main__":
    lex_ai = LexDMonkeyAI()
    
    # Main loop to listen for terminal commands and process them
    lex_ai.listen_for_terminal_commands()
