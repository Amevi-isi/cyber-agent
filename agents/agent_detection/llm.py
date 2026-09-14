import os
import anthropic
import ollama

class ClaudeLLM:

    def __init__(self, api_key):

        self.client = anthropic.Anthropic(api_key=api_key)

    def ask(self, prompt):

        response = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=3000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return response.content[0].text
    
class OllamaLLM:

    def __init__(self, model='llama3', max_tokens=1024, temperature=0):

        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    def ask(self, prompt):

        response = ollama.chat(
            model=self.model,
            messages=[{'role': 'user', 'content': prompt}],
            options={
                'temperature': self.temperature,  # 0 pour être le plus précis possible par défaut
                'max_tokens': self.max_tokens
            }
        )
        return response['message'].get('content', '')


def build_llm():
    """
    Factory LLM — choisit automatiquement le backend selon l'environnement :
      - ANTHROPIC_API_KEY défini → ClaudeLLM  (production)
      - sinon              → OllamaLLM  (dev, 100 % local)

    Variables d'environnement :
      ANTHROPIC_API_KEY   clé Anthropic (optionnel)
      OLLAMA_MODEL        modèle Ollama, défaut llama3.2
      LLM_MAX_TOKENS      défaut 30000
      LLM_TEMPERATURE     défaut 0.7
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        return ClaudeLLM(api_key)
    return OllamaLLM(
        model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "30000")),
        temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
    )