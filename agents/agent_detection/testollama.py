import ollama

response = ollama.chat(
    model='llama3',
    messages=[{'role': 'user', 'content': "Donne-moi l'âge de Marc (25 ans) en JSON"}],
    format='json',
    options={'temperature': 0} # 0 pour être le plus précis possible
)
print(response['message']['content'])