import requests
import os
import threading
import time
from datetime import datetime
from queue import Queue

os.system('figlet Hacking')
time.sleep(1)
os.system('figlet Euliveira')
time.sleep(3)

print("""
••••••••••••••••••••••••••••••••••••••••••••••
   WILLIAN DE OLIVEIRA
  Cibersegurança Ofensivo
•••••••••••••••••••••••••••••••••••••••••••••""")
time.sleep(1)

time.sleep(1)
print('Conectando...')
time.sleep(1)
print(""" 20% ••""")
time.sleep(1)
print(""" 40% ••••""")
time.sleep(1)
print(""" 60% ••••••""")
time.sleep(1)
print(""" 80% ••••••••""")
time.sleep(1)
print(""" 100% ••••••••••""")
time.sleep(1)
print(""" Pronto para uso""")
time.sleep(2)

print('Conexao bem sucedida')
time.sleep(1)


# --- DICIONÁRIO TÉCNICO DE RELATÓRIO (HackerOne Style) ---
VULN_DETAILS = {
    "SQLi": {
        "titulo": "SQL Injection (SQLi)",
        "remediacao": "Utilize Prepared Statements e parametrização de consultas para impedir a manipulação do banco de dados."
    },
    "XSS": {
        "titulo": "Cross-Site Scripting (XSS)",
        "remediacao": "Implemente Sanitização de Output (HTML Entity Encoding) e Headers de segurança como Content-Security-Policy (CSP)."
    },
    "RCE": {
        "titulo": "Remote Code Execution (RCE)",
        "remediacao": "Evite o uso de funções que executam comandos de sistema (como eval, exec ou system) com inputs do usuário."
    }
}

class OffensiveEngine:
    def __init__(self, target_url, threads=10):
        self.target_url = target_url
        self.threads = threads
        self.queue = Queue()
        self.lock = threading.Lock()
        self.resultados = []

    def carregar_wordlist(self, arquivo_path, categoria):
        """Lê arquivos externos (ex: SecLists) e coloca na fila de processamento."""
        if os.path.exists(arquivo_path):
            with open(arquivo_path, 'r', encoding='utf-8', errors='ignore') as f:
                count = 0
                for line in f:
                    payload = line.strip()
                    if payload:
                        self.queue.put((payload, categoria))
                        count += 1
            print(f"📂 [CARGA] {count} payloads de {categoria} carregados com sucesso.")
        else:
            print(f"⚠️ [ERRO] Arquivo não encontrado: {arquivo_path}")

    def worker(self):
        """Thread worker para processar a fila."""
        while not self.queue.empty():
            try:
                payload, categoria = self.queue.get()
                self.disparar_teste(payload, categoria)
                self.queue.task_done()
            except:
                break

    def disparar_teste(self, payload, categoria):
        """Executa a requisição e valida se houve sucesso na exploração."""
        try:
            headers = {"User-Agent": "NeuralKore-Bounty-Researcher/1.0"}
            # Injeta o payload em múltiplos parâmetros comuns
            params = {'id': payload, 'user': payload, 'query': payload, 'search': payload}
            
            resp = requests.get(self.target_url, params=params, headers=headers, timeout=5)

            vulneravel = False
            # Lógica de Confirmação de Falha
            if categoria == "SQLi" and ("sql syntax" in resp.text.lower() or resp.status_code == 500):
                vulneravel = True
            elif categoria == "XSS" and payload in resp.text:
                vulneravel = True
            elif categoria == "RCE" and ("root:" in resp.text or "uid=" in resp.text):
                vulneravel = True

            if vulneravel:
                with self.lock:
                    print(f"🎯 [FALHA CONFIRMADA] {categoria} -> Payload: {payload}")
                    self.registrar(payload, categoria)
        except:
            pass

    def registrar(self, payload, categoria):
        """Prepara os dados para o relatório Markdown."""
        data = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        info = VULN_DETAILS.get(categoria, {})
        relatorio = (
            f"## 🚩 {info['titulo']} Identificado\n"
            f"- **Alvo:** {self.target_url}\n"
            f"- **Data do Achado:** {data}\n"
            f"- **PoC (Payload):** `{payload}`\n"
            f"- **Sugestão de Correção:** {info['remediacao']}\n\n"
            f"---\n"
        )
        self.resultados.append(relatorio)

    def iniciar(self):
        print(f"\n🚀 Iniciando scan em {self.target_url} com {self.threads} threads...")
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads_list.append(t)
        
        for t in threads_list:
            t.join()
            
        self.salvar_relatorio()

    def salvar_relatorio(self):
        if self.resultados:
            nome_arq = "Relatorio_HackerOne.md"
            with open(nome_arq, "w", encoding="utf-8") as f:
                f.write("# Relatório de Segurança - NeuralKore Offensive\n\n")
                f.writelines(self.resultados)
            print(f"\n✅ Scan concluído! Relatório gerado: {nome_arq}")
        else:
            print("\n✅ Scan finalizado. Nenhuma vulnerabilidade óbvia detectada.")

# --- INTERFACE DE ENTRADA (INPUT) ---
if __name__ == "__main__":
    
print("========================================")
    print("   NEURALKORE OFFENSIVE ENGINE v1.0")
    print("========================================")

    url = input("🎯 URL do Alvo (ex: http://site.com/prod.php): ")
    threads = int(input("🧵 Número de Threads (ex: 20): "))
    
    scanner = OffensiveEngine(url, threads)

    print("\n[Wordlists - Deixe em branco para pular]")
    sqli_path = input("📄 Caminho da lista SQLi: ")
    if sqli_path: scanner.carregar_wordlist(sqli_path, "SQLi")
    
    xss_path = input("📄 Caminho da lista XSS: ")
    if xss_path: scanner.carregar_wordlist(xss_path, "XSS")

    if not scanner.queue.empty():
        scanner.iniciar()
    else:
        print("\n❌ Nenhuma carga de teste foi fornecida.")
