import os
import requests
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# --- CAMADA DE INFRAESTRUTURA ---
def get_cred(file):
    """Lê tokens conforme a regra de arquivos separados."""
    if os.path.exists(file):
        with open(file, "r") as f:
            return f.read().strip()
    return None

# --- CAMADA DE INTELIGÊNCIA ARTIFICIAL ---
class NeuralKoreWAF:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(2, 5), analyzer='char')
        self.clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
        self.le = LabelEncoder()
        self.model_file = "cyber_model.pkl"

    def inicializar(self, csv_path=None):
        if os.path.exists(self.model_file):
            print("📦 [SISTEMA] Carregando inteligência pré-treinada...")
            self.clf, self.vectorizer, self.le = joblib.load(self.model_file)
        else:
            print("🧠 [SISTEMA] Treinando nova rede neural defensiva...")
            df = pd.read_csv(csv_path) if csv_path else self._dados_base()
            y = self.le.fit_transform(df['label'])
            X = self.vectorizer.fit_transform(df['payload'])
            self.clf.fit(X, y)
            joblib.dump((self.clf, self.vectorizer, self.le), self.model_file)
            print("💾 [SISTEMA] Modelo salvo para inicialização rápida.")

    def _dados_base(self):
        # Dataset inicial para garantir que o sistema suba sem erros
        data = [
            ("index.php?id=1", "Safe"), ("/home", "Safe"),
            ("' OR 1=1 --", "SQLi"), ("<script>alert(1)</script>", "XSS"),
            ("; whoami", "RCE"), ("../../etc/passwd", "PathTraversal"),
            ("?url=http://169.254.169.254", "SSRF")
        ]
        return pd.DataFrame(data, columns=['payload', 'label'])

# --- CAMADA DE COMUNICAÇÃO E RESPOSTA ---
def enviar_alerta_telegram(mensagem):
    token = get_cred("TELEGRAM_TOKEN.txt")
    chat_id = get_cred("TELEGRAM_CHATID.txt")
    
    if not token or not chat_id:
        print("⚠️ [ERRO] Arquivos de token/ID não encontrados. Alerta via Telegram abortado.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": mensagem, "parse_mode": "Markdown"}
    
    try:
        response = requests.post(url, data=payload, timeout=10)
        if response.status_code != 200:
            print(f"❌ Erro na API do Telegram: {response.text}")
    except Exception as e:
        print(f"❌ Falha de conexão ao enviar alerta: {e}")

def logs_auditoria(evento):
    with open("audit_firewall.log", "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {evento}\n")

# --- ENGINE DE INTERCEPTAÇÃO ---
waf = NeuralKoreWAF()
waf.inicializar()

def processar_requisicao(payload, ip_cliente):
    # 1. Filtro de Reputação (Blacklist de IPs Proxy/Suspeitos)
    IP_BLACKLIST = ["45.77.12.34", "104.248.10.12"] 
    
    if ip_cliente in IP_BLACKLIST:
        aviso = f"🚫 *BLOQUEIO POR REPUTAÇÃO*\nIP: `{ip_cliente}`\nStatus: Conexão encerrada."
        print(f"🚩 Bloqueado IP Suspeito: {ip_cliente}")
        logs_auditoria(f"IP_BLACKLIST_BLOCK: {ip_cliente}")
        enviar_alerta_telegram(aviso)
        return False

    # 2. Análise de Payload via Machine Learning
    X_input = waf.vectorizer.transform([payload])
    probabilidades = waf.clf.predict_proba(X_input)[0]
    classe_id = np.argmax(probabilidades)
    confianca = probabilidades[classe_id] * 100
    categoria = waf.le.inverse_transform([classe_id])[0]

    # 3. Decisão Defensiva
    if categoria != "Safe" and confianca > 45:
        alerta_msg = (
            f"⚔️ *INCIDENTE DE CIBERSEGURANÇA*\n\n"
            f"🔹 *Tipo:* `{categoria}`\n"
            f"🔹 *Confiança:* `{confianca:.2f}%`\n"
            f"🔹 *Origem:* `{ip_cliente}`\n"
            f"🔹 *Payload:* `{payload}`\n\n"
            f"🛡️ _Ação: Requisição bloqueada pelo NeuralKore._"
        )
        print(f"🔥 ATAQUE DETECTADO: {categoria} de {ip_cliente}")
        logs_auditoria(f"ATAQUE_{categoria}: {payload} | IP: {ip_cliente} | Conf: {confianca:.2f}%")
        enviar_alerta_telegram(alerta_msg)
        return False
    
    print(f"✅ Requisição Limpa: {ip_cliente}")
    return True

# --- TESTES DE INCIDENTES ---
if __name__ == "__main__":
    print("🛰️  NeuralKore-WAF Online - Monitorando Tráfego...\n")
    
    # Simulação 1: SQL Injection
    processar_requisicao("' UNION SELECT password FROM users--", "187.45.10.22")
    
    # Simulação 2: IP em Blacklist
    processar_requisicao("index.html", "45.77.12.34")
    
    # Simulação 3: Tráfego legítimo
    processar_requisicao("/api/v1/get_status", "200.10.20.30")
