# Cibersegurança

# # 🛡️ NeuralKore-WAF (Intelligent HIDS/WAF)

**Desenvolvido por:** Willian de Oliveira  
**Certificação:** Cibersegurança Essencial pela IBSEC (Instituto Brasileiro de Cirsegurança)  
**Versão:** 1.0.0

---

## 📖 Visão Geral

O **NeuralKore-WAF** é um sistema inteligente de detecção de intrusão (HIDS) focado em inspeção de payloads em tempo real. Diferente de firewalls tradicionais baseados em assinaturas estáticas (Regex), o NeuralKore utiliza **Machine Learning** para identificar comportamentos anômalos e tentativas de exploração no tráfego web.

Este projeto foi desenhado para atuar na vanguarda da defesa, fornecendo visibilidade total sobre o atacante e gerando documentação forense instantânea.

---

## 🧠 Diferenciais Estratégicos

### 1. Detecção Baseada em Inteligência Artificial
Utiliza o algoritmo **Random Forest** com vetorização de caracteres (**TF-IDF**), permitindo que o sistema identifique:
* **Ataques conhecidos:** SQLi, XSS, RCE, LFI.
* **Zero-Days:** Identificação de padrões suspeitos mesmo em payloads nunca antes catalogados.

### 2. Análise Forense Automatizada
Ao detectar uma ameaça, o sistema não apenas alerta, mas executa o triângulo da resposta a incidentes:
* **Exposição em Tempo Real:** Detalhes do invasor (IP, Dispositivo, User-Agent) exibidos no terminal.
* **Relatórios Legíveis (.txt):** Geração automática de "fichas criminais" detalhadas para auditoria.
* **Log de Auditoria:** Registro persistente para análise post-mortem.

### 3. Fingerprinting do Invasor
O sistema captura e correlaciona metadados críticos:
* **🌐 IP de Origem:** Identificação do ponto de ataque.
* **🖥 Dispositivo e UA:** Mapeamento do ambiente do atacante.
* **🕛 Timestamp Preciso:** Cronologia exata para resposta a incidentes.

---

## 🛠️ Arquitetura Técnica



* **Linguagem:** Python 3.x
* **Engine de IA:** Scikit-Learn (Random Forest Classifier)
* **Processamento de Linguagem:** TF-IDF Vectorizer (N-grams)
* **Input Stream:** Monitoramento de logs via File Tailing (O(1) overhead)

---

## 🚀 Como Executar

1. **Ative seu ambiente virtual:**
   ```Linux
   source venv/bin/activate

---

*Focado em Segurança Defensivo e Ofensivo com Inteligência Artificial.*

## Testes de invasão:
1. SQL Injection
2. Open Redirect
3. XSS (Cross-Site Scripting)


## Instalação Rápida
1. git clone https://github.com/euliveira/hack
2. Instale as bibliotecas: `pip install -r requirements.txt'
2. Execução NeuralKore-WAF.py

## Bug Bounty ou Pentest
1. Execução openredirect.py
2. Execução sqlinjection.py
3. Execução xss.py

