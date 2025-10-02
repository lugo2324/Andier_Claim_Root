# Andier_Claim_Root
Herramienta orientada a la seguridad de redes, con propósitos  de auditar las redes vulnerabless a ataques BPDUs  y mala configuraciones de STP.

EXPLICACIÓN COMPLETA DEL CÓDIGO
STP (Spanning Tree Protocol) es un protocolo que previene loops en redes con switches. Los switches intercambian mensajes llamados BPDUs para elegir un "switch raíz" (root bridge).
El ataque Claim Root consiste en:

Enviar BPDUs falsos con prioridad más baja (valores más bajos = mayor prioridad)
Hacer que tu máquina se convierta en el root bridge
Esto te permite interceptar tráfico o causar problemas en la red.




COMANDOS Y OPCIONES DISPONIBLES

sudo apt-get update -y

sudo apt-get install scapy -y

sudo python3 stp.py -i <interfaz> [opciones]


EJEMPLOS PRÁCTICOS CON EXPLICACIONES


Ataque básico con prioridad máxima

sudo python3 stp.py -i eth0 -p 0

Explicación:

Usa la interfaz eth0
Prioridad 0 (la más alta posible)
Envía BPDUs continuamente cada 2 segundos
Efecto: Tu máquina intentará convertirse en root bridge'


Ataque rápido y agresivo

sudo python3 stp.py -i eth0 -p 0 -t 0.5 -v

Explicación:

Prioridad 0
Intervalo de 0.5 segundos (mucho más rápido)
Modo verbose (muestra cada paquete enviado)
Efecto: Inunda la red con BPDUs rápidamente

 Envío controlado (100 paquetes)
bashsudo python3 stp.py -i eth0 -p 4096 -c 100
Explicación:

Prioridad 4096 (segunda mejor)
Envía exactamente 100 BPDUs y termina
Útil para pruebas controladas


Ver el paquete sin enviarlo
bashsudo python3 stp.py -i eth0 --show-packet
Explicación:

Muestra la estructura completa del BPDU
NO envía nada
Útil para verificar que el paquete esté bien formado


Configuración avanzada completa
bashsudo python3 stp.py -i eth0 -p 0 --cost 0 --hello 1 --max-age 10 --forward-delay 8 -t 1.0 -v
Explicación:

Prioridad 0
Root path cost 0 (directamente conectado)
Hello time de 1 segundo (más agresivo)
Max age de 10 segundos
Forward delay de 8 segundos
Intervalo de 1 segundo con verbose

