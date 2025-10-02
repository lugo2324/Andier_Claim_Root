# Andier_Claim_Root
herramienta orientada a la seguridad de redes, con propósitos  de auditar las redes vulnerabilidades  a ataques BPDUs  y mala configuraciones.

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


