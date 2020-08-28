# minitrue


This is a project whose main functionality is to have the entire network monitored. A ping-based scan is performed using nmap to check for new computers on the network. Each of the computers on the network is registered in a local database, which it uses to check for new computers. If new equipment is detected, it will send a notification with a telegram bot to the administrator to indicate that a new host has been detected.


It is being designed to be easily extensible through plugins, as it may allow to enhance an advanced scan with nmap or OpenVas.


![minitrue][minitrue]

[minitrue]: resources/images/bot_scan_networks.svg


bot telegram:

![tg][tg]

[tg]: resources/images/tg.png

# Installation


The Python 3 libraries that are necessary to run the project can be installed with:

```bash
pip3 install -r requirements.txt --user
```

It is also necessary to install certain utilities in Linux, these can be installed as:

```bash
sudo apt install nmap texlive-latex-recommended texlive-latex-extra

# or

sudo dnf install nmap texlive-latex-recommended texlive-latex-extra texlive-datetime
```


# Basic Usage



```bash
python3 bot_scan.py
```


# Functionality


- Management through a Telegram bot
- Periodic automatic network scans
- Manufacturer information for each MAC
- Generation of a PDF report with information from the network
- Information stored in a SQLITE database
- IP Scanning using nmap


# Pending

- [ ] Generar pdf se tiene que lanzar en un hilo con la instancia de bot, para que genere el pdf tranquilamente sin bloquear el bot
- [ ] Implementar para IPv6
- [x] EN el \_\_init\_\_ si la BD no existe crearla con la estrucutra basica
- [x] nmap con mas info a una o varias IP
- [ ] Implementar escaneos con OpenVas
- [ ] Hacer un MITM, obtener mac del router (ip route) mac spoffing
- [ ] Capturar trafico tshark, tcpdump, etc
- [ ] PyTaskIO puede ser interesante para cola de tareas de los procesos en ejecucion
- [ ] Usar un contenedor docker para la compilacion de latex
- [ ] Investigar si añadir funcionalidad con docker (openvas)
- [ ] Escaneos automaticas AP con visibilidad??
- [ ] Escaneo dispositivos bluetooh visibles
- [ ] Repaso bot proxmox usando bot scan network

