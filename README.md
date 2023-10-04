# tp1-redes-file-transfer
En este trabajo práctico se implementa un File Transfer haciendo uso del protocolo de transporte UDP (User Datagram Protocol) con ciertas extensiones para que cumpla con las condiciones de un protocolo RDT (Reliable Data Transfer).

Para ver todas las opciones disponibles: 
`python3 start-server -h` o `python3 download.py -h` o `python3 upload.py -h`

Comando para correr el servidor:
`python3 start-server.py -v`

Comandos para correr los clientes:
```
# upload selective repeat
python3 upload.py -v -s test-files/image.jpg -pr sr

# upload stop and wait
python3 upload.py -v -s test-files/image.jpg

# download selective repeat
python3 download.py -v -d imagen.jpg -pr sr -n image.jpg

# download stop and wait
python3 download.py -v -d imagen.jpg -n image.jpg
```
(Los path pasados son a modo de ejemplo)

Activar packet loss:
`go run comcast.go --device=lo --packet-loss=10%`
