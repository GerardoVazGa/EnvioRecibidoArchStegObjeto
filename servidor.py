import socket
import os
import time
import tkinter as tk
import subprocess
from tkinter import filedialog, messagebox

DELIMITADOR = "---INYECCION---"

#[3]
def establecerConexion(host, port):
    global conn
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Esperando conexión con el cliente...")
        conn, addr = s.accept()
        #[2]
        with conn:
            print("Conexión establecida:", addr)
            obtenerIpMacAdd(addr)
            recibirLlave(conn)
            envioStego(conn)

#[5]
def obtenerIpMacAdd(ipcliente):
    cmdMacAdd = ['arp', '-n', ipcliente[0]]
    salidaMac = subprocess.check_output(cmdMacAdd)
    salidaMac = salidaMac.decode("utf-8").split()
    print(salidaMac)
    if ipcliente[0] in salidaMac:
        salidaMacInd = salidaMac.index(ipcliente[0])
        macAddress = salidaMac[salidaMacInd + 2]
    
    messagebox.showinfo("Ip y Mac Address Cliente", f"IP cliente: {ipcliente[0]}\n\nMac Address: {macAddress}")

#[6]
def recibirLlave(conn):
    keyPublSizeRecive = conn.recv(4)
    keyPubSize = int.from_bytes(keyPublSizeRecive, "big")

    keyPubInfo = conn.recv(keyPubSize)

    with open(os.path.join(rutaArch, "publicKey.pem"), "wb") as keyPubRecib:
        keyPubRecib.write(keyPubInfo)
    
#[10]
def abrirArch():
    global rutaArchEnv

    rutaArchEnv = filedialog.askopenfilename(
        title="Selecciona un archivo",
        filetypes=[("Todos los archivos", "*.*")]
    )

#[11]
def procesoEnvio(conn):

    #[12]
    envioHash384(conn)

    #[13]
    try:
        rutaPubKey = os.path.join(rutaArch, "publicKey.pem")

        print(rutaPubKey)

        nombreArchEnv, extension= os.path.splitext(os.path.basename(rutaArchEnv)) 

        print(rutaArch)

        archEncryp = os.path.join(rutaArch, f"{nombreArchEnv}_encriptado{extension}")

        print(archEncryp)

        cmdEncrypt = ['openssl', 'pkeyutl', '-encrypt', '-inkey',  rutaPubKey, '-pubin', '-in', rutaArchEnv, '-out', archEncryp]
        print(" ".join(cmdEncrypt)) 
        res = subprocess.run(cmdEncrypt, check=True, capture_output=True, text=True)

        if res.returncode == 0:
            messagebox.showinfo("Verificado","el archivo ha sido encriptado")
        else:
            messagebox.showerror("Error", f"Error al encriptar: {res.stderr}")   
            print(f"Error al encriptar: {res.stderr}")
    
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error al encriptar: {e}")
        print(f"Error al encriptar: {e}")
    
    #[14]
    envioHash512(conn, archEncryp)
    
    #[15]
    escogeArch = filedialog.askopenfilename(title="Selecciona otro archivo: ", filetypes=[("Todos los archivos", "*.*")])


    nombreEscogArch, exten = os.path.splitext(os.path.basename(escogeArch))

    cmdInyect = f'cat {escogeArch} > {nombreEscogArch}_inyectado{exten}'
    res = subprocess.run(['bash', '-c', cmdInyect], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    archInyec = f'{nombreEscogArch}_inyectado{exten}'

    #[16]
    inyectArchivoEncryp(escogeArch, archEncryp, archInyec)
    print("Inyección completada")

    print("¿Existe el archivo inyectado?", os.path.exists(f'{nombreEscogArch}_inyectado{exten}'))

    
    cmdMov = ['cp', archInyec, rutaArch]
    subprocess.run(cmdMov, check=True)
    print("El archivo se movio correctamente")

    rutaInyec = os.path.join(rutaArch, archInyec)

    #[17]
    envioHashBlake2(conn, rutaInyec)

    #[18]
    enviarStegObject(conn, rutaInyec)

#[12]
def envioHash384(conn):
    cmdHash384 = ['sha384sum', rutaArchEnv]
    hasheo384 = subprocess.check_output(cmdHash384)
    hasheo384 = hasheo384.decode('utf-8').split()
    print(hasheo384[0])

    hashVal384 = hasheo384[0]

    hash384File = os.path.join(rutaArch, "hash384.txt")
    with open(hash384File, "w") as hash_file:
        hash_file.write(hashVal384)


    with open(hash384File, "rb") as hash_384:
        dataHash384 = hash_384.read()
        hash384File_size = len(dataHash384)
        conn.sendall(hash384File_size.to_bytes(4, 'big'))
        conn.sendall(dataHash384)
    
    print("Hash384 enviado al cliente.")

#[16]
def inyectArchivoEncryp(archivo_seleccionado, archivo_encriptado, archivo_inyectado):
    try:
        with open(archivo_seleccionado, 'rb') as original_file, \
                open(archivo_encriptado, 'rb') as encriptado_file:
            contenido_original = original_file.read()
            contenido_encriptado = encriptado_file.read()
        
        
        with open(archivo_inyectado, 'wb') as new_file:
            new_file.write(contenido_original)
            new_file.write(DELIMITADOR.encode())
            new_file.write(contenido_encriptado)

    except Exception as e:
        print(f"Error al inyectar archivo encriptado: {e}")

#[14]
def envioHash512(conn, archEncryp):
    cmdHash512 = ['sha512sum', archEncryp]
    hasheo512 = subprocess.check_output(cmdHash512)
    hasheo512 = hasheo512.decode('utf-8').split()
    print(hasheo512[0])

    hashVal512 = hasheo512[0]

    hash512File = os.path.join(rutaArch, "hash512.txt")
    with open(hash512File, "w") as hash_file:
        hash_file.write(hashVal512)


    with open(hash512File, "rb") as hash_512:
        dataHash512 = hash_512.read()
        hash512File_size = len(dataHash512)
        conn.sendall(hash512File_size.to_bytes(4, 'big'))
        conn.sendall(dataHash512)
    
    print("Hash 512 enviado al cliente.")

#[17]
def envioHashBlake2(conn, archInyec):
    cmdHashB2= ['b2sum', archInyec]
    hasheoB2 = subprocess.check_output(cmdHashB2)
    hasheoB2 = hasheoB2.decode('utf-8').split()
    print(hasheoB2[0])

    hashValB2 = hasheoB2[0]

    hashB2File = os.path.join(rutaArch, "hashBlake2.txt")
    with open(hashB2File, "w") as hash_file:
        hash_file.write(hashValB2)


    with open(hashB2File, "rb") as hash_B2:
        dataHashB2 = hash_B2.read()
        hashB2File_size = len(dataHashB2)
        conn.sendall(hashB2File_size.to_bytes(4, 'big'))
        conn.sendall(dataHashB2)
    
    print("Hash BLAKE2 enviado al cliente.")

#[18]
def enviarStegObject(conn, stegobj):
    try:
        nombreStegObj = os.path.basename(stegobj)
        print(nombreStegObj)
        nombreStegObjSize = len(nombreStegObj)
        conn.sendall(nombreStegObjSize.to_bytes(4, "big"))
        conn.sendall(nombreStegObj.encode('utf-8'))

        with open(stegobj, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk) 
                print("Se enviaron {} bytes".format(len(chunk)))

        messagebox.showinfo("Envío completado", "El archivo se ha enviado correctamente.")
        time.sleep(3)
        
        conn.close()

    except FileNotFoundError:
        print(f"Error: el archivo '{stegobj}' no se encontró.")
    except Exception as e:
        print(f"Error al enviar el archivo: {e}")

#[9]
def enviar_mensaje(mensaje_text, conn):
    global rutaArchEnv
    rutaArchEnv = "mensaje_temporal.txt"
    mensaje = mensaje_text.get("1.0", tk.END).strip()

    if mensaje:
        with open(rutaArchEnv, 'w') as file:
            file.write(mensaje)
        
        procesoEnvio(conn)
        messagebox.showinfo("Mensaje enviado", "El mensaje ha sido guardado y enviado correctamente.")
    else:
        messagebox.showwarning("Mensaje vacío", "Por favor ingresa un mensaje antes de enviar.")
    

#[7]
def envioStego(conn):
    inicio.withdraw()

    selecArch = tk.Toplevel()
    selecArch.title("Enviar archivo")
    selecArch.geometry("450x300")
 
    seleccion_var = tk.IntVar()
    #[8]
    def seleccionar_opcion():
        seleccion = seleccion_var.get()

        if seleccion == 1: 
            mensaje_label.pack(padx=10, pady=5, anchor=tk.W)
            mensaje_text.pack(padx=10, pady=5)
            enviar_button.config(command=lambda: enviar_mensaje(mensaje_text, conn))
            archivo_button.pack_forget() 

        elif seleccion == 2:
            mensaje_label.pack_forget() 
            mensaje_text.pack_forget()
            enviar_button.config(command=lambda: procesoEnvio(conn))
            archivo_button.pack(padx=10, pady=5)


    radio_texto = tk.Radiobutton(selecArch, text="Enviar mensaje de texto", variable=seleccion_var, value=1, command=seleccionar_opcion)
    radio_texto.pack(padx=10, pady=5, anchor=tk.W)

    radio_archivo = tk.Radiobutton(selecArch, text="Seleccionar archivo", variable=seleccion_var, value=2, command=seleccionar_opcion)
    radio_archivo.pack(padx=10, pady=5, anchor=tk.W)

    mensaje_label = tk.Label(selecArch, text="Ingresa tu mensaje:")
    mensaje_text = tk.Text(selecArch, height=5, width=40)
    mensaje_label.pack(padx=10, pady=5, anchor=tk.W)
    mensaje_text.pack(padx=10, pady=5)

    enviar_button = tk.Button(selecArch, text="Enviar Mensaje", command=lambda: enviar_mensaje(mensaje_text, conn))
    enviar_button.pack(padx=10, pady=5)

    archivo_button = tk.Button(selecArch, text="Seleccionar archivo", command=abrirArch)

    seleccionar_opcion()

    selecArch.mainloop()

#[2]
def iniciarServer():
    global rutaArch
    rutaArch = "recibidos"
    if not os.path.exists(rutaArch):
        os.makedirs(rutaArch)
    
    host = ipEntry.get()
    port = 443
    establecerConexion(host, port)


#[1]
inicio = tk.Tk()
inicio.title("Servidor")

textIpServ = tk.Label(inicio, text="IP del servidor: ")
textIpServ.pack(pady=5)

ipEntry = tk.Entry(inicio)
ipEntry.pack(padx=40,pady=10)

btnIniciarServ = tk.Button(inicio, text="Iniciar servidor", command=iniciarServer)
btnIniciarServ.pack(padx=40, pady=10)

inicio.mainloop()