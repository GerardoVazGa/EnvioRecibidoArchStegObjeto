import socket
import os
import subprocess
import time
import tkinter as tk
from tkinter import messagebox

DELIMITADOR = "---INYECCION---"

#[5]
def generarRSA(nombreCarpeta):
    if not os.path.exists(nombreCarpeta):
        os.makedirs(nombreCarpeta)
    
    rutaLlavePriv = os.path.join(nombreCarpeta, "privateKEY")

    cmdPrivateKey = ['openssl', 'genrsa', '-out', rutaLlavePriv]
    subprocess.run(cmdPrivateKey, check=True)

    rutaLlavePubli = os.path.join(nombreCarpeta, "publicKey.pem")

    cmdPublicKey = ['openssl', 'rsa', '-in', rutaLlavePriv, '-outform', 'PEM', '-pubout', '-out', rutaLlavePubli]
    subprocess.run(cmdPublicKey, check=True)

    print(f"La llave pública y privada se generaron de manera correcta en la carpeta: {rutaLlavePriv}")

#[3]
def conexionServer(host, port, nombreCarpeta):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        enviarLlave(s, nombreCarpeta)
        recibirHash(nombreCarpeta, s)
        recibirStegObj(nombreCarpeta, s)
        procesoEliminacion(nombreCarpeta, s)
        hola()

def hola():
    print("Hola mundo")

#[4]
def enviarLlave(s, nombreCarpeta):
    
    #[5]
    generarRSA(nombreCarpeta)

    rutaLlavePublic = os.path.join(nombreCarpeta, "publicKey.pem")

    with open(rutaLlavePublic, "rb") as fileKEYPublic:
        keyPubData = fileKEYPublic.read()
        keyPubSize = len(keyPubData)
        s.sendall(keyPubSize.to_bytes(4, 'big'))
        s.sendall(keyPubData)
    
#[6]
def recibirHash(nombreCarpeta, s):
    hash384rec = s.recv(4)
    hash384size = int.from_bytes(hash384rec, "big")

    hash384Info = s.recv(hash384size)

    with open(os.path.join(nombreCarpeta, "hash384.txt"), "wb") as hash384recive:
        hash384recive.write(hash384Info)
    
    messagebox.showinfo("Envío Hash384", "Hash guardado en hash384.txt")
    time.sleep(3)

    hash512rec = s.recv(4)
    hash512size = int.from_bytes(hash512rec, "big")

    hash512Info = s.recv(hash512size)

    with open(os.path.join(nombreCarpeta, "hash512.txt"), "wb") as hash512recive:
        hash512recive.write(hash512Info)
    
    messagebox.showinfo("Envío Hash384", "Hash guardado en hash512.txt")
    time.sleep(3)

    hashB2rec = s.recv(4)
    hashB2size = int.from_bytes(hashB2rec, "big")

    hashB2Info = s.recv(hashB2size)

    with open(os.path.join(nombreCarpeta, "hashBlake2.txt"), "wb") as hashB2recive:
        hashB2recive.write(hashB2Info)

    messagebox.showinfo("Envío Hash384", "Hash guardado en  hashBlake2.txt")
    time.sleep(3)

#[7]
def recibirStegObj(nombreCarpeta, s):

    try:
        fileNameSize = int.from_bytes(s.recv(4), 'big')
        global filename
        filename = s.recv(fileNameSize).decode('utf-8')

        print(f"[*] Recibiendo {filename}")

        with open(os.path.join(nombreCarpeta, filename), 'wb') as f:
            while True:
                data = s.recv(4096)
                if not data:
                    break

                f.write(data)
                print("Se recibieron {} bytes".format(len(data)))

            messagebox.showinfo("Archivo recibido", "se recibio el archivo")
            time.sleep(3)
        
    except FileNotFoundError:
        print(f"Error: el archivo '{filename}' no se encontró.")
    except Exception as e:
        print(f"Error al enviar el archivo: {e}")

#[8]
def procesoEliminacion(nombreCarpeta, s):
    rutaStegObj = os.path.join(nombreCarpeta, filename)
    rutaEncryp = os.path.join(nombreCarpeta, "archivo_inyectado")
    rutaLlave = os.path.join(nombreCarpeta, "privateKEY")
    rutaDecrypt = os.path.join(nombreCarpeta, "archivo_desencriptado")
    rutaArchivoSep = os.path.join(nombreCarpeta, "archivo_original")

    cmdBlake2 = ['b2sum', rutaStegObj]
    cmd512 = ['sha512sum', rutaEncryp]
    cmd384 = ['sha384sum', rutaDecrypt]
    cmdRmStegObj = ['rm', rutaStegObj]
    cmdRmArchivoCubridor = ['rm', rutaArchivoSep]
    
    try:
        #[9]
        resultado = subprocess.run(cmdBlake2, check=True, capture_output=True, text=True)
        hashBlake = resultado.stdout.split()[0]

        
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar b2sum: {e.stderr}")

    #[10]
    hashb2correcto = compararHashBlake(nombreCarpeta, hashBlake)
    
    #[11]
    if hashb2correcto:
        #[12]
        separarInyectado(rutaStegObj, nombreCarpeta)
        subprocess.run(cmdRmStegObj, check=True)
        subprocess.run(cmdRmArchivoCubridor, check=True)

        #[13]
        resHash512 = subprocess.run(cmd512, check=True, capture_output=True, text=True)
        hash512sum = resHash512.stdout.split()[0]
        print(hash512sum)

        #[14]
        hash512correcto = compararHash512(nombreCarpeta, hash512sum)

        #[15]
        if hash512correcto:
            cmdDecrypt = ['openssl', 'pkeyutl', '-decrypt','-inkey', rutaLlave,'-in', rutaEncryp, '-out', rutaDecrypt]
            try:
                subprocess.run(cmdDecrypt, check=True)
                messagebox.showinfo("Desencriptación", "Archivo desencriptado correctamente")

            except Exception as e:
                print(f"Error al ejecutar openssl pkeyutl -decrypt: {e.stderr}")

            #[16]
            try:
                resHash384 = subprocess.run(cmd384, check=True, capture_output=True, text=True)
                hash384sum = resHash384.stdout.split()[0]
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar sha384sum: {e.stderr}")
                return
            
            #[17]
            hash384correcto = compararHash384(nombreCarpeta, hash384sum)

            #[18]
            if hash384correcto:
                messagebox.showinfo("Correcto", f"El archivo {os.path.basename(rutaDecrypt)} se recibio de manera correcta\nEn la ruta {rutaDecrypt}")
            else:
                cmdRmDecrypt = ['rm', rutaDecrypt]
                subprocess.run(cmdRmDecrypt, check=True)
                messagebox.showinfo("Eliminacion", f"Eliminacion del archivo {rutaDecrypt} por alteracion")

        else:
            print("el hash cambio por completo")
            cmdRmEncrypt = ['rm', rutaEncryp]
            subprocess.run(cmdRmEncrypt, check=True)
            messagebox.showinfo("Eliminacion", f"Eliminacion del archivo {rutaEncryp} por alteracion")

    else:
        subprocess.run(cmdRmStegObj, check=True)
        messagebox.showinfo("Eliminacion", f"Eliminacion del archivo {filename} por alteracion")

#[12]
def separarInyectado(archivo, nombreCarpeta):
    print(f"ruta: {archivo}")
    with open(archivo, "rb") as f:
        contenido = f.read()

    indice_delimitador = contenido.find(DELIMITADOR.encode())
    if indice_delimitador == -1:
        print("Delimitador no encontrado.")
        return

    original = contenido[:indice_delimitador]
    inyectado = contenido[indice_delimitador + len(DELIMITADOR):]

    # Guardar los archivos separados
    archivoOriginal = os.path.join(nombreCarpeta, "archivo_original")
    archivoInyectadoSeparado = os.path.join(nombreCarpeta, "archivo_inyectado")

    with open(archivoOriginal, "wb") as f:
        f.write(original)

    with open(archivoInyectadoSeparado, "wb") as f:
        f.write(inyectado)

    print("Archivos separados guardados en:", nombreCarpeta)

#[10]
def compararHashBlake(rutaCarpeta, hashB2Arch):
    
    try:
        with open(os.path.join(rutaCarpeta, "hashBlake2.txt"), 'r') as f:
            hashB2 = f.read().strip()
        return hashB2Arch == hashB2
    except Exception as e:
        print("Error de lectura")
        return False
    
#[14]
def compararHash512(rutaCarpeta, hash512Arch):
    try:
        with open(os.path.join(rutaCarpeta, "hash512.txt"), 'r') as f:
            hash512 = f.read().strip()
        return hash512Arch == hash512
    except Exception as e:
        print("Error de lectura")
        return False

#[17]    
def compararHash384(rutaCarpeta, hash384Arch):
    
    try:
        with open(os.path.join(rutaCarpeta, "hash384.txt"), 'r') as f:
            hash384 = f.read().strip()
        return hash384Arch == hash384
    except Exception as e:
        print("Error de lectura: {e}")
        return False
    
#[2]
def iniciarConexion():
    nombreCarpeta = "proyecto"
    if not os.path.exists(nombreCarpeta):
        os.makedirs(nombreCarpeta)
    host = entryIP.get()  
    port = 443 
    conexionServer(host, port, nombreCarpeta)
    
#[1]
ventanaInicio = tk.Tk() 
ventanaInicio.title("Maquina B")

lblIpServ = tk.Label(ventanaInicio, text="Ingresa la IP del servidor")
lblIpServ.pack(pady=20)

entryIP = tk.Entry(ventanaInicio)
entryIP.pack(padx=40, pady=20)

btnConect = tk.Button(ventanaInicio, text="Inciar conexion", command=iniciarConexion)
btnConect.pack(padx=40, pady=20)

ventanaInicio.mainloop()


