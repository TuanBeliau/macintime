from flask import Flask, render_template, request
import paramiko

app = Flask(__name__)

# Membuat define untuk melakukan koneksi SSH
def koneksi_ssh(host, username, password, port):
    """Aplikasi MaCInTime Untuk Melakukan Konfigurasi Mikrotik"""
    try:
        # Mencoba menghubungkan koneksi
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port)

        # Menjalankan perintah
        stdin, stdout, stderr = ssh.exec_command("ip address print detail")
        output = stdout.read().decode()
        ssh.close()

        # Parsing data IP , split untuk memotong bagian, misal hasil command address=1 ..=.. ..=.. maka akan mengambil nilai indeks 1 (nilai address) dan menghapus sisanya dari indeks 0 split()[0]
        data_ip = []
        for item in output.splitlines():
            if "interface=" in item and "address=" in item:
                interface = item.split("interface=")[1].split()[0]
                address = item.split("address=")[1].split()[0]
                data_ip.append({"interface": interface, "address": address})

        return data_ip
    except Exception as e:
        return str(e)

@app.route("/", methods=["GET", "POST"])
def index():
    hasil = None
    if request.method == "POST":
        host = request.form["host"]
        username = request.form["username"]
        password = request.form["password"]
        port = int(request.form["port"])
        hasil = koneksi_ssh(host, username, password, port)
    
    return render_template("index.html", hasil=hasil)

if __name__ == "__main__":
    app.run(debug=True)