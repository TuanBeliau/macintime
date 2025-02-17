from flask import Flask, render_template, request, redirect, url_for, session
import paramiko
import uuid  # Untuk membuat user_id unik

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Ganti dengan key yang lebih aman untuk session

# Simpan objek SSH di dictionary global berdasarkan user_id
ssh_connections = {}

def ssh_connect(host, username, password, port):
    """Fungsi untuk koneksi SSH ke MikroTik"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port)

        # Buat user_id unik jika belum ada
        if "user_id" not in session:
            session["user_id"] = str(uuid.uuid4())

        # Simpan status login di session
        session["logged_in"] = True
        session["host"] = host

        # Simpan koneksi SSH dalam dictionary global
        ssh_connections[session["user_id"]] = ssh

        return True  # Login berhasil
    except paramiko.AuthenticationException:
        return "Autentikasi gagal. Periksa username dan password."
    except Exception as e:
        return f"Kesalahan: {e}"  # Kirim error ke frontend

def get_ip_addresses():
    """Mengambil daftar IP Address dari MikroTik"""
    if not session.get("logged_in"):
        return [{"interface": "Error", "address": "Not logged in"}]

    # Ambil user_id dari session
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)
    
    if not ssh:
        return [{"interface": "Error", "address": "Tidak ada koneksi SSH aktif"}]

    try:
        stdin, stdout, stderr = ssh.exec_command("ip address print detail")
        output = stdout.read().decode()

        ip_data = []
        for line in output.splitlines():
            if "interface=" in line and "address=" in line:
                interface = line.split("interface=")[1].split()[0]
                address = line.split("address=")[1].split()[0]
                ip_data.append({"interface": interface, "address": address})

        return ip_data if ip_data else [{"interface": "Error", "address": "Tidak ada IP Address ditemukan"}]

    except Exception as e:
        return [{"interface": "Error", "address": f"Unknown Error: {e}"}]

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        host = request.form["host"]
        username = request.form["username"]
        password = request.form["password"]
        port = int(request.form["port"])

        result = ssh_connect(host, username, password, port)
        if result is True:
            return redirect(url_for("dashboard"))  # Redirect ke dashboard jika login berhasil
        else:
            return render_template("login.html", error=result)  # Tampilkan pesan error jika gagal

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    ip_list = get_ip_addresses()
    return render_template("dashboard.html", host=session["host"], ip_list=ip_list)

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    
    if user_id in ssh_connections:
        ssh_connections[user_id].close()  # Tutup koneksi SSH
        del ssh_connections[user_id]  # Hapus dari dictionary
    
    session.clear()  # Hapus session saat logout
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
