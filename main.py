from flask import Flask, render_template, request, redirect, url_for, session
import paramiko

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Ganti dengan key yang aman untuk session

def ssh_connect(host, username, password, port):
    """Fungsi untuk koneksi SSH ke MikroTik"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port)
        return ssh  # Mengembalikan objek SSH
    except Exception as e:
        return str(e)  # Kirim error ke frontend

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        host = request.form["host"]
        username = request.form["username"]
        password = request.form["password"]
        port = int(request.form["port"])

        ssh = ssh_connect(host, username, password, port)
        if isinstance(ssh, paramiko.SSHClient):  # Jika koneksi berhasil
            session["logged_in"] = True
            session["host"] = host
            session["username"] = username
            session["password"] = password
            session["port"] = port
            return redirect(url_for("dashboard"))  # Redirect ke dashboard
        else:
            return render_template("login.html", error=ssh)  # Menampilkan error

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("index"))

    # Ambil daftar IP Address langsung di dalam dashboard
    ip_list = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=session["host"], username="admin", password="", port=22
        )  # Sesuaikan login

        stdin, stdout, stderr = ssh.exec_command("ip address print detail")
        output = stdout.read().decode()
        ssh.close()

        for line in output.splitlines():
            if "interface=" in line and "address=" in line:
                interface = line.split("interface=")[1].split()[0]
                address = line.split("address=")[1].split()[0]
                ip_list.append({"interface": interface, "address": address})

    except Exception as e:
        ip_list.append({"interface": "Error", "address": str(e)})

    return render_template("dashboard.html", host=session["host"], ip_list=ip_list)

@app.route("/logout")
def logout():
    session.clear()  # Hapus session saat logout
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
