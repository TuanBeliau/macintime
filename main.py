from flask import Flask, request, render_template, redirect, url_for, flash, session
import paramiko
import uuid
import time

app = Flask(__name__)
app.secret_key = "apalah"

ssh_connections = {}

# Def akan di eksekusi sesudah di panggil di def login
def ssh_connect(host, username, password, port):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port)

        session.pop("error", None)

        # Membuat id unik untuk session jika belum ada
        if "user_id" not in session:
            session["user_id"] = str(uuid.uuid4())

        # Membuat session untuk menandai login berhasil dan alamat host 
        session["logged_in"] = True
        session["host"] = host

        # menyimpan koneksi ssh dalam dictionary dan di kunci dengan user_id
        ssh_connections[session["user_id"]] = ssh

        return True
    except paramiko.AuthenticationException:
        session['error'] = "Authentication failed, please check your username and password."
        return False
    except Exception as e:
        session['error'] = f"Connection error: {e}"
        return False

@app.route("/", methods=["GET", "POST"])
def login() :
    berhasil = None
    error = session.pop("error", None)

    # Jika ada form di kirim dengan method POST 
    if request.method == "POST":
        host = request.form["host"] # Mengambil request dari tag form dan name nya sesuai
        username = request.form["username"]
        password = request.form["password"]
        port = int(request.form["port"])

        # Memanggil def ssh_connect di awal dan mengirimkan variable di atas
        result = ssh_connect(host, username, password, port)
        if result is True:
            berhasil = True
        else:
            return redirect(url_for("login"))
    
    return render_template("login.html", error=error, berhasil=berhasil)

@app.route("/dashboard", methods=["GET"])
def dashboard():
    berhasil = None
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    berhasil = True

    stdin, stdout, stderr = ssh.exec_command("/interface print detail")
    output = stdout.read().decode()

    interface_all = []
    for line in output.splitlines():
        if "name" in line:
            name = line.split("name=")[1].split()[0].strip('"')
            interface_all.append(name)
    
    def show_ip():
        try:
            stdin, stdout, stderr = ssh.exec_command("/ip address print detail")
            output = stdout.read().decode()

            ip_data = []
            for line in output.splitlines():
                if "address=" in line and "interface=" in line:
                    parts = line.split()

                    flag = parts[1] # Mengambil nilai index ke 1 dari list parts alias statusnya, misal D
                    ip_id = parts[0] # Sama seperti di atas namun ini untuk id
                    
                    address = next((part.split("address=")[1] for part in parts if "address=" in part), "Unknown") # Next membuat perulangan lebih singkat. Di sini akan mengambil nilai address= (ini index 0)
                    interface = next((part.split("interface=")[1] for part in parts if "interface=" in part), "Unknown")
                    status = "dynamic" if "D" in flag else "static"

                    ip_data.append({
                        "id": ip_id,
                        "interface": interface,
                        "address": address,
                        "status": status
                    })

            return ip_data or [{"interface": "Error", "address": "IP Address Not Found"}]

        except Exception as e:
            return [{"interface": "Error", "address": str(e)}]

    ip_list = show_ip()

    return render_template("dashboard.html", host=session["host"], ip_list=ip_list, interfaces=interface_all, berhasil=berhasil)

@app.route("/add_ip", methods=["POST"])
def add_ip():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    if request.method == "POST":
        address = request.form["address"]
        prefix = int(request.form["prefix"])
        interface = request.form["interface"]

        try :
            command = f"/ip address add address={address}/{prefix} interface={interface}"
            stdin, stdout, stderr = ssh.exec_command(command)
            stderr_output = stderr.read().decode()
             
            if stderr_output:
                return f"Erorr when add IP: {stderr_output}"

            return redirect(url_for("dashboard"))
        except Exception as e:
            return f"error occured : {e}"

@app.route('/delete_ip/<id>', methods=["POST"])
def delete_ip(id):

    def delete():
        if not session.get("logged_in"):
            return redirect(url_for("dashboard"))
        
        user_id = session.get("user_id")
        ssh = ssh_connections.get(user_id)

        if not ssh:
            return redirect(url_for('login'))
        
        try:
            command = f"/ip address remove {id}"
            stdin, stdout, stderr = ssh.exec_command(command)
            stderr_output = stderr.read().decode()

            if stderr_output:
                return f"Error when delete IP: {stderr_output}"
            return "IP Address Deleted Succesfully"
        except Exception as e:
            return f"Error: {e}"
    
    result = delete()
    if result == "IP Address Deleted Succesfully":
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("dashboard"))

@app.route('/change_ip/<id>', methods=["POST"])
def change_ip(id):

    if not session.get("logged_in"):
        return redirect(url_for("login"))
        
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    if request.method == "POST":
        address = request.form['address'] # Nanti di buat form
        prefix = int(request.form['prefix']) 
        interface = request.form['interface']

        def change(address, prefix, interface, id):
            try:
                command = f"/ip address set {id} address={address}/{prefix} interface={interface}"
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode()

                if stderr_output:
                    return f"Error when change IP: {stderr_output}"
                return "IP Address Change Succesfully"
            except Exception as e:
                return f"Error: {e}"

        result = change(address, prefix, interface, id)
        if result == "IP Address Change Succesfully":
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("dashboard"))
    
    return render_template("test.html")

@app.route("/settings", methods={"GET", "POST"})
def settings() :

    if not session.get("logged_in") :
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)
    
    if not ssh:
        return redirect(url_for("login"))
    
    stdin, stdout, stderr = ssh.exec_command("/system identity print")
    output = stdout.read().decode()
    current_identity = output.strip().split(": ")[1] if ": " in output else "Uknown"
    
    if request.method == "POST":
        identity = request.form["identity"]
        password = request.form["password"]

        def ganti_identity(identity):
            try:
                command = f"/system identity set name={identity}"
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode()

                if stderr_output:
                    return f"Error when change identity: {stderr_output}"
                return "Identity Changed Succesfully"
            except Exception as e:
                return f"Error: {e}"

        def ganti_pw(password):
            try:
                command = f"user set 0 password={password}"
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode()

                if stderr_output:
                    return f"Error when change password: {stderr_output}"
                return "Password Changed Succesfully"

            except Exception as e:
                return f"Error: {e}"

        
        messages = []

        if identity:
            messages.append(ganti_identity(identity))

        if password:
            messages.append(ganti_pw(password))

        for msg in messages:
            flash(msg)

        return redirect(url_for("settings"))


    return render_template("setting.html", current_identity=current_identity)

@app.route("/DHCP-Server", methods={"GET", "POST"})
def dhcp():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    try:
        command_ip = "/ip address print detail"
        stdin, stdout, stderr = ssh.exec_command(command_ip)
        output = stdout.read().decode()

        addresses_all = []
        for line in output.splitlines():
            if "address" in line :
                address = line.split("address=")[1].split()[0]
                cek_oktet = address.split("/")[0].split(".")[3]
                if cek_oktet == "1" or cek_oktet == "254" :
                    addresses_all.append(address)

    except Exception as e:
        return render_template("DHCP.html")

    if request.method == "POST": # Code Di bawah akan jalan jika terdeteksi method post
        name = request.form["name"]
        ip_address = request.form["ip_address"] # IP address dari select sebagai gateway
        pool_range = int(request.form["pool_range"]) # Range IP

        if not ip_address or pool_range <=0:
            return "Input tidak valid"
        
        pool_name = f"dhcp_pool_{int(time.time())}" # Memberi nama unik untuk tiap pool_ip
        gateway = ip_address.split("/")[0]
        prefix = ip_address.split("/")[1]
        base_ip = gateway.rsplit(".", 1)[0] # Memotong oktet ke-4
        cek_ip = gateway.split(".")[3] # Ambil oktet ke-4

        # Cek apakah oktet ke-4 .1/.254
        if cek_ip == "1" :
            pool_start = f"{base_ip}.2"
            pool_end = f"{base_ip}.{pool_range + 1}"
        else:
            pool_start = f"{base_ip}.1"
            pool_end = f"{base_ip}.{pool_range}"

        pool_range = f"{pool_start}-{pool_end}"

        try:
            command_interface = f'/ip address print where address~"{gateway}"'
            stdin, stdout, stderr = ssh.exec_command(command_interface)
            output = stdout.read().decode()

            interface = None
            for line in output.splitlines():
                hasil_output = line.split()
                for kata in hasil_output:
                    if kata.startswith("ether"):
                        interface = kata
                        break
                if interface:
                    break
            
            if not interface:
                return "flash nyusul"

        except Exception as e:
            return f"my bad maybe {e}"

        # Membuat command CLI
        command_main = [
            f"/ip pool add name={pool_name} ranges={pool_range}",
            f"/ip dhcp-server network add address={base_ip}.0/{prefix} gateway={gateway} dns-server=8.8.8.8",
            f"/ip dhcp-server add name={name} interface={interface} address-pool={pool_name} disabled=no"
        ]

        try:
            for cmd in command_main:
                ssh.exec_command(cmd)
            return redirect(url_for("dashboard"))
        except Exception as e:
            return f"My bad maybe, dunno {e}"
        
    return render_template("DHCP.html", ip_address=addresses_all)

@app.route("/logout")
def logout():
    # Ambil kunci
    user_id = session.get("user_id")

    # cek jika kunci sesuai
    if user_id in ssh_connections:
        # menutup koneksi ssh
        ssh_connections[user_id].close()
        # Mengahapus kunci user_id
        del ssh_connections[user_id]
    
    # Menghapus session
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)