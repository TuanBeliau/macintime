from flask import Flask, request, render_template, redirect, url_for, flash, session
import paramiko
import uuid

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
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("login"))
    
    return render_template("login.html", error=error)

@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    def show_ip():
        user_id = session.get("user_id")
        ssh = ssh_connections.get(user_id)

        if not ssh:
            return [{"interface": "Error", "address": "Tidak ada koneksi SSH"}]

        try:
            stdin, stdout, stderr = ssh.exec_command("ip address print detail")
            output = stdout.read().decode()

            ip_data = []
            for line in output.splitlines():
                if "address=" in line and "interface=" in line:
                    parts = line.split()

                    flag = parts[1] # Mengambil nilai index ke 1 dari list parts alias statusnya, misal D
                    ip_id = parts[0] # Sama seperti di atas namun ini untuk id
                    
                    address = next((part.split("address=")[1] for part in parts if "address=" in part), "Unknown") 
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

    return render_template("dashboard.html", host=session["host"], ip_list=ip_list)

# Masih belum tau bisa enggak
@app.route('/ubah_ip/<id>', methods=["POST"])
def change_ip(id):

    if not session.get("logged_in"):
        return redirect(url_for("login"))
        
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    if request.method == "POST":
        address = request.form['address'] # Nanti di buat form
        interface = request.form['interface']

        def change():
            try:
                command = f"ip address set [find .id={id}] address={address} interface={interface}"
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode()

                if stderr_output:
                    return f"Error when change IP: {stderr_output}"
                return "IP Address Change Succesfully"
            except Exception as e:
                return f"Error: {e}"

        result = change(address, interface, id)
        if result == "IP Address Change Succesfully":
            return redirect(url_for("dashboard"))
        else:
            return redirect(url_for("dashboard"))


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
            command = f"ip address remove {id}"
            stdin, stdout, stderr = ssh.exec_command(command)
            stderr_output = stderr.read().decode()

            if stderr_output:
                return f"Error saat mengahapus IP: {stderr_output}"
            return "IP Address Deleted Succesfully"
        except Exception as e:
            return f"Error: {e}"
    
    result = delete()
    if result == "IP Address Deleted Succesfully":
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("dashboard"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)
    
    if not ssh:
        return redirect(url_for("login"))
    
    current_identity = ""
    try:
        stdin, stdout, stderr = ssh.exec_command("system identity print")
        output = stdout.read().decode()
        current_identity = output.split("name: ")[1].strip() if "name: " in output else ""
    except Exception as e:
        flash(f"Error: {e}")
        return redirect(url_for("login"))

    if request.method == "POST":
        identity = request.form.get("identity")
        password = request.form.get("password")

        def ganti_identity(identity):
            try:
                command = f'system identity set name="{identity}"'
                stdin, stdout, stderr = ssh.exec_command(command)
                stderr_output = stderr.read().decode()

                if stderr_output:
                    return False, f"Error when changing identity: {stderr_output}"
                return True, "Identity Changed Successfully"
            except Exception as e:
                return False, f"Error: {e}"

        def ganti_pw(password):
            try:
                # Set the timeout for the command to be very short
                command = f'user set admin password="{password}"; :delay 1'
                ssh.exec_command(command, timeout=1)
                
                # If we get here, assume success (even if connection drops)
                return True, "Password Changed Successfully"
            except paramiko.SSHException:
                # This is expected - connection will drop after password change
                return True, "Password Changed Successfully"
            except Exception as e:
                return False, f"Error: {e}"

        # Handle both identity and password changes
        need_logout = False
        messages = []

        # Do password change last if both are being changed
        if identity and identity != current_identity:
            success, message = ganti_identity(identity)
            messages.append(message)
            if success:
                need_logout = True

        if password:
            success, message = ganti_pw(password)
            messages.append(message)
            if success:
                need_logout = True

        # If any change was successful, close connection and redirect to login
        if need_logout:
            try:
                # Try to close SSH connection gracefully
                if user_id in ssh_connections:
                    try:
                        ssh_connections[user_id].close()
                    except:
                        pass  # Ignore any errors during close
                    del ssh_connections[user_id]
                
                # Clear session
                session.clear()
            except:
                pass  # Ignore any cleanup errors
            
            # Flash all messages
            for message in messages:
                flash(message)
            
            return redirect(url_for("login"))
        else:
            # If no successful changes, just show messages and stay on settings
            for message in messages:
                flash(message)
            return redirect(url_for("settings"))

    return render_template("settings.html", current_identity=current_identity)

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
