from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import paramiko
import uuid
import time
import re

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
        session['error'] = "Autentikasi gagal, coba cek username dan password"
        return False
    except TimeoutError:
        session['error'] = "Timeout, gagal terhubung. Pastikan koneksi tersedia"
        return False
    except Exception as e:
        session['error'] = f"Connection error: {e}"
        return False

# sudah VALID
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

# Bagian Dashboard (BELUM SELESAI)
@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    # Cek, jika wireless ada, maka ambil ssid dan lakukan bandwith test
    speedtest = None
    password = None
    ssid = None

    try:
        stdin, stdout, stderr = ssh.exec_command("/wireless print detail")
        output = stdout.read().decode()

        # pattern = re.search('wpa-pre-shared-key="([^"]+)"(?:.*ssid="([^"\n]+))?', output)
        pattern = re.search(r'wpa-pre-shared-key="([^"]+)".*ssid="([^"/n]+)"', output)

        if pattern :
            password = pattern.group(1)
            ssid = pattern.group(2)

            stdin, stdout, stderr = ssh.exec_command("/tool speed-test address=speedtest.telkom.net.id")
            output = stdout.read().decode()

            pattern_1 = re.search(r'download-mbps:/s([/d.]+).*upload-mbps:/s([/d.]+)')

            if pattern_1 : 
                speedtest = {
                    'download' : pattern_1.group(1),
                    'upload' : pattern_1.group(2)
                }

            pattern = re.search('')


    except Exception as e:
        return jsonify({'success': False, 'error':str(e)})

    return render_template("dashboard.html", password=password, ssid=ssid, speedtest=speedtest)

# -------------------------------------------

# Bagian Setting

# Sudah VALID 
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

# sudah VALID (GUEST Belum)
@app.route("/wireless", methods={"GET", "POST"})
def wireless():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    error = session.pop("error", None) # Menghapus error jika ada

    try:
        stdin, stdout, stderr = ssh.exec_command("/interface wireless access-list print detail where action=deny")
        output = stdout.read().decode()

        pattern = r'mac-address=([\w:]+).*?comment="(.*?)"'

        matches = re.findall(pattern, output, re.DOTALL)
        
        if not matches :
            user_block = [{
                "hostname": "Kosong",
                "mac_address": "Kosong"
            }]
        else :
            user_block = [{
                "hostname": comment,
                "mac_address": mac,
            } for comment, mac in matches]
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}) 

    # Buat cek dhcp-server wlan1
    try:
        stdin, stdout, stderr = ssh.exec_command("/ip dhcp-server print detail")
        output = stdout.read().decode()

        pattern = r'.*?interface=([wlan\d]+)'

        matches = re.findall(pattern, output, re.DOTALL)
        
        cek_wlan = None
        if matches:
            cek_wlan = True

    except Exception as e:
        return jsonify({"error_cek(wlan1)": str(e)}), 500

    # Buat list pengguna jika ada
    try:
        stdin, stdout, stderr = ssh.exec_command("/ip dhcp-server lease print detail")
        output_1 = stdout.read().decode().strip()

        pattern_1 = r'address=([\d.]+)\s+mac-address=([\w:]+).*?host-name="(.*?)"'
        matches_1 = re.findall(pattern_1, output_1, re.DOTALL)

        # stidin, stdout, stderr = ssh.exec_command("/interface wireless print detail")
        # output_2 = stdout.read().decode()

        # pattern_2 = r'ssid="(.*?)"'
        # matches_2 = re.findall(pattern_2, output_2, re.DOTALL)

        # if not matches_2:
        #     return matches_2

        if not matches_1 :
            data_user = [{
                "address": "Kosong",
                "mac_address": "Kosong",
                "hostname": "Kosong"
            }]
        else :
            data_user = [{
                "address": ip,
                "mac_address": mac,
                "hostname": hostname
            } for ip, mac, hostname in matches_1]
        
        # data_user = []
        # ssid_list = list(matches_2)  # SSID yang ditemukan

        # for i, (ip, mac, hostname) in enumerate(matches_1):
        #     ssid = ssid_list[i] if i < len(ssid_list) else "Tidak Diketahui"
        #     data_user.append({
        #         "address": ip,
        #         "mac_address": mac,
        #         "hostname": hostname,
        #         "ssid": ssid
        #     })
   
    except Exception as e:
        return jsonify({"error_dhcplease": str(e)}), 500

    # Wireless Utama (Done, pakai wlan1, ISP sering make kabel)  guest Def lagi
    if request.method == "POST":
        name = request.form["name"] # Untuk edit pastikan value ini di ambil dan di simpan di form edit lalu di ganti dan di jalankan ulang
        password = request.form["password"]
        ip_address = request.form["ip_address"]
        pool_range = int(request.form["pool_range"])

        gateway, prefix = ip_address.split("/")
        base_ip = gateway.rsplit(".", 1)[0]
        cek_ip = gateway.split(".")[3]

        if cek_ip == "1":
            pool_start = f"{base_ip}.2"
            pool_end = f"{base_ip}.{pool_range + 1}"
        else:
            pool_start = f"{base_ip}.1"
            pool_end = f"{base_ip}.{pool_range}"

        pool_range = f"{pool_start}-{pool_end}"

        # Cek wlan1
        try:
            stdin, stdout, stderr = ssh.exec.command("/interface wireless find where disabled=yes")
            output = stdout.read().decode()

            if not output :
                interface_wlan =[line.split()[1] for line in output.splitlines() if "wlan" in line]

                if interface_wlan:
                    stdin, stdout, stderr = ssh.exce_command(f"/interface wireless enable {interface_wlan[0]}")
        
        except Exception as e:
            return jsonify({"Error_activatingWlan1": {e}})

        # Buat IP address
        try:
            stdin, stdout, stderr = ssh.exec_command("ip address print detail")
            output = stdout.read().decode()

            pattern = r'address=([\d.+])'

            matches = re.findall(pattern, output, re.DOTALL)

            if gateway not in matches:
                try:
                    stdin, stdout, stderr = ssh.exec_command(f"/ip address add address={gateway} interface=wlan1")
                    error_addIP = stderr.read().decode()

                    if error_addIP:
                        return f"Error_addIP: {error_addIP}"
                except Exception as e:
                    return f"Error_addIP: {e}"
        
        except Exception as e:
            return jsonify({"Error_cariIP": {e}}),500

        # Cek Firewall
        try:
            stdin, stdout, stderr = ssh.exec_command(f"/ip firewall nat print")
            output = stdout.read().decode()

            pattern = r'chain=srcnat\s+action=masquerade'

            matches = re.findall(pattern, output)

            if not matches:
                try:
                    stdin, stdout, stderr = ssh.exec_command("/ip firewall nat add chain=srcnat action=masquerade")
                    error_firewall = stderr.read().decode()

                    if error_firewall:
                        print(f"Error: {error_firewall}")
                
                except Exception as e:
                    return jsonify({"error_cmd_firewall": str(e)}), 500
        
        except Exception as e:
            return jsonify({"error_try_firewall": str(e)}), 500

        # Ambil data interface ()
        try:
            stdin, stdout, stderr = ssh.exec_command(f'/ip address print detail where address~"{gateway}"')
            output = stdout.read().decode()

            pattern = r'interface=([\w\d-]+)'

            matches = re.findall(pattern, output, re.DOTALL)

            interface = None
            if not matches:
                return f"Gagal Mendapatkan interface: {output}"
            else :
                interface = matches[0]

        except Exception as e:
            return jsonify({"error_interface": str(e)}), 500

        # Menjalankan command utama
        try:
            # Menjalankan command pool
            stdin, stdout, stderr = ssh.exec_command(f"/ip pool add name=pool_{name} ranges={pool_range}")
            error_pool = stderr.read().decode()

            if error_pool:
                print(f"Error_pool: {error_pool}")

            # Menjalankan command dhcp
            command_dhcp = [
                f"/ip dhcp-server network add address={base_ip}.0/{prefix} gateway={gateway} dns-server=8.8.8.8",
                f"/ip dhcp-server add name=dhcp_{name} interface={interface} address-pool=pool_{name} lease-time=12m disabled=no"
            ]

            for cmd in command_dhcp:
                print(f"Executing: {cmd}")  # Debugging
                stdin, stdout, stderr = ssh.exec_command(cmd)
                error = stderr.read().decode()
                if error:
                    print(f"Error_dhcp: {error}")  # Debugging
                    return error  # Menghentikan eksekusi jika ada error

            # Menjalankan command wireless
            command_wireless = [
                f"/interface wireless security-profiles add name=security_{name} mode=dynamic-keys authentication-types=wpa-psk,wpa2-psk wpa-pre-shared-key={password}  wpa2-pre-shared-key={password}",
                f"/interface wireless set {interface} mode=ap-bridge ssid={name} security-profile=security_{name}"
            ]

            for cmd in command_wireless:
                print(f"Executing: {cmd}")  # Debugging
                stdin, stdout, stderr = ssh.exec_command(cmd)
                error = stderr.read().decode()
                if error:
                    print(f"Error_wireless: {error}")  # Debugging
                    return error  # Menghentikan eksekusi jika ada error

        except Exception as e:
            return jsonify({"error_cmd": str(e)}), 500

    return render_template("wireless.html", data_user=data_user, cek_wlan=cek_wlan)

# CEK BISA ENGGAK NYA
@app.route("/edit_wireless/<id>", methods=["POST"])
def edit_wireless(id):

    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get(user_id)
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))
    
    error = session.pop("error", None)

    ssid = request.form.get("ssid")
    password = request.form.get("password")
    address = request.form.get("address")
    pool_range = int(request.form.get("pool_range"))

    gateway, prefix = address.split("/")
    base_ip = gateway.rsplit(".", 1)[0]
    cek_ip = gateway.split(".")[3]

    if cek_ip == "1":
        pool_start = f"{base_ip}.2"
        pool_end = f"{base_ip}.{pool_range + 1}"
    else:
        pool_start = f"{base_ip}.1"
        pool_end = f"{base_ip}.{pool_range}"

    ranges = f"{pool_start}-{pool_end}"
    
    try:
        stdin, stdout, stderr = ssh.exec_command(f"/wireless interface security-profile set {id} wpa-pre-shared-key={password}  wpa2-pre-shared-key={password}")
        error_security = stderr.read().decode()

        if error_security:
            return error_security

        stdin, stdout, stderr = ssh.exec_command(f"/wireless set [find where interface=wlan1] ssid={ssid}")
        error_ssid = stderr.read().decode()

        if error_ssid:
            return error_ssid

        stdin, stdout, stderr = ssh.exec_command(f"/ip dhcp-server print detail where interface=wlan1")
        output = stdout.read().decode()
        error_print = stderr.read().decode()

        if error_print:
            return error_print
        
        pattern = r'address-pool=([\w\d-]+)' 

        address_pool = re.findall(pattern, output, re.DOTALL)

        if not address_pool:
            return output
        
        stdin, stdout, stderr = ssh.exec_command(f'ip pool set [find where name="{address_pool}"] ranges={ranges}')
         
    except Exception as e:
        return f"Error: {e}"

# CEK BISA ENGGAK NYA
@app.route("/delete_wireless/<mac_address>", methods=["POST"])
def delete_wireless(mac_address):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login")) 
    
    try:
        data = request.get_json()
        hostname = data.get("hostname", "Tidak diketahui")

        stdin, stdout, stderr = ssh.exec_command(f"/interface wireless access-list add mac-address={mac_address} comment={hostname} authentication=no")
        error_block = stderr.read().decode()

        if error_block:
            return jsonify({"success": False, "Gagal Memblokir": error_block})

        return jsonify({"success": True, "success": "DHCP Server Berhasil dihapus"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# BELUM DONE
@app.route("/nat", methods={"GET", "POST"})
def nat():
    
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))
    
    filter = None

    if request.method == "POST":
        website = request.form['website']

        stdin, stdout, stderr  = ssh.exec_command('/ip firewall address-list list=website address=website')
        address_list = stderr.read().decode()

        if address_list:
            return jsonify({'success':False, 'error':address_list})
        
        stdin, stdout, stderr = ssh.exec_command('/ip firewall filter chain=forward protocol=tcp dst-port=443 dst-address-list=website log=no log-prefix=""')
        stdin, stdout, stderr = ssh.exec_command('/ip firewall filter chain=forward protocol=udp dst-port=443 dst-address-list=website log=no log-prefix=""')

        filter = {
            'tcp': stderr.read().decode(),
            'udp': stderr.read().decode()
        }

        if not filter:
            return jsonify({'success':False, 'error':filter})

    return render_template("nat.html", filter=filter)
# -------------------------------------------

# Bagian Logout

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

# -------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)