from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import paramiko
import uuid
import time
import re
import socket
import validators

app = Flask(__name__)
app.secret_key = "apalah"

ssh_connections = {}

# Def akan di eksekusi sesudah di panggil di def login
def ssh_connect(host, username, password, port):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port, timeout=3)

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
    except (socket.timeout, socket.gaierror):
        session['error'] = "IP Address tidak ditemukan atau Mikrotik offline"
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

# CEK BISA ENGGAK NYA
@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))

    # Cek, jika wireless ada, maka ambil ssid dan lakukan bandwith test
    speedtest = {}
    password = None
    ssid = None

    try:
        stdin, stdout, stderr = ssh.exec_command("/interface wireless print detail")
        output = stdout.read().decode()

        # Untuk Ambil SSID dan Password
        cek_wireless = re.search(r'wpa-pre-shared-key="([^"]+)".*?ssid="([^"]+)"', output, re.DOTALL)

        if cek_wireless :
            password = cek_wireless.group(1)
            ssid = cek_wireless.group(2)

            stdin, stdout, stderr = ssh.exec_command("/tool speed-test address=speedtest.telkom.net.id")
            output = stdout.read().decode()

            # Untuk cek kecepatan
            speedtest = re.search(r'download-mbps:\s([\d.]+).*upload-mbps:\s([\d.]+)', output, re.DOTALL)

            if speedtest : 
                speedtest = {
                    'download' : speedtest.group(1),
                    'upload' : speedtest.group(2)
                }

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

    return render_template("settings.html", current_identity=current_identity)

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

    # Buat cek user yang di blokir
    try:
        stdin, stdout, stderr = ssh.exec_command("/interface wireless access-list print where authentication=no forwarding=no")
        # action=deny untuk versi 7
        output = stdout.read().decode()

        pattern = re.findall(r';;;\s*(.+?)\s*mac-address=([0-9A-Fa-f:]+)', output)
        user_block = []

        if pattern:
            for hostname, mac_address in pattern:
                user_block = [{
                    "hostname": hostname,
                    "mac_address": mac_address,
                }]
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}) 

    # Buat cek dhcp-server wlan1
    try:
        stdin, stdout, stderr = ssh.exec_command("/ip dhcp-server print detail")
        output = stdout.read().decode()

        pattern = r'.*?interface=([wlan\d]+)'

        matches = re.findall(pattern, output, re.DOTALL)
        
        cek_dhcp = None
        if matches:
            cek_dhcp = True

    except Exception as e:
        return jsonify({"error_cek(wlan1)": str(e)}), 500

    # Buat list pengguna jika ada
    try:
        stdin, stdout, stderr = ssh.exec_command("/ip dhcp-server lease print detail")
        output_1 = stdout.read().decode().strip()

        pattern_1 = r'address=([\d.]+)\s+mac-address=([\w:]+).*?status=([\w]+).*?host-name="(.*?)"'
        matches_1 = re.findall(pattern_1, output_1, re.DOTALL)

        if not matches_1 :
            data_user = [{
                "address": "Kosong",
                "mac_address": "Kosong",
                "status": "Kosong",
                "hostname": "Kosong"
            }]
        else :
            data_user = [{
                "address": ip,
                "mac_address": mac,
                "status": status,
                "hostname": hostname
            } for ip, mac, status, hostname in matches_1]
   
    except Exception as e:
        return jsonify({"error_dhcplease": str(e)}), 500

    # Wireless Utama (Done, pakai wlan1, ISP sering make kabel)  guest Def lagi
    if request.method == "POST":
        action = request.form["action"]

        # Ini untuk proses unlock
        if action == "unblock":
            mac_address = request.form["mac_address"]
            stdin, stdout, stderr = ssh.exec_command(f"/interface wireless access-list remove [find where mac-address={mac_address}]")

            if stderr.read().decode():
                return jsonify({'success':False, 'error':'Gagal Hapus Mac-Address'})
            else :
                return jsonify({'success':True, 'message':'User Berhasil di Unblock'})
            
        if action == "addORcreate":
            name = request.form["name"] 
            password = request.form["password"]
            ip_address = "192.168.10.1/24" 
            download = request.form['download']
            upload = request.form['upload']

            pool_range = int(request.form["pool_range"])

            gateway, prefix = ip_address.split("/")
            base_ip = gateway.rsplit(".", 1)[0]

            pool_range = f"{base_ip}.2-{base_ip}.{pool_range + 1}"

            # Cek interface wlan1
            try:
                stdin, stdout, stderr = ssh.exec_command("/interface wireless find where disabled=yes")
                output = stdout.read().decode()

                if not output :
                    interface_wlan =[line.split()[1] for line in output.splitlines() if "wlan" in line]

                    if interface_wlan:
                        stdin, stdout, stderr = ssh.exec_command(f"/interface wireless enable {interface_wlan[0]}")
            
            except Exception as e:
                return jsonify({"Error_activatingWlan1": {e}})

            # Buat IP address
            try:
                stdin, stdout, stderr = ssh.exec_command("ip address print detail")
                output = stdout.read().decode()

                pattern = r'address=([\d\.+])'

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
                    return f"Gagal Mendapatkan interface: {gateway}"
                else :
                    interface = matches[0]

            except Exception as e:
                return jsonify({"error_interface": str(e)}), 500

            # Menjalankan command utama
            try:
                if cek_dhcp:
                    stdin, stdout, stderr = ssh.exec_command(f"/interface wireless security-profiles set [find where name=] wpa-pre-shared-key={password} wpa2-pre-shared-key={password}")
                    error_security = stderr.read().decode() 

                    if error_security:
                        return error_security

                    stdin, stdout, stderr = ssh.exec_command(f"/wireless set [find where interface=wlan1] ssid={name}")
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
                    
                    stdin, stdout, stderr = ssh.exec_command(f'ip pool set [find where name="{address_pool}"] ranges={pool_range}')
                    error_ranges = stderr.read().decode()

                    if error_ranges:
                        return error_ranges

                else:
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
                    
                    command_limiter = f"queue simple add name=bandwith_{name} target={base_ip}.0 max-limit={download}/{upload}"
                    stdin, stdout, stderr = ssh.exec_command(command_limiter)
                    if stderr.read().decode():
                        print(f"Error_queue : {stderr.read().decode()}")

            except Exception as e:
                return jsonify({"error_cmd": str(e)}), 500

        if action == "guest":
            pools = request.form['pool_range']

            stdin, stdout, stderr = ssh.exec_command('/interface wireless where ssid="GUEST_WIFI" disabled=yes')

            if stdout.read().decode():
                stdin, stdout, stderr = ssh.exec_command('/interface wiresless set [find where ssid="GUEST_WIFI] disabled=no')
            else :
                ip_address = "192.168.20.1/24"
                base_ip = ip_address.split('/')[0].rsplit('.', 1)

                pool_range = f'{base_ip}.2-{base_ip}.{pools + 1}'  

                try:
                    commands = [
                        ("/interface wireless add master-interface=wlan1 name=vap_guest ssid=\"GUEST_WIFI\" vlan-mode=use-tag vlan-id=20", "Failed Make a VAP"),
                        ("/interface vlan add name=vlan_guest interface=vap_guest vlan-id=20", "Failed Make a Vlan"),
                        ("/ip address add address=192.168.20.1/24 interface=vlan_guest", "Failed Make a IP Address"),
                        (f"/ip pool add name=guest_pool ranges={pool_range}", "Failed Make a pool"),
                        (f"/ip dhcp-server add name=dhcp_guest interface=vlan_guest address-pool=guest_pool", "Failed Make a dhcp-server"),
                        (f"/ip dhcp-server network add address={base_ip}.0/24 gateway={base_ip}.1", "Failed Make a dhcp-server network")
                    ]

                    for command, error_message in commands:
                        stdin, stdout, stderr = ssh.exec_command(command)
                        error_output = stderr.read().decode()

                        if error_output:
                            return jsonify({'success': False, 'error': error_message})

                except:
                    return jsonify({'success': False, 'error':'Gagal print vlan'})
                
    return render_template("wireless.html", data_user=data_user, cek_dhcp=cek_dhcp, user_block=user_block)

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

        # Gunakan action=deny untuk versi 7
        stdin, stdout, stderr = ssh.exec_command(f"/interface wireless access-list add mac-address={mac_address} comment={hostname} authentication=no forwarding=no")
        error_block = stderr.read().decode()
            
        if error_block:
            return jsonify({"success": False, "Gagal Memblokir": error_block})
        
        stdin, stdout, stderr= ssh.exec_command(f"/ip dhcp-server lease remove [find where mac-address={mac_address}]")

        if stderr.read().decode():
            return jsonify({'success':False, 'error':'Gagal Hapus Mac-Address'})
        else :
            return jsonify({"success": True, "success": f"User {hostname} Berhasil di Blokir"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# CEK BISA ENGGAK NYA

# -------------------------------------------

# CEK BISA ENGGAK NYA
@app.route("/nat", methods=["GET", "POST"])
def nat():
    
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    user_id = session.get("user_id")
    ssh = ssh_connections.get(user_id)

    if not ssh:
        return redirect(url_for("login"))
    
    # Cek ada yang ke block enggak
    try:
        stdin,stdout,stderr = ssh.exec_command('/ip firewall address-list print detail')
        
        pattern = re.findall(r'(?:address=|;;;\s*)([\w\.\-]+)', stdout.read().decode())

        blocked = set()
        if pattern:
            for x in pattern:
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', x):
                    blocked.add(x)
    
    except:
        return jsonify({'success':False, 'error':'Gagal ambil address-list di firewall'})
    
    filter = {}

    if request.method == "POST":
        data = request.get_json()
        action = data['action']

        if action == 'block':
            website = data['website'] 

            try:
                stdin, stdout, stderr = ssh.exec_command("/ip firewall address-list print detail")
                output = stdout.read().decode()

                pattern = re.findall(r'list=([\w\.]+)', output)
                if website in pattern :
                    return jsonify({"success":False, 'error':'Website sudah diblokir'})
            except:
                return jsonify({'success':False, 'error':'Gak bisa ngeprint'})

            if not validators.url(f'https://{website}'):
                return jsonify({'success':False, 'error':'Website sudah tidak active'})

            stdin, stdout, stderr  = ssh.exec_command(f'/ip firewall address-list add list={website} address={website}')
            address_list = stderr.read().decode()

            if address_list:
                return jsonify({'success':False, 'error':address_list})
            
            stdin, stdout_tcp, stderr = ssh.exec_command(f'/ip firewall filter add chain=forward action=drop protocol=tcp dst-port=443 dst-address-list={website} log=no log-prefix=""')
            stdin, stdout_udp, stderr = ssh.exec_command(f'/ip firewall filter add chain=forward action=drop protocol=udp dst-port=443 dst-address-list={website} log=no log-prefix=""')

            filter = {
                'tcp': stdout_tcp.read().decode(),
                'udp': stdout_udp.read().decode()
            }

            if filter:
                return jsonify({'success': True, 'message': f'Website {website} berhasil di blokir'})
            else:
                return jsonify({'success': False, 'error':'Gagal memblokir'})

        else:
            website = data['website']
            stdin, stdout, stderr = ssh.exec_command(f"/ip firewall address-list remove [find where list={website}]")

            if stderr.read().decode() :
                return jsonify({'success':False, 'error':'Gagal hapus address list'})
            
            stdin, stdout, stderr = ssh.exec_command(f'ip firewall filter remove [find where dst-address-list="{website}]"')

            if stderr.read().decode() :
                return jsonify({'success':False, 'error':'Gagal hapus firewall filter'})
            
            return jsonify({'success':True, 'message':f'Berhasil Unblock {website}'})

    return render_template("nat.html", filter=filter, blocked=blocked)
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