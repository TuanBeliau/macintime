import paramiko
import streamlit as st
from streamlit_option_menu import option_menu

if "page" not in st.session_state:
    st.session_state.page = "login"

if "koneksi" not in st.session_state:
    st.session_state.koneksi = None


def login():
    st.title("MaCInTime, Make Connection In Time")
    st.subheader("Login ke Perangkat Mikrotik")

    host = st.text_input("Masukkan IP Addess")
    username = st.text_input("Masukkan Username Mikrotik", value="admin")
    password = st.text_input("Masukkan Password", value=1, type="password")
    port = st.number_input("Port", 22, step=1)
    
    def connect():
        if host and username and port:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=host, username=username, password=password, port=port)

                st.session_state.koneksi = ssh
                st.session_state.page = "home"
            except paramiko.AuthenticationException:
                st.error("Autentikasi Gagal")
            except paramiko.SSHException as e:
                st.error(f"Koneksi SSH Gagal {e}")
            except Exception as e:
                st.error(f"Error Tak Terdefinisi {e}")
        else:
            st.warning("Mohon isi semua kolom input")

    st.button("Hubungkan", on_click=connect)

def home():

    def logout() :
        if st.session_state.koneksi:
            st.session_state.koneksi.close()
        st.session_state.koneksi = None
        st.session_state.page = "login"

    st.title("Selamat Datang di Halaman Konfigurasi Mikrotik")

    if st.session_state.koneksi:

        with st.sidebar:
            selected = option_menu("Menu", ["General", "Others", "Logout"],
                                   icons=["bar-chart", "...", "box-arrow-left"],
                                   menu_icon="house", default_index=0)
            
        # BAGIAN MENU GENERAL
        if selected == "General":
            st.write("Silahkan Lakukan Konfigurasi Mandiri")

            def IP():
                stdin, stdout, stderr = st.session_state.koneksi.exec_command("ip address print detail")
                IPAddress_output = stdout.read().decode()

                ip_data = []
                for line in IPAddress_output.splitlines():
                    if "address=" in line:
                        interface = line.split("interface=")[1].split()[0]
                        mentah = line.split("address=")[1].split()[0]
                        address = mentah.split("/")[0]
                        ip_data.append((interface, address))

                if ip_data:
                    new_ips = {}

                    for interface, address in ip_data:
                        new_ips[interface] = st.text_input(f"IP Address untuk {interface} :", value=address, key=f"ip_{interface}")
                        
                    return new_ips
                else:
                    st.error("Tidak koneksi yang aktif, Silakan login terlebih dahulu.")
                    return None

            def user():
                try:
                    new_password = st.text_input("Password Baru:", type="password", key="new_password")

                    if new_password:
                        return new_password
                    else:
                        return None
                except Exception as e:
                    st.error(f"Terjadi kesalahan saat memuat data pengguna: {e}")
                    return None

            # Mengambil data baru
            new_ips = IP()
            new_password = user()

            if st.button("Simpan Perubahan"):
                if new_ips or new_password:
                    berhasil = True

                    try:
                        # Perubahan IP
                        if new_ips:
                            try:
                                for interface, new_ip in new_ips.items():
                                    ip_address = f"ip address set [find interface={interface}] address={new_ip}"
                                    stdin, stdout, stderr = st.session_state.koneksi.exec_command(ip_address)
                            except Exception as e:
                                st.error(f"Gagal memperbarui IP Address: {e}")
                                berhasil = False
                        if new_password:
                            try:
                                ganti_pw = f"user set 0 password={new_password}"
                                stdin, stdout, stderr = st.session_state.koneksi.exec_command(ganti_pw)
                            except Exception as e:
                                st.error(f"Error saat mengganti Password: {e}")
                                berhasil = False

                        if new_ips and new_password :
                            try:
                                for interface, new_ip in new_ips.items():
                                    ip_address = f"ip address set [find interface={interface}] address={new_ip}"
                                    stdin, stdout, stderr = st.session_state.koneksi.exec_command(ip_address)
                                ganti_pw = f"user set 0 password={new_password}"
                                stdin, stdout, stderr = st.session_state.koneksi.exec_command(ganti_pw)
                            except Exception as e:
                                st.error(f"Error saat memperbarui IP dan Password: {e}")
                                berhasil = False
                        else:
                            st.error("Di Isi Ya bg")
                    except Exception as e:
                        st.error(f"Gagal memperbarui: {e}")
                        berhasil = False


                    if berhasil:
                        @st.dialog("Perubahan Berhasil")
                        def alert():
                            st.success("Selamat! Konfigurasi Sudah Berhasil Di terapkan")
                        alert()
                        
                else:
                    st.error("Tolong isi salah satu field")

        # -------------------------------------------------------------------------------------------------
        
        # BAGIAN MENU LOGOUT
        if selected == "Logout" :
            logout()
            

    else :
        st.error("Koneksi SSH tidak aktif")

if st.session_state.page == "login":
    login()
elif st.session_state.page == "home":
    home()
