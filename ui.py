import paramiko
import streamlit as st

if "page" not in st.session_state:
    st.session_state.page = "login"

if "koneksi" not in st.session_state:
    st.session_state.koneksi = None


def login():
    st.title("MaCInTime, Make Connection In Time")
    st.subheader("Login ke Perangkat Mikrotik")

    host = st.text_input("Masukkan IP Addess", "192.168.43.5")
    username = st.text_input("Masukkan Username Mikrotik", value="admin")
    password = st.text_input("Masukkan Password", type="password")
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
    st.title("Halaman Konfigurasi")
    st.write("Selamat Datang di Halaman Konfigurasi Mikrotik")

    if st.session_state.koneksi:
        st.write("Koneksi SSH Berhasil dipertahankan")

        stdin, stdout, stderr = st.session_state.koneksi.exec_command("system resource print")
        st.text(stdout.read().decode())
    else :
        st.error("Koneksi SSH tidak aktif")

    def logout() :
        if st.session_state.koneksi:
            st.session_state.koneksi.close()
        st.session_state.koneksi = None
        st.session_state.page = "login"

    st.button("Logout", on_click=logout)

if st.session_state.page == "login":
    login()
elif st.session_state.page == "home":
    home()