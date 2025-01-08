import paramiko
import streamlit as st
from streamlit_option_menu import option_menu

# Streamlit app for Mikrotik configuration
def main():
    st.title("Alat Konfigurasi Mikrotik")

    # Sidebar menu for navigation
    with st.sidebar:
        selected = option_menu("Menu", ["Buat Koneksi", "Pengaturan"],
                               icons=["plug", "gear"],
                               menu_icon="cast", default_index=0)

    # Connect Page
    if selected == "Buat Koneksi":
        st.subheader("Mikrotik SSH Connection")

        # Input fields for Mikrotik connection
        ip_address = st.text_input("IP Address")
        username = st.text_input("Username", value="admin")
        password = st.text_input("Password", type="password")
        port = st.number_input("Port", value=22, step=1)

        # Button to establish connection
        if st.button("Hubungkan"):
            if ip_address and username and password:
                try:
                    # Establish SSH connection
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(hostname=ip_address, port=port, username=username, password=password)
                    st.success("Terhubung Mikrotik!")

                    # Execute a command (for demonstration purposes)
                    stdin, stdout, stderr = ssh.exec_command("/ip address print")
                    output = stdout.read().decode()
                    st.text_area("Output", output, height=300)

                    ssh.close()
                except paramiko.AuthenticationException:
                    st.error("Autentikasi Gagal, Coba cek lagi Username dan Password anda!")
                except paramiko.SSHException as e:
                    st.error(f"Koneksi SSH Gagal: {e}")
                except Exception as e:
                    st.error(f"Error yang tidak terdifinisi muncul: {e}")
            else:
                st.warning("Tolong isi kolom yang tersedia.")

    # Settings Page
    if selected == "Pengaturan":
        st.subheader("Mikrotik Settings")
        st.text("Makan Nasi biar owalah")
        # You can add more functionality here for Settings if needed.

if __name__ == "__main__":
    main()
