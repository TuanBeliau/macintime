import streamlit as st
from streamlit_option_menu import option_menu

# Sidebar dengan option menu
with st.sidebar:
    selected = option_menu(
        menu_title="Main Menu",  # Judul menu
        options=["Home", "About"],  # Opsi menu
        icons=["house", "info-circle"],  # Ikon untuk setiap menu
        menu_icon="cast",  # Ikon menu utama
        default_index=0  # Opsi default
    )

    # Tambahkan tombol di bawah option menu
    if st.button("Klik Saya"):
        st.sidebar.success("Tombol ditekan!")

# Konten berdasarkan menu yang dipilih
st.write(f"Anda memilih: {selected}")
