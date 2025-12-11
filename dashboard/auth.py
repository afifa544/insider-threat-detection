# dashboard/auth.py
import streamlit as st
import requests
import os

API_URL = os.getenv("API_URL", "http://localhost:8000")

def authenticate_user(email: str, password: str) -> bool:
    """Authenticate user with API"""
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"email": email, "password": password},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            st.session_state.token = data["access_token"]
            st.session_state.user = data["user"]
            st.session_state.logged_in = True
            return True
    except Exception as e:
        st.error(f"Authentication error: {e}")
    
    return False

def logout():
    """Clear session state"""
    keys = ['token', 'user', 'logged_in', 'current_page']
    for key in keys:
        if key in st.session_state:
            del st.session_state[key]

def get_current_user():
    """Get current user from session"""
    return st.session_state.get('user')