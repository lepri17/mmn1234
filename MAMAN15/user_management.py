import uuid
import os
from threading import Lock

file_lock = Lock()

def check_and_register_user_in_file(username):
    with file_lock:
        users = {}
        if os.path.exists('registed_name_uuid.txt'):
            with open('registed_name_uuid.txt', 'r') as file:
                for line in file:
                    stored_username, stored_uuid, *_ = line.strip().split(',')
                    users[stored_username] = (stored_uuid)

        if username in users:
            return False, users[username]
        else:
            new_uuid = uuid.uuid4()
            with open('registed_name_uuid.txt', 'a') as file:
                file.write(f"{username},{new_uuid}\n")
            return True, new_uuid

def save_publick_and_aes_key(user_name, aes_key, public_key):
    end_marker = "#END#"
    with file_lock:
        if os.path.exists('registed_name_uuid.txt'):
            with open('registed_name_uuid.txt', 'r') as file:
                lines = file.readlines()
            with open('registed_name_uuid.txt', 'w') as file:
                for i, line in enumerate(lines):
                    username, id_client, *_ = line.strip().split(',')
                    if user_name == username:
                        lines[i] = f"{username},{id_client},{aes_key},{public_key}{end_marker}"
                        break
                file.writelines(lines)

def load_client_id(user_name):
    end_marker = "#END#"
    with open('registed_name_uuid.txt', 'r') as file:
        content = file.read()
    records = content.split(end_marker)
    for record in records:
        name, id, *_ = record.split(',')
        if name == user_name:
            return id
    return None
