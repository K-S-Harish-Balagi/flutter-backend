import requests
import argon2
from pymongo import MongoClient
import os
from dotenv import dotenv_values

# Load your .env file from backend folder
config = dotenv_values(".env")

client = MongoClient(config["MONGO_URI"])
db = client["test"]  # change if your db name is different

ph = argon2.PasswordHasher()

def seed_therapist(name, password):
    import random
    therapist_id = "THE" + str(random.randint(10000, 99999))
    hashed = ph.hash(password)
    db["therapists"].insert_one({
        "therapistId": therapist_id,
        "password": hashed,
        "name": name,
    })
    print(f"✅ Therapist created — ID: {therapist_id} | Password: {password}")

def seed_supervisor(name, password):
    import random
    supervisor_id = "SUP" + str(random.randint(10000, 99999))
    hashed = ph.hash(password)
    db["supervisors"].insert_one({
        "supervisorId": supervisor_id,
        "password": hashed,
        "name": name,
    })
    print(f"✅ Supervisor created — ID: {supervisor_id} | Password: {password}")


# ── Run these once ──────────────────────────────────────
seed_therapist("Dr. Arun Kumar", "therapist123")
seed_supervisor("Prof. Meena Rao", "supervisor123")