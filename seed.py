from pymongo import MongoClient
from dotenv import dotenv_values
import argon2
import random

config = dotenv_values(".env")

client = MongoClient(config["MONGO_URI"])
db = client["test"]  # change if your db name is different

ph = argon2.PasswordHasher()

def seed_supervisor(name, password):
    supervisor_id = "SUP" + str(random.randint(10000, 99999))
    hashed = ph.hash(password)
    db["supervisors"].insert_one({
        "supervisorId": supervisor_id,
        "password":     hashed,
        "name":         name,
    })
    print(f"✅ Supervisor created — ID: {supervisor_id} | Password: {password}")
    return supervisor_id  # return so we can pass to therapist

def seed_therapist(name, password, supervisor_id):
    therapist_id = "THE" + str(random.randint(10000, 99999))
    hashed = ph.hash(password)
    db["therapists"].insert_one({
        "therapistId":  therapist_id,
        "password":     hashed,
        "name":         name,
        "supervisorId": supervisor_id,
    })
    print(f"✅ Therapist created — ID: {therapist_id} | Password: {password} | Supervisor: {supervisor_id}")

# ── Run once ────────────────────────────────────────────
# Step 1: create supervisor first, get their ID back
sup_id = seed_supervisor("Prof. Meena Rao", "supervisor123")

# Step 2: create therapist and assign that supervisor
seed_therapist("Dr. Arun Kumar", "therapist123", sup_id)

# To assign an existing supervisor manually:
# seed_therapist("Dr. Someone", "pass123", "SUP12345")