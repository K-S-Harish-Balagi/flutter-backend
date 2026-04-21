from pymongo import MongoClient
from dotenv import dotenv_values

config = dotenv_values(".env")
client = MongoClient(config["MONGO_URI"])
db = client["flutterLoginDB"]

def assign_patient(therapist_id, patient_id):
    db["assigneds"].update_one(
        {"patientId": patient_id},
        {
            "$set": {
                "therapistId": therapist_id,
                "patientId": patient_id
            }
        },
        upsert=True
    )

    print(f"✅ Assigned {patient_id} → {therapist_id}")

assign_patient("THE54177", "PAT09432")
assign_patient("THE54177", "PAT23377")
