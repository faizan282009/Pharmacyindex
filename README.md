# Pharmacyindex
pharmacy index 

# Pharmacy App

# Inventory dictionary (medicine: quantity)
inventory = {
    "Paracetamol": 50,
    "Ibuprofen": 30,
    "Amoxicillin": 20
}

# List of prescriptions
prescriptions = []

# Function to show current inventory
def show_inventory():
    print("\nCurrent Inventory:")
    for med, qty in inventory.items():
        print(f"{med}: {qty}")
    print()

# Function to add prescription
def add_prescription():
    print("\nAdd Prescription")
    patient = input("Enter Patient Name: ")
    medicine = input("Enter Medicine Name: ")
    quantity = int(input("Enter Quantity: "))

    # Check inventory
    if medicine not in inventory:
        print("Medicine not available in inventory!")
        return
    if quantity > inventory[medicine]:
        print(f"Not enough {medicine} in stock!")
        return

    # Add prescription
    prescriptions.append({
        "patient": patient,
        "medicine": medicine,
        "quantity": quantity
    })

    # Update inventory
    inventory[medicine] -= quantity
    print(f"Prescription added! {quantity} {medicine} given to {patient}.\n")

# Function to show all prescriptions
def show_prescriptions():
    print("\nAll Prescriptions:")
    if len(prescriptions) == 0:
        print("No prescriptions yet!")
        return
    for p in prescriptions:
        print(f"{p['patient']} - {p['medicine']} - {p['quantity']}")
    print()

# Function to show analytics
def show_analytics():
    print("\nAnalytics - Total Medicines Given:")
    if len(prescriptions) == 0:
        print("No prescriptions yet!")
        return
    total_meds = {}
    for p in prescriptions:
        total_meds[p['medicine']] = total_meds.get(p['medicine'], 0) + p['quantity']
    for med, qty in total_meds.items():
        print(f"{med}: {qty}")
    print()

# Main loop
while True:
    print("===== Pharmacist App Menu =====")
    print("1. Show Inventory")
    print("2. Add Prescription")
    print("3. Show Prescriptions")
    print("4. Show Analytics")
    print("5. Exit")
    choice = input("Enter your choice (1-5): ")

    if choice == "1":
        show_inventory()
    elif choice == "2":
        add_prescription()
    elif choice == "3":
        show_prescriptions()
    elif choice == "4":
        show_analytics()
    elif choice == "5":
        print("Exiting app...")
        break
    else:
        print("Invalid choice! Please enter 1-5.\n")
