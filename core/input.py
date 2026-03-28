def get_target():
    target = input("Enter target (IP/Domain): ").strip()
    
    if not target:
        print("[-] Invalid input")
        return None
    
    return target
