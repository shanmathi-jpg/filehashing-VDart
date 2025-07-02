from werkzeug.security import generate_password_hash, check_password_hash

password = "yourpassword123"
hashed = generate_password_hash(password)
print("Hashed password:", hashed)

# Check the password
print("Password correct?", check_password_hash(hashed, "yourpassword123"))  # Should print True
print("Wrong password check:", check_password_hash(hashed, "wrongpassword"))  # Should print False
